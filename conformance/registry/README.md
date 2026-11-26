# Encrypted registry conformance vectors (WDY-3958)

Byte-level rules and vectors for the crypto in `wendycloud/v2/registry.proto`.
The CLI and console (wrap, seal, encrypt) and the agent (unwrap, open, decrypt)
must agree on every byte, so each side tests against
`registry-vectors-v1.json` here. Device-signed key registrations and their
`RecipientKey` checks are in `conformance/reqsig` (device-signer profile).

Every byte layout is pinned. The chunk, wrap and seal layouts follow the
orchestrator ruling of 2026-10-22 20:26 under the 2026-10-20 primitives
decisions, as amended at 20:50 (chunk size in the per-blob key, one-byte
recipient kind). `lp(x)` below is a uint16 big-endian byte length followed by
the UTF-8 bytes of `x`; a field longer than 65535 bytes is an error, and
consumers refuse it rather than truncate the length.

## Pinned

| item | rule | vector |
|---|---|---|
| key ids | `content_key_id`, `deployment_key_id`, `key_id`, `recipient_key_id` = lower-case hex SHA-256 of the raw key bytes (a public key in its HPKE serialization) | `per_blob_key.content_key_id`, `hybrid_kem.key_id` |
| per-blob key (Q4 amendment, amended 2026-10-22 20:50) | `blob_key = HKDF-SHA256(IKM = content key, salt = none, info = UTF-8 bytes of EncryptedBlob.plaintext_digest ‖ u32 big-endian ArtifactManifest.chunk_size, L = 32)`. No salt means the RFC 5869 default (32 zero bytes). `plaintext_digest` is the string as carried, `sha256:<hex>`. Two blobs of one release get different keys, and so does one blob chunked at two sizes: without the chunk size in the key, re-chunking the same blob under the same content key would encrypt different bytes under the same key and nonce (GCM nonce reuse). An AAD would not prevent that; the key must differ. This changes the `per_blob_key` vectors first published in #141 (no consumer had shipped). | `per_blob_key` |
| hybrid KEM (Q5) | HPKE base mode (RFC 9180), KEM `MLKEM768-X25519` (X-Wing, draft-ietf-hpke-pq, `kem_id` 0x647a), KDF HKDF-SHA256 (`0x0001`), AEAD AES-256-GCM (`0x0002`). `RegisterEncryptionKeyRequest.public_key` is the KEM's `SerializePublicKey` output (1216 bytes). `KeyWrap.enc` is the encapsulation, `KeyWrap.ciphertext` the sealed key with its tag. | `hybrid_kem` |
| chunk AEAD | AES-256-GCM per chunk under the per-blob key. Nonce = 11-byte big-endian chunk index ‖ 1 byte last-chunk flag (`0x01` on the last chunk, else `0x00`). No AAD: the per-blob key already binds the blob. Ciphertext = the chunks' `ct‖tag` (16-byte tag) concatenated, nothing else. Every chunk holds `chunk_size` plaintext bytes except the last, which holds 1..`chunk_size`; an empty blob is one empty last chunk (16 bytes). Chunk index ≤ 2^32. A reader treats the chunk the ciphertext ends with as the last one, so truncation, reordering and splicing fail authentication. | `chunk_aead` |
| key wrap | HPKE base mode with the suite above. `info = "wendy-registry-wrap-v1" ‖ lp(organization_id) ‖ u8 scope kind (1 = deployment_id, 2 = app_release_id, 3 = secret_version) ‖ lp(scope id) ‖ lp(WrapScope.key_id) ‖ u8 recipient_kind (the RecipientKind enum value) ‖ lp(recipient) ‖ lp(recipient_key_id)`; `recipient` is empty for the custodian. AAD empty. Plaintext = the 32-byte deployment key (deployment scope), content key (release scope) or secret key (secret scope, WDY-4374). **A client never makes a custodian wrap at secret scope**, whatever recipients it is given; a wrap helper that adds the custodian for releases and deployments must not add it there. The registry's refusal of one is a tripwire only. A client that finds a custodian wrap at a secret scope treats that secret version as compromised: it refuses to use it (no wrap onward, never in a `DeviceAssignment`) and reports it to its operator. HPKE base mode does not authenticate the sender, so a secret-scope wrap is trusted only with the setter's signed `SetSecret` request (`SignedSecretVersion`, `wendycloud/v2/registry.proto`). | `key_wrap`; secret scope: `conformance/postbox-entry` `secret_vectors`, `secret_readback_vectors` |
| secret seal (WDY-4374) | AES-256-GCM under the 32-byte secret key of one secret version (fresh per version), 12-byte random nonce in `SealedSecret.nonce`. `AAD = "wendy-secret-seal-v1" ‖ lp(organization_id) ‖ lp(app_id) ‖ lp(name) ‖ lp(version in decimal) ‖ lp(secret_key_id)`. Plaintext = the value (UTF-8, no NUL, at most 16 KiB). | `conformance/postbox-entry` `secret_vectors` |
| session approval (WDY-4375) | ML-DSA-65 (FIPS 204, pure, empty context string) with the approving session's approval key (`RegisterEncryptionKeyRequest.approval_public_key`, the FIPS 204 public key encoding). Message = `"wendy-session-approval-v1"` ‖ `SignedSessionApproval.statement`, the serialized `SessionApproval` exactly as carried; a verifier checks the signature over the received bytes, then decodes. Root: `approver_key_id = key_id`, signed with the approved session's own approval key. | `session-vectors-v1.json`, `approval_vectors` |
| session revocation (WDY-4375) | As session approval, with the revoking session's approval key. Message = `"wendy-session-revocation-v1"` ‖ `SignedSessionRevocation.statement`, the serialized `SessionRevocation` exactly as carried. Its own prefix, so an approval never verifies as a revocation. | `session-vectors-v1.json`, `revocation_vectors` |
| sealed content key | AES-256-GCM under the 32-byte deployment key, 12-byte random nonce in `SealedContentKey.nonce` (fresh from a CSPRNG for every seal; the vector's fixed nonce is for the vector only). `AAD = "wendy-registry-seal-v1" ‖ lp(organization_id) ‖ lp(deployment_id) ‖ lp(manifest_digest) ‖ lp(content_key_id) ‖ lp(deployment_key_id)`. Plaintext = the 32-byte content key. | `sealed_content_key` |

`hybrid_kem` pins the suite only. Its `info` and `aad` are labelled test
strings, NOT the wrap layout. A consumer derives the key pair from `ikm_hex`
(`DeriveKeyPair`), checks `public_key_hex` and `key_id`, then opens
`ciphertext_hex` with `enc_hex`, `info_hex` and `aad_hex` and gets
`plaintext_hex`.

`chunk_aead` uses `chunk_size` 16 so a vector spans several chunks. A
consumer decrypts each `ciphertext_hex` under the key derived from
`content_key_hex` and the vector's `plaintext_digest`, and a valid vector
yields `plaintext_hex`. Encryption is deterministic, so a producer given
`plaintext_hex` must reproduce `ciphertext_hex`. The invalid vectors are a
dropped last chunk, two swapped chunks, chunk 0 of another blob of the same
release in slot 0 (same index and flag, so only the per-blob key separates
them), an empty ciphertext, and an empty blob followed by an extra chunk.
Their `ciphertext_digest` is that of the bytes given, so the refusal comes
from decryption, not the digest check.

`key_wrap` vectors are opened with the key pair derived from
`recipient_ikm_hex` (the `hybrid_kem` key). A consumer rebuilds `info_hex`
from `binding`, opens `enc_hex`/`ciphertext_hex` and gets `wrapped_key_hex`.
Each `wrong-*-invalid` wrap is the device wrap opened under a binding with
one field changed (scope id, scope kind, organization, key_id, recipient,
recipient_key_id). `sealed_content_key` vectors are opened with
`deployment_key_hex`; each `wrong-*-invalid` changes one AAD field
(deployment id, manifest digest, content_key_id, deployment_key_id,
organization). A consumer that checks key ids before opening may refuse
some of them earlier; either way they must not open.

## Session signatures (WDY-4375)

`session-vectors-v1.json` contains 15 `approval_vectors` and 14
`revocation_vectors`. Each `signed_session_b64` is the serialized
`SignedSessionApproval` or `SignedSessionRevocation`: field 1 is the exact
statement bytes, field 2 is the ML-DSA-65 signature. Verify the appropriate
prefix concatenated with the received statement bytes, with an empty ML-DSA
context. Decode only after verification. The reverse-field-order valid cases
ensure a verifier does not reserialize the statement before checking it.

`sessions` contains test-only KEM seeds, public keys and their SHA-256 key
ids, and approval-key seeds and public keys. A vector's `signer` selects an
already verified registration. `expected_statement` gives the caller's
organization, user, target key id and signer key id. `signer_key_id` means
`approver_key_id` for approval and `revoker_key_id` for revocation.

The checks model acceptance of the inner statement at ApproveSession or
RevokeUserEncryptionKey. The target is a live registered session of the
caller, waiting for approval or approved for revocation. `signer_live`,
`signer_approved` and `has_prior_root` are trusted test preconditions from
registration, approval-chain verification and membership history. They are
not claims supplied by the session being approved or revoked. These vectors
do not test the outer SignedRequest, registration certificate chains,
approval-chain traversal or discovery of multiple roots. Historical approvals
made by a now-revoked signer remain valid; the live check here applies only
to accepting a new approval or revocation.

Both sets cover another session and self, reordered protobuf fields, a wrong
signing key, the other operation's prefix, a missing prefix, tampered
statement/signature bytes, each of the four statement bindings, and waiting
or revoked signers. Approval also rejects a new self-approved root after an
earlier root was revoked. A first root may self-approve without an existing
approved signer. A self-revocation still requires an approved signer.

Invalid cases must fail with their exact `refusal`, not just any error.
Those labels are conformance checks, not wire status values. Signing is
deterministic only to make these test vectors reproducible; production
signatures may use randomized ML-DSA signing.

## Files

- `registry-vectors-v1.json`: registry encryption vectors.
- `session-vectors-v1.json`: session approval and revocation vectors.
- `generate.go`: writes both registry files and `conformance/reqsig/device-signed-request-vectors-v1.json`.
  `go run conformance/registry/generate.go conformance` (Go 1.27+, standard library only).
- `verify.go`: checks every vector in all three files against its `expect`,
  including the exact session refusal labels and derived key material.
  `go run conformance/registry/verify.go conformance`.

Keys come from `SHA-256(<label>)`; the labels in `generate.go` are test private
keys. HPKE encapsulation and ES256 signatures are randomized: verify those
bytes, do not regenerate to match. A rerun keeps the committed randomized
bytes while their deterministic inputs are unchanged, so it does not churn
copies pinned elsewhere.
