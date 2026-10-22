# Encrypted registry conformance vectors (WDY-3958)

Byte-level rules and vectors for the crypto in `wendycloud/v2/registry.proto`.
The CLI and console (wrap, seal, encrypt) and the agent (unwrap, open, decrypt)
must agree on every byte, so each side tests against
`registry-vectors-v1.json` here. Device-signed key registrations and their
`RecipientKey` checks are in `conformance/reqsig` (device-signer profile).

Every byte layout is pinned. The chunk, wrap and seal layouts follow the
orchestrator ruling of 2026-10-22 20:26 under the 2026-10-20 primitives
decisions. `lp(x)` below is a uint16 big-endian byte length followed by the
UTF-8 bytes of `x`.

## Pinned

| item | rule | vector |
|---|---|---|
| key ids | `content_key_id`, `deployment_key_id`, `key_id`, `recipient_key_id` = lower-case hex SHA-256 of the raw key bytes (a public key in its HPKE serialization) | `per_blob_key.content_key_id`, `hybrid_kem.key_id` |
| per-blob key (Q4 amendment) | `blob_key = HKDF-SHA256(IKM = content key, salt = none, info = UTF-8 bytes of EncryptedBlob.plaintext_digest, L = 32)`. No salt means the RFC 5869 default (32 zero bytes). `plaintext_digest` is the string as carried, `sha256:<hex>`. Two blobs of one release get different keys. | `per_blob_key` |
| hybrid KEM (Q5) | HPKE base mode (RFC 9180), KEM `MLKEM768-X25519` (X-Wing, draft-ietf-hpke-pq, `kem_id` 0x647a), KDF HKDF-SHA256 (`0x0001`), AEAD AES-256-GCM (`0x0002`). `RegisterEncryptionKeyRequest.public_key` is the KEM's `SerializePublicKey` output (1216 bytes). `KeyWrap.enc` is the encapsulation, `KeyWrap.ciphertext` the sealed key with its tag. | `hybrid_kem` |
| chunk AEAD | AES-256-GCM per chunk under the per-blob key. Nonce = 11-byte big-endian chunk index ‖ 1 byte last-chunk flag (`0x01` on the last chunk, else `0x00`). No AAD: the per-blob key already binds the blob. Ciphertext = the chunks' `ct‖tag` (16-byte tag) concatenated, nothing else. Every chunk holds `chunk_size` plaintext bytes except the last, which holds 1..`chunk_size`; an empty blob is one empty last chunk (16 bytes). Chunk index ≤ 2^32. A reader treats the chunk the ciphertext ends with as the last one, so truncation, reordering and splicing fail authentication. | `chunk_aead` |
| key wrap | HPKE base mode with the suite above. `info = "wendy-registry-wrap-v1" ‖ lp(organization_id) ‖ u8 scope kind (1 = deployment_id, 2 = app_release_id) ‖ lp(scope id) ‖ lp(WrapScope.key_id) ‖ lp(recipient_kind as a decimal enum number) ‖ lp(recipient) ‖ lp(recipient_key_id)`; `recipient` is empty for the custodian. AAD empty. Plaintext = the 32-byte deployment key (deployment scope) or content key (release scope). | `key_wrap` |
| sealed content key | AES-256-GCM under the 32-byte deployment key, 12-byte random nonce in `SealedContentKey.nonce`. `AAD = "wendy-registry-seal-v1" ‖ lp(organization_id) ‖ lp(deployment_id) ‖ lp(manifest_digest) ‖ lp(content_key_id) ‖ lp(deployment_key_id)`. Plaintext = the 32-byte content key. | `sealed_content_key` |

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
dropped last chunk, two swapped chunks and a chunk spliced in from another
blob of the same release; their `ciphertext_digest` is that of the bytes
given, so the refusal comes from authentication, not the digest check.

`key_wrap` vectors are opened with the key pair derived from
`recipient_ikm_hex` (the `hybrid_kem` key). A consumer rebuilds `info_hex`
from `binding`, opens `enc_hex`/`ciphertext_hex` and gets `wrapped_key_hex`.
`wrong-scope-id-invalid` is a wrap made for another deployment id, opened
under the binding shown. `sealed_content_key` vectors are opened with
`deployment_key_hex`; `wrong-deployment-id-invalid` changes only the
deployment id in the AAD.

## Files

- `registry-vectors-v1.json`: the vectors.
- `generate.go`: writes this file and `conformance/reqsig/device-signed-request-vectors-v1.json`.
  `go run conformance/registry/generate.go conformance` (Go 1.27+, standard library only).
- `verify.go`: checks every vector in both files against its `expect`.
  `go run conformance/registry/verify.go conformance`.

Keys come from `SHA-256(<label>)`; the labels in `generate.go` are test private
keys. HPKE encapsulation is randomized: verify `enc_hex`/`ciphertext_hex`, do
not regenerate to match (a rerun rewrites them, and the ES256 vectors in
`conformance/reqsig`, with fresh valid bytes).
