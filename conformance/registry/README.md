# Encrypted registry conformance vectors (WDY-3958)

Byte-level rules and vectors for the crypto in `wendycloud/v2/registry.proto`.
The CLI and console (wrap, seal, encrypt) and the agent (unwrap, open, decrypt)
must agree on every byte, so each side tests against
`registry-vectors-v1.json` here. Device-signed key registrations and their
`RecipientKey` checks are in `conformance/reqsig` (device-signer profile).

Only rules the contract fixes are pinned. Where the contract names an algorithm
but not a byte layout, the file carries a `todo[]` entry instead of a vector,
and the layout waits for a ruling.

## Pinned

| item | rule | vector |
|---|---|---|
| key ids | `content_key_id`, `deployment_key_id`, `key_id`, `recipient_key_id` = lower-case hex SHA-256 of the raw key bytes (a public key in its HPKE serialization) | `per_blob_key.content_key_id`, `hybrid_kem.key_id` |
| per-blob key (Q4 amendment) | `blob_key = HKDF-SHA256(IKM = content key, salt = none, info = UTF-8 bytes of EncryptedBlob.plaintext_digest, L = 32)`. No salt means the RFC 5869 default (32 zero bytes). `plaintext_digest` is the string as carried, `sha256:<hex>`. Two blobs of one release get different keys. | `per_blob_key` |
| hybrid KEM (Q5) | HPKE base mode (RFC 9180), KEM `MLKEM768-X25519` (X-Wing, draft-ietf-hpke-pq, `kem_id` 0x647a), KDF HKDF-SHA256 (`0x0001`), AEAD AES-256-GCM (`0x0002`). `RegisterEncryptionKeyRequest.public_key` is the KEM's `SerializePublicKey` output (1216 bytes). `KeyWrap.enc` is the encapsulation, `KeyWrap.ciphertext` the sealed key with its tag. | `hybrid_kem` |

`hybrid_kem` pins the suite only. Its `info` and `aad` are labelled test
strings, NOT the wrap layout. A consumer derives the key pair from `ikm_hex`
(`DeriveKeyPair`), checks `public_key_hex` and `key_id`, then opens
`ciphertext_hex` with `enc_hex`, `info_hex` and `aad_hex` and gets
`plaintext_hex`.

## Waiting on a ruling (`todo[]`)

| item | what is fixed | what is open |
|---|---|---|
| `chunk-aead` | AES-256-GCM per chunk under the per-blob key; `chunk_size` plaintext bytes per chunk (65536 default); the nonce derives from (chunk index, last-chunk flag) | the 96-bit nonce layout, the chunk AAD, the ciphertext framing (`ct‖tag` per chunk, concatenated?) and the empty-blob case. Vectors then: valid, truncate, reorder, splice, cross-blob. |
| `key-wrap` | the suite above; info binds tenant, scope, key_id and recipient_key_id (#135: length-prefixed) | the info byte layout (field order, length prefix width, scope kind encoding) and the wrap AAD |
| `sealed-content-key` | AAD = `deployment_id ‖ manifest_digest` (#135: length-prefixed, extended with tenant and deployment_key_id) | the cipher (AES-256-GCM is the only AEAD named), nonce and deployment key lengths, the exact AAD encoding |

## Files

- `registry-vectors-v1.json`: the vectors and the `todo[]` list.
- `generate.go`: writes this file and `conformance/reqsig/device-signed-request-vectors-v1.json`.
  `go run conformance/registry/generate.go conformance` (Go 1.27+, standard library only).
- `verify.go`: checks every vector in both files against its `expect`.
  `go run conformance/registry/verify.go conformance`.

Keys come from `SHA-256(<label>)`; the labels in `generate.go` are test private
keys. HPKE encapsulation is randomized: verify `enc_hex`/`ciphertext_hex`, do
not regenerate to match.
