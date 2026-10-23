# postbox checkpoint vectors (WDY-4015 item 2, WDY-2162)

Cross-implementation vectors for the postbox head checkpoint: the bytes of
`PullChangesResponse.checkpoint` (`wendycloud/v2/postbox.proto`), which cloud
relays byte for byte as pki-core signed them. A device verifies it before it
treats any entry up to `max_id` as complete.

Producer of record is pki-core (`main` at `e5db2982`):

| part | pki-core symbol |
|---|---|
| body | `postbox.EncodeBody` (`internal/postbox/checkpoint.go`) |
| wrapper | `postbox.EncodeArtifact` (same file) |
| signature | `Engine.SignCheckpoint` (`internal/ca/checkpoint_signer.go`) |
| timestamp token | `Engine.IssueTimestamp` (`internal/ca/tsa.go`), called by `Engine.NotarizePostboxHead` (`internal/ca/postbox.go`) |
| reference verifier | `postbox.Verifier.Verify` (`internal/postbox/verify.go`) with `ca.CheckpointSignatureVerifier` and `timeattest.TimestampVerifier` |

pki-core's own signers cannot be used offline (their keys are private), so the
vectors use a test hierarchy of the same shape (see Generation).

## Format

The checkpoint is JSON with three members, all required:

| member | content |
|---|---|
| `body` | base64url, unpadded: the canonical body bytes. A verifier also accepts standard or padded base64. |
| `signature` | the compact JWS text itself, not base64-wrapped again |
| `timestamp_token` | base64url, unpadded: the DER RFC 3161 `TimeStampResp`. Standard or padded base64 is accepted too. |

The body is RFC 8785 JCS:
`{"expires_at","hash_of_head","max_id","notarized_at","target","tenant","v"}`.
`v` = 1. `tenant` = the tenant UUID. `target` = the device SPIFFE URI, or `""`
for a tenant-wide checkpoint. `max_id` = the postbox head entry id.
`hash_of_head` = base64url SHA-256 (32 bytes) of the head entry, as cloud
asserted it. `notarized_at` is pki-core's clock when it signed.
`expires_at` = `notarized_at` + `postbox.checkpoint_ttl` (default 15 min).
Both times are RFC 3339 UTC, to the second.

The signature is a JWS whose payload is exactly the body bytes. Its protected
header is `{"alg","x5c"}`. `x5c` = [checkpoint signer leaf, TSA Intermediate],
standard-base64 DER (pki-core's startup loader always supplies the
intermediate). The leaf carries the checkpoint-signer EKU
`1.3.6.1.4.1.65441.1.8`, non-critical. It is never `id-kp-timeStamping`. The
leaf's algorithm is config-driven: ML-DSA-65 by default, ML-DSA-44/87 or
ES256/ES384 also allowed.

The token is a granted `TimeStampResp`. Its `MessageImprint` = SHA-256 over
the exact body bytes. The CMS SignedData is attached (it carries the TSTInfo)
and embeds the TSA signer leaf only. The TSA signer leaf has the critical
`id-kp-timeStamping` EKU and sits under the same TSA Intermediate. The signed
attributes are content-type, message-digest (SHA-256 of the TSTInfo),
signing-time and signingCertificateV2. With an ML-DSA TSA signer, the
signature is pure ML-DSA over the DER SET of those attributes (RFC 5652 §5.4).
With ECDSA, it signs their hash.

## Verification order

Mirror `postbox.Verifier.Verify` exactly. Run every step, in order. Any
refusal is fail-safe: hold current state, apply nothing, alert. Never fall back
to cloud's word. Hash the body bytes you were given and never re-canonicalize
them.

| # | check | refusal |
|---|---|---|
| 1 | Decode the JSON. `body`, `signature` and `timestamp_token` must all be present and non-empty. | `malformed` |
| 2 | Authorship. Parse the JWS (`crit` and `kid` refused). Chain `x5c[0]` to the **pinned platform root**, with `x5c[1:]` as candidate intermediates, at the device's trusted now. Check that `alg` matches the leaf key, then verify the signature. | `signature` |
| 2b | The leaf must carry the checkpoint-signer EKU. A valid TSA signer cert is refused here. | `signer_role` |
| 3 | The JWS payload must equal the `body` bytes. | `signature_body_mismatch` |
| 4 | The token, checked only after authorship: status granted, exactly one SignerInfo, and the signer is the embedded cert that SignerInfo names (never a list position). The signature algorithm must match the signer key. content-type = id-ct-TSTInfo and message-digest = SHA-256(TSTInfo); then verify the CMS signature. Chain the signer to the pinned root at the TSTInfo's `genTime`, with EKU id-kp-timeStamping. Candidate intermediates are the JWS's `x5c[1:]` plus the token's other certs, because the token embeds no intermediate. | `timestamp` |
| 4b | `MessageImprint` = SHA-256(body bytes). | `imprint_mismatch` |
| 5 | Decode the body with exact member names. Refuse `v` other than 1, an unknown, duplicate or case-folded member (pki-core `exactjson.UnmarshalStrict`), or a malformed member. pki-core always emits all seven members; refuse a body missing one (pki-core itself would read a missing `target` as `""`). | `body` |
| 6 | `tenant` = your tenant | `tenant_mismatch` |
| 7 | `target` = your SPIFFE URI, or `""` | `target_mismatch` |
| 8 | `genTime` ≥ `notarized_at` − 5 s (exactly −5 s passes) | `skew` |
| 9 | `max_id` ≥ your checkpoint high-water mark (equal passes) | `rollback` |
| 10 | trusted now ≤ `expires_at` (equal is still fresh) | `stale` |

Then set the mark: `mark = max(mark, max_id)`. This checkpoint mark is not the
entry high-water mark. Entries up to `max_id` must still be fetched and
gap-checked (pki-core `docs/integration/device-postbox-verification.md`).

The refusal codes exist so a conformance run proves each vector fails at the
intended step. A device may report them all as one checkpoint refusal.

### Trusted time

The device's trusted time from a checkpoint is the token's `genTime`: the
TSA's time (AAA contract D9). The device never takes it from `notarized_at`,
from the JWS, or from any `iat`. `genTime` is used three ways:

- The TSA chain is validated at `genTime` (step 4).
- It bounds the body's own claim, with no upper limit: a late `genTime` only
  means the TSA was reached late, the fail-safe direction (step 8).
- Once the checkpoint is accepted, it may advance the device's anti-rollback
  time floor (AAA §4.4, D12: the floor moves only on an authenticated source
  or the newest verified artifact, never backward).

Staleness (step 10) and the checkpoint-signer chain (step 2) are checked at
the device's own trusted now, which that floor bounds. In the vectors this is
`verify_at`.

## Vectors: `checkpoint-vectors-v1.json`

The file is `{version, contract, generation, root_cert_der_b64,
tsa_intermediate_cert_der_b64, checkpoint_signer_eku,
max_notarize_skew_seconds, vectors[]}`. `root_cert_der_b64` is the root to
pin. The TSA Intermediate is informational: it is also `x5c[1]` of every
signature.

Each vector gives `expected_tenant`, `expected_target` (the device's own
SPIFFE URI), `high_water_mark`, `verify_at` (Unix seconds, the trusted now),
`checkpoint_b64` (standard base64 of the exact `checkpoint` bytes), `expect`
and, if invalid, `refusal`. Each vector is independent: no state carries over.

| name | expect |
|---|---|
| `checkpoint-valid` | valid. `high_water_mark` = `max_id`. Broken out in `breakdown`: `body_jcs`, `body_sha256_hex`, `signature_jws`, `timestamp_token_b64`, `gen_time`, and both signer certs. |
| `tenant-wide-valid` | valid: `target` `""`, `verify_at` = `expires_at` |
| `skew-boundary-valid` | valid: `genTime` = `notarized_at` − 5 s |
| `missing-token-invalid` | `malformed`: no `timestamp_token` |
| `missing-signature-invalid` | `malformed`: no `signature` |
| `bad-signature-invalid` | `signature`: one bit of the JWS signature flipped |
| `untrusted-notary-invalid` | `signature`: a checkpoint-EKU leaf under a foreign root |
| `wrong-notary-role-invalid` | `signer_role`: signed by the TSA signer (chain and signature valid) |
| `signature-body-mismatch-invalid` | `signature_body_mismatch`: a valid JWS over another body (max_id 43) |
| `token-imprint-mismatch-invalid` | `imprint_mismatch`: a genuine token over another body's hash |
| `token-bad-signature-invalid` | `timestamp`: one bit of the CMS signature flipped |
| `token-untrusted-tsa-invalid` | `timestamp`: right imprint, but the TSA signer is under a foreign root |
| `token-skew-invalid` | `skew`: `genTime` = `notarized_at` − 6 s |
| `unknown-version-invalid` | `body`: `v` = 2, signed and stamped |
| `tenant-mismatch-invalid` | `tenant_mismatch` |
| `target-mismatch-invalid` | `target_mismatch`: another device of the same tenant |
| `rollback-invalid` | `rollback`: `high_water_mark` = `max_id` + 1 |
| `stale-invalid` | `stale`: `verify_at` = `expires_at` + 1 |

## Generation

Run `go run conformance/postbox/generate.go conformance/postbox` (Go 1.27,
standard library). The test hierarchy:

- Root, TSA Intermediate and TSA signer are ML-DSA-87.
- The checkpoint signer is ML-DSA-65.
- The foreign root and its leaves are ML-DSA-65.

Keys come from `SHA-256(<label>)`, and every certificate, JWS and CMS
signature is deterministic, so a rerun reproduces the file byte for byte.
**The labels are test private keys.** Real checkpoints are signed hedged, and
verifiers cannot tell the difference.

`go run conformance/postbox/verify.go conformance/postbox` verifies every
vector in the order above. It exits non-zero unless each vector ends in its
`expect` and `refusal`. It handles ML-DSA signers only, as the vectors do, and
uses `encoding/json`, so it does not refuse duplicate or case-folded body
members (no vector carries them).

These vectors were cross-checked against pki-core `e5db2982`. Its reference
verifier gives the same verdict on all 18, with the checkpoint signer verifier
given no intermediates (`x5c[1]` suffices) and the TSA verifier given the TSA
Intermediate. `postbox.EncodeBody` and `EncodeArtifact` reproduce
`checkpoint-valid` byte for byte.
