# reqsig conformance vectors (W2 — cert-bound request-signature proof)

Cross-implementation test vectors for the Wendy per-request signature format
(`reqsig`): JWS Compact Serialization over an RFC 8785 JCS descriptor, with the
signer's leaf certificate in the `x5c` header. Producer of record is pki-core's
`internal/reqsig`; these let a second implementation (e.g. wendy-auth's Swift
verifier) confirm it agrees **byte-for-byte**.

Contract: pki-core `docs/integration/cloud-request-signing.md` (v1 descriptor
schema) + `docs/reference/request-signing.md` (envelope/algorithms).

**Provenance:** generated from pki-core `main` commit `2cd507f` (PR #45) with
`go1.27rc2`, via `internal/reqsig/conformance_vectors_test.go`. Signatures are a
fresh snapshot per generation (ECDSA/ML-DSA are randomized) — verify these
bytes, don't regenerate to match.

## File

`reqsig-vectors-v1.json` — `{version, go_toolchain, notes, algorithms, vectors[]}`.

Each `vectors[]` entry has `name`, `kind`, `expect`, and kind-specific fields:

- **`kind: "cert_bound"`** — a full JWS proof.
  - `jws_compact` — the envelope to verify (`b64url(header).b64url(payload).b64url(sig)`).
  - `leaf_cert_der_b64` / `root_cert_der_b64` — standard-base64 DER. The `x5c`
    header carries the leaf, leaf-first; anchor the chain to the root and require
    `ExpectedTenant == tenant_uuid`.
  - `descriptor` — the v1 request descriptor (informational; the JWS payload is
    its JCS form).
  - `canonical_jcs_hex` — the exact JCS bytes = the JWS payload. Verify your JCS
    of `descriptor` reproduces these.
  - `body_b64` — preimage of `descriptor.body_sha256`; confirm
    `base64url(SHA-256(body_b64)) == descriptor.body_sha256`.
  - `expect: "valid"` must verify; `expect: "invalid"` must be rejected
    (`invalid_reason` says why).
- **`kind: "canonicalization"`** — JCS only: `canonical_jcs_utf8` /
  `canonical_jcs_hex` are the required RFC 8785 output for the described input.

## Coverage (v1)

| name | what it pins |
|---|---|
| `es256-cert-bound-valid` | ES256 (`r‖s`, not DER), full CertChain anchoring |
| `mldsa65-cert-bound-valid` | ML-DSA-65 (RFC 9964, pure/empty-context), incl. a sample ML-DSA-65 leaf SPKI |
| `tampered-payload-invalid` | signature must not verify over a swapped payload |
| `jcs-edge-key-ordering-nonascii-int` | JCS key sorting, bare integers, raw-UTF-8 non-ASCII value, nested/`null`/`bool` |

## Notes / limitations

- **Signatures are a fresh snapshot per generation run** (ECDSA and ML-DSA are
  randomized). Verify these bytes; do not regenerate to match. The
  `canonical_jcs_hex` values are the deterministic anchor.
- **ML-DSA-65 cert-bound anchoring requires Go 1.27+** on the pki-core side
  (stdlib `crypto/x509` ML-DSA support). Generated with `go1.27rc2`.
- `x5c` is standard-base64 DER, leaf-first. `typ` is ignored; a **populated
  `crit`** header is rejected.
- Freshness/replay (`nonce`/`iat`/`expiry`) is each side's own concern — not
  covered here.

## Regenerating

From the pki-core repo (needs Go 1.27+):

```
REQSIG_VECTORS_OUT=<this-dir>/reqsig-vectors-v1.json \
  go test ./internal/reqsig/ -run TestConformanceVectors
```
