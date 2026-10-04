# reqsig conformance vectors (W2 — cert-bound request-signature proof)

Cross-implementation test vectors for the Wendy per-request signature format
(`reqsig`): JWS Compact Serialization over an RFC 8785 JCS descriptor, with the
signer's leaf certificate in the `x5c` header. Producer of record is pki-core's
`internal/reqsig`; these let a second implementation (e.g. wendy-auth's Swift
verifier) confirm it agrees **byte-for-byte**.

This directory has two files. `signed-request-vectors-v1.json` covers the body
envelope that operator-signed RPCs use. `reqsig-vectors-v1.json` covers the
same JWS in its original header-carried form, which servers refuse once
WDY-3458 lands.

## SignedRequest envelope (WDY-3458)

Operator-signed RPCs carry their signature in the request body. The RPCs are the
ones marked `option (wendy.signed_request) = true` (`wendy/options.proto`); that
option is the only list. Their input is `wendycloud.v2.SignedRequest`
(`wendycloud/v2/signed_request.proto`). Headers carry only the bearer token and
the DPoP proof. Client-streaming and bidirectional RPCs are not signed. A
server-streaming RPC still takes a single request message, so it can be signed;
`PKIAdminService.ListAuditLog` is.
Responses are unchanged.

| field | content |
|---|---|
| `payload` | the serialized request message. These exact bytes are what gets signed. |
| `payload_type` | fully-qualified request message name. Must equal the one named in the RPC's `Signed; payload_type "…"` comment. |
| `signature` | compact JWS (ASCII bytes), see below |
| `pki_management_request` | pki-core tier-3 operations only: the operator's `management-request+jws`, relayed verbatim as the fabric `Envelope.signed_artifact` |

### JWS

- JWS Compact Serialization: three non-empty segments in canonical unpadded
  base64url. The signing input is the exact received `header.payload` bytes.
- Protected header: `alg` (`ML-DSA-65`, `ML-DSA-87`, `ES256`, `ES384`, `EdDSA`;
  never `none`; must match the leaf key) and `x5c` (one entry: the operator
  **leaf**, standard-base64 DER). `crit` is rejected. `kid` is logged only and
  grants nothing.
- **Reserved for the follow-up:** `kid` = leaf thumbprint after a once-per-session
  registration, with `x5c` then omitted. Not part of this round. Until it lands,
  `x5c` is required.

### Claims (JCS, RFC 8785)

| claim | rule |
|---|---|
| `operation` | fully-qualified method, e.g. `wendycloud.v2.AssetService/CreateAsset`. Must equal the called method. |
| `target` | `{tenant, ca?, resource}`. `tenant` = the signer's pki tenant UUID. `resource` follows the per-method table in cloud's `RequestSigning.md`. |
| `body_sha256` | `base64url(SHA-256(payload))`, unpadded, computed over the `payload` bytes exactly as carried. Never re-serialize them. |
| `nonce` | fresh and unpredictable, at most 256 bytes, single use per audience across all replicas. A request that fails any other check does not consume it. The server keeps it for `min(expiry, iat + 60s)`. |
| `iat` / `expiry` | Unix seconds. `iat` within ±60 s of the server clock. `expiry` is strict: `now == expiry` is already expired. |
| `aud` | the verifier's audience (cloud broker default `https://cloud.wendy.sh/broker`) |
| `correlation_id` | 1–64 bytes of `[A-Za-z0-9._-]`. Minted once at the origin, normally a lower-case UUID. The server adopts this value, and an `x-correlation-id` header that differs from it rejects the request. It propagates unchanged to fabric envelopes and audit. |

There is no `jti` claim; `nonce` serves that purpose. `pki_management_request`
carries its own `jti`, which pki-core enforces as single use, so every retry
needs a fresh nonce and a fresh management request.

### Verification (one generic gate, before the handler)

1. Parse the JWS and check the size cap, `alg` and the absence of `crit`.
2. Get pki-core's verdict on `x5c[0]` (fail closed). Check `alg` against the
   leaf key family, then verify the signature.
3. Check the principal kind and the tenant (principal = `target.tenant` = the
   organization's tenant = the token's tenant).
4. Check `operation`, `aud`, `iat`/`expiry`, `body_sha256` and `correlation_id`.
5. Check `payload_type` against the method, then decode `payload` as that
   message.
6. Claim the nonce last, then call the handler with the decoded message.
7. For tier-3 methods, `pki_management_request` is required, and its `x5c` leaf
   must be byte-equal to the `signature` leaf. Cloud does not verify its
   signature; it relays it byte for byte and pki-core verifies it.

Every rejection is one generic `PERMISSION_DENIED`, and the reason is only
logged. A method whose input is `SignedRequest` is always verified, whether or
not it carries the option. Each consumer should test that the option and the
input type agree.

### Vectors: `signed-request-vectors-v1.json`

`{version, contract, generation, root_cert_der_b64, vectors[]}`. Each vector
gives `method`, `verify_at` (the clock to verify at), `expected_tenant`,
`expect`, and `signed_request_b64` (the serialized `SignedRequest`, which is
what a server receives). Producers and consumers must both pass all three:

| name | expect |
|---|---|
| `mldsa65-create-asset-valid` | valid. Also broken out: `payload_b64`, `claims`, `claims_jcs`, `jws_compact`, `leaf_cert_der_b64`. A producer given the same inputs and keys must reproduce `claims_jcs` and `payload_b64`. |
| `tampered-payload-invalid` | invalid: the signature verifies but `body_sha256` does not match |
| `payload-type-mismatch-invalid` | invalid: the signature verifies but `payload_type` is not the method's request message |

The file is fully deterministic. Its keys are ML-DSA-65 from
`hexseed = SHA-256(<seed label>)` (`openssl genpkey -pkeyopt hexseed:…`), and
the certificates and JWS were signed with OpenSSL `deterministic:1`. Rebuilding
from the labels in `generation` with OpenSSL ≥ 3.5 and `buf convert` reproduces
it byte for byte. **The labels are test private keys.** Real producers sign
hedged (randomized), and verifiers cannot tell the difference.

## v1 vectors: header-carried descriptor (pki-core producer)

Contract: pki-core `docs/integration/cloud-request-signing.md` (v1 descriptor
schema) + `docs/reference/request-signing.md` (envelope/algorithms).

**Provenance:** generated from pki-core `main` commit `2cd507f` (PR #45) with
`go1.27rc2`, via `internal/reqsig/conformance_vectors_test.go`. Signatures are a
fresh snapshot per generation (ECDSA/ML-DSA are randomized) — verify these
bytes, don't regenerate to match.

### File

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

### Coverage (v1)

| name | what it pins |
|---|---|
| `es256-cert-bound-valid` | ES256 (`r‖s`, not DER), full CertChain anchoring |
| `mldsa65-cert-bound-valid` | ML-DSA-65 (RFC 9964, pure/empty-context), incl. a sample ML-DSA-65 leaf SPKI |
| `tampered-payload-invalid` | signature must not verify over a swapped payload |
| `jcs-edge-key-ordering-nonascii-int` | JCS key sorting, bare integers, raw-UTF-8 non-ASCII value, nested/`null`/`bool` |

### Notes / limitations

- **Signatures are a fresh snapshot per generation run** (ECDSA and ML-DSA are
  randomized). Verify these bytes; do not regenerate to match. The
  `canonical_jcs_hex` values are the deterministic anchor.
- **ML-DSA-65 cert-bound anchoring requires Go 1.27+** on the pki-core side
  (stdlib `crypto/x509` ML-DSA support). Generated with `go1.27rc2`.
- `x5c` is standard-base64 DER, leaf-first. `typ` is ignored; a **populated
  `crit`** header is rejected.
- Freshness/replay (`nonce`/`iat`/`expiry`) is each side's own concern — not
  covered here.

### Regenerating

From the pki-core repo (needs Go 1.27+):

```
REQSIG_VECTORS_OUT=<this-dir>/reqsig-vectors-v1.json \
  go test ./internal/reqsig/ -run TestConformanceVectors
```
