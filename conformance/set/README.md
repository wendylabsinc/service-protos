# SET conformance vectors (WDY-2335 — SSF/CAEP security event tokens)

Cross-implementation test vectors for the Wendy Security Event Token (SET) wire
contract: RFC 8417 SETs pushed over the fabric as `wendyauth.v1.Envelope` messages.
**Producer of record is wendy-auth's `SETBuilder`** (the transmitter owns the payload
bytes); receivers (pki-core's `internal/ssf` verifier, cloud's SET receiver) should
assert their verifier accepts a JWS-signed form of exactly these payloads.

Contract provenance: WDY-2335 cross-repo proposal (per-receiver subject shape /
OQ-B resolution, pinned audiences, exp semantics) — see the issue for sign-off state.

## File

`set-vectors-v1.json` — `{version, generated_by, notes, vectors[]}`.

Each `vectors[]` entry:

- `name` — vector id.
- `inputs` — the fixed SET inputs: `issuer`, `audience`, `event_uri`, `subject`,
  `reason`, `jti`, `iat`, `exp`, and (pki-core-bound shapes only) `sub_id_uri`.
- `canonical_payload_hex` / `canonical_payload_utf8` — the **exact canonical payload
  bytes** wendy-auth signs. Deterministic: JSON with lexicographically sorted keys
  (Foundation `JSONSerialization .sortedKeys`; note forward slashes are escaped as
  `\/`, which is valid JSON and canonical for THESE bytes). Receivers verify the
  signed bytes as-is — do not re-serialize and compare structurally.

## Wire contract pinned by these vectors

- **Envelope constants:** `msg_type = "ssf.security_event"`,
  `signed_artifact.kind = "set+jwt"`, JWS `typ = "secevent+jwt"`.
- **JWS alg: `ES256`** — pinned regardless of wendy-auth's platform signing posture
  (default ML-DSA-65): pki-core's realm-trust SET verifier resolves keys ES256-only
  (`internal/ssf/verify.go` hardcodes `reqsig.AlgES256`, and its go-jose cannot
  materialize AKP/ML-DSA JWKS entries), so a PQ-signed SET is rejected at key
  resolution. Revisit when pki-core's `Verifier` adopts the alg-agnostic
  `EntryByKID` path its `CloudVerifier` already uses.
- **Audiences:** pki-core `https://pki.wendy.sh/fabric/ssf`,
  cloud `https://cloud.wendy.sh/fabric/ssf`.
- **`exp = iat + 300`** — deliberate deviation from RFC 8417 §2.2 (which discourages
  `exp` in SETs): pki-core's `verifySpine` uses it as the replay/freshness bound
  (now ∈ [iat−2min, exp+2min]) and reaps `ssf_replay` rows at `exp`.
- **Subject shape, per receiver:**
  - cloud-bound: per-event `subject: {format:"iss_sub", iss, sub}`, no top-level
    `sub_id`.
  - pki-core-bound (RISC account-disabled/purged): additionally top-level
    `sub_id: {format:"uri", uri:"spiffe://wendy.sh/tenant/<tenant_uuid>/<kind>/<sub>"}`
    with `<kind>` ∈ {`operator`, `service`} — byte-matching the SAN pki-core mints
    via `spiffeid.BuildTenantURI`.

## Coverage (v1)

| name | what it pins |
|---|---|
| `cloud-session-revoked-iss-sub` | CAEP session-revoked, cloud shape (no sub_id) |
| `cloud-token-claims-change-iss-sub` | CAEP token-claims-change, cloud shape |
| `cloud-credential-change-iss-sub` | CAEP credential-change, cloud shape |
| `cloud-account-disabled-iss-sub` | RISC account-disabled as cloud sees it |
| `pki-account-disabled-operator-sub-id` | RISC account-disabled, top-level SPIFFE sub_id, kind `operator` |
| `pki-account-purged-service-sub-id` | RISC account-purged, kind `service` |

## Notes / limitations

- **No signatures in v1** — signing/verification is covered by the existing reqsig
  vectors (`conformance/reqsig/`); the deterministic anchor here is the payload bytes.
- Freshness windows and replay storage are receiver-side concerns; the vectors pin
  claim VALUES, not verifier clock behavior.

## Regenerating

wendy-auth: `WENDY_AUTH_GENERATE_SET_VECTORS=<out.json> swift test --filter SETVectorGeneration`
(then verify determinism by generating twice and diffing). Regeneration is only
legitimate when the CONTRACT changes — receivers conform to the committed bytes.
