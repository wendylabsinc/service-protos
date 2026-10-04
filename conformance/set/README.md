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
- `expect` (optional) — `accept` or `reject` for the receiver's verification gate.
  Absent ⇒ `accept` (the v1 payload-determinism vectors). `reject_reason` accompanies
  a `reject`. Used by the tenant-lifecycle rule (see below).

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
  - pki-core-bound (RISC account-disabled/purged, CAEP session-revoked): additionally
    top-level
    `sub_id: {format:"uri", uri:"spiffe://wendy.sh/tenant/<tenant_uuid>/<kind>/<sub>"}`
    with `<kind>` ∈ {`operator`, `service`} — byte-matching the SAN pki-core mints
    via `spiffeid.BuildTenantURI`.
- **pki-core effect, per event-type:** account-disabled / account-purged disable the
  principal and revoke its live certificates. session-revoked (WDY-3448) is **audit
  only**: one `ssf.session_revoked` row, no disable, no revocation — a session revoke
  is not a certificate revoke. All three are verified the same way (realm-bound
  issuer, system realm rejected).

## Tenant-lifecycle events (WDY-3177)

Event-type `https://schemas.wendy.sh/secevent/tenant-deleted` — the **first
Wendy-minted (non-standard) SSF event type**; no RISC/CAEP type fits tenant
deletion. Signals that a tenant/realm was purged in wendy-auth so cloud and
pki-core run offboarding. Fan-out = **[cloud, pki-core]** (both are direct
receivers, one aud-specific vector each).

These are the **first realm-scoped SETs** (subject is the tenant, not a
principal). Shape difference from principal events:

- **Issuer = the `system` realm** (`iss = https://auth.wendy.sh/realms/system`),
  NOT the tenant realm. The purge deletes the tenant realm's signing keys, so a
  receiver fetching that realm's JWKS post-purge (async delivery may arrive after
  purge) could never verify — the system realm's JWKS persists (it is mechanically
  undeletable). Signed at emit time with the system-realm key.
- **Subject = top-level `sub_id: {format:"uri", uri:"spiffe://wendy.sh/tenant/<tenant_uuid>"}`**
  — the tenant URI with no `<kind>/<sub>` suffix (realm-scoped truncation of the
  principal SPIFFE form). There is **no per-event `iss_sub` subject** (no principal).
  `<tenant_uuid>` is the stable/global UUID (== cloud `organizations.id` since
  WDY-2808), never the reclaimable slug.
- Event body carries only `event_timestamp` and `reason_admin`.

### Receiver verification rule (tenant-lifecycle only)

**Net gate — the cross-realm exemption is bidirectional, not a one-way relaxation.**
The exemption alone would let *any* tenant realm emit a `tenant-deleted` for another
tenant, or let the system realm act on a principal event. So the rule is an
`iss ⇔ event-type` binding, verified in both directions:

- **`iss == system` AND event-type ∈ {tenant-lifecycle}** → accept. For this class
  ONLY: verify the JWS against the **system realm** JWKS, and **do NOT** gate on
  subject-realm == issuer (the `sub_id` tenant belongs to the purged realm, not the
  system issuer). Then map `sub_id` `<tenant_uuid>` → the receiver's own tenant/org
  record and run **tenant offboarding** (cloud: org offboard; pki-core:
  `OffboardTenant`), idempotent on the SET `jti`; ack `accepted=true` on already-seen
  or unknown/never-provisioned tenant.
- **tenant-lifecycle event-type REQUIRES `iss == system`** → a `tenant-deleted`
  signed by a *tenant* realm MUST be **rejected**. (A tenant realm cannot delete
  itself or another tenant via this channel.)
- **`iss == system` with a principal/subject event-type** → **rejected**. The system
  realm's authority is scoped to tenant-lifecycle types only.
- **all other (principal/subject) event-types** stay realm-bound: issuer MUST equal
  the subject's realm (`iss->realm`), exactly as before.

The `expect` field on each vector pins this: `accept` / `reject` (absent ⇒ `accept`,
for the v1 payload-determinism vectors); `reject_reason` states why. Pinned cases:

| vector | iss | event-type | expect |
|---|---|---|---|
| `{cloud,pki}-tenant-deleted-sub-id` | system | tenant-deleted | accept |
| `cloud-tenant-deleted-wrong-issuer-reject` | tenant realm | tenant-deleted | reject |
| `pki-account-purged-system-issuer-reject` | system | account-purged (principal) | reject |

**Receiver authority.** The system-signed SET is the **sole authority** for the
offboard — there is no operator signature in this path (the cloud-initiated
`DeleteOrganization` is retired; wendy-auth is the initiator, cloud/pki-core are
notified-only per AAA §5.9). pki-core offboards directly on its own SET copy, no
cloud in the loop (wendy-self-hosted no-SaaS-dependency rule).

## Certificate-revoked events (WDY-3409)

Event-type CAEP `https://schemas.openid.net/secevent/caep/event-type/credential-change`
with `credential_type: "x509"`, `change_type: "revoke"`. **Transmitter = pki-core**,
not wendy-auth. Cloud already receives `credential-change` from wendy-auth for realm
credentials; the issuer and `credential_type` keep the two apart at dispatch.

- **Issuer** = pki-core's public hostname per env: dev `https://dev.pki.wendy.sh`,
  prod `https://pki.wendy.dev`. pki-core publishes the JWKS on that host.
- **Signing key** = a dedicated ML-DSA-65 event-signing key, never a CA key.
- **Binding** is bidirectional, like tenant-lifecycle: an x509 `credential-change`
  REQUIRES `iss == pki-core`, and a pki-core issuer is rejected for any other
  event-type or `credential_type`. Realm SETs keep the `iss->realm` rule.
- **Audience** cloud `https://cloud.wendy.sh/fabric/ssf`, the same cloud fabric aud
  wendy-auth uses. wendy-auth and devices join when they have a receiver (WDY-3403);
  each gets its own aud-specific SET.
- **One SET per revoked serial.** A by-principal revoke of N leaves emits N SETs.
- **Subject** top-level `sub_id: {format:"uri", uri:<leaf SPIFFE principal>}`; for a
  leaf with no SPIFFE SAN, the tenant URI `spiffe://wendy.sh/tenant/<tenant_uuid>`.
  No per-event `iss_sub` (pki-core holds no realm subject).
- **Event body** `{event_timestamp, credential_type, change_type, ca_id, x509_serial,
  reason}`: `x509_serial` is the CAEP claim, lowercase hex without separators;
  `ca_id` (the issuing CA, as in `CertMetadata.ca_id`) and `reason` (the RFC 5280
  reason code) are Wendy extension claims.
- `exp = iat + 300`, as above. The SET is a notification; CRL/OCSP stay the
  revocation authority for relying parties.

- **JWKS** at `<iss>/.well-known/ssf-jwks.json` (AKP keys, `alg: ML-DSA-65`). The SET
  header is `{alg: "ML-DSA-65", kid, typ: "secevent+jwt"}`; unlike the realm SETs above,
  this type is never ES256.
- `jti` (== `txn`) is stable across delivery retries; each retry is re-signed with a fresh
  `iat`/`exp`. Receivers dedup on `jti`.
- `x509_serial` is the hex of the certificate serial's big-endian integer bytes (Go
  `big.Int.Bytes()`), so it can start with `0`.

Vectors for this type come from the producer (pki-core) with WDY-3410, the same way
wendy-auth owns the payload bytes for its types. They carry `"producer": "pki-core"`.
Their canonical bytes are Go `encoding/json` (sorted keys, compact, no HTML escaping), so
forward slashes are **not** escaped. As above, verify the signed bytes as-is.

## Coverage (v1)

| name | what it pins |
|---|---|
| `cloud-session-revoked-iss-sub` | CAEP session-revoked, cloud shape (no sub_id) |
| `cloud-token-claims-change-iss-sub` | CAEP token-claims-change, cloud shape |
| `cloud-credential-change-iss-sub` | CAEP credential-change, cloud shape |
| `cloud-account-disabled-iss-sub` | RISC account-disabled as cloud sees it |
| `pki-account-disabled-operator-sub-id` | RISC account-disabled, top-level SPIFFE sub_id, kind `operator` |
| `pki-account-purged-service-sub-id` | RISC account-purged, kind `service` |
| `pki-session-revoked-operator-sub-id` | CAEP session-revoked, kind `operator`, pki aud (accept; audit only, no revoke) |
| `cloud-tenant-deleted-sub-id` | tenant-deleted, system-realm iss, tenant sub_id, cloud aud (accept) |
| `pki-tenant-deleted-sub-id` | tenant-deleted, system-realm iss, tenant sub_id, pki aud (accept) |
| `cloud-tenant-deleted-wrong-issuer-reject` | tenant-deleted signed by a tenant realm — MUST reject |
| `pki-account-purged-system-issuer-reject` | principal event signed by system realm — MUST reject |
| `cloud-x509-revoke-spiffe-sub-id` | pki-core x509 credential-change, leaf SPIFFE sub_id, cloud aud (accept) |
| `cloud-x509-revoke-tenant-sub-id` | same, leaf without a SPIFFE SAN: tenant URI sub_id (accept) |
| `cloud-x509-revoke-realm-issuer-reject` | x509 credential-change from a realm issuer — MUST reject |
| `cloud-pki-issuer-session-revoked-reject` | pki-core issuer on a non-x509 event — MUST reject |

## Notes / limitations

- **No signatures in v1** — signing/verification is covered by the existing reqsig
  vectors (`conformance/reqsig/`); the deterministic anchor here is the payload bytes.
- Freshness windows and replay storage are receiver-side concerns; the vectors pin
  claim VALUES, not verifier clock behavior.

## Regenerating

wendy-auth: `WENDY_AUTH_GENERATE_SET_VECTORS=<out.json> swift test --filter SETVectorGeneration`
(then verify determinism by generating twice and diffing).
pki-core (the `producer: pki-core` vectors): `PKICORE_GENERATE_SET_VECTORS=<out.json> go test
-run TestSETVectors_MatchServiceProtos ./internal/ca/`. Without the variable, that test checks
pki-core's bytes against this file. Regeneration is only
legitimate when the CONTRACT changes — receivers conform to the committed bytes.
