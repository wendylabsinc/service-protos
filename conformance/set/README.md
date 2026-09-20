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
  - pki-core-bound (RISC account-disabled/purged): additionally top-level
    `sub_id: {format:"uri", uri:"spiffe://wendy.sh/tenant/<tenant_uuid>/<kind>/<sub>"}`
    with `<kind>` ∈ {`operator`, `service`} — byte-matching the SAN pki-core mints
    via `spiffeid.BuildTenantURI`.

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

## Coverage (v1)

| name | what it pins |
|---|---|
| `cloud-session-revoked-iss-sub` | CAEP session-revoked, cloud shape (no sub_id) |
| `cloud-token-claims-change-iss-sub` | CAEP token-claims-change, cloud shape |
| `cloud-credential-change-iss-sub` | CAEP credential-change, cloud shape |
| `cloud-account-disabled-iss-sub` | RISC account-disabled as cloud sees it |
| `pki-account-disabled-operator-sub-id` | RISC account-disabled, top-level SPIFFE sub_id, kind `operator` |
| `pki-account-purged-service-sub-id` | RISC account-purged, kind `service` |
| `cloud-tenant-deleted-sub-id` | tenant-deleted, system-realm iss, tenant sub_id, cloud aud (accept) |
| `pki-tenant-deleted-sub-id` | tenant-deleted, system-realm iss, tenant sub_id, pki aud (accept) |
| `cloud-tenant-deleted-wrong-issuer-reject` | tenant-deleted signed by a tenant realm — MUST reject |
| `pki-account-purged-system-issuer-reject` | principal event signed by system realm — MUST reject |

## Notes / limitations

- **No signatures in v1** — signing/verification is covered by the existing reqsig
  vectors (`conformance/reqsig/`); the deterministic anchor here is the payload bytes.
- Freshness windows and replay storage are receiver-side concerns; the vectors pin
  claim VALUES, not verifier clock behavior.

## Regenerating

wendy-auth: `WENDY_AUTH_GENERATE_SET_VECTORS=<out.json> swift test --filter SETVectorGeneration`
(then verify determinism by generating twice and diffing). Regeneration is only
legitimate when the CONTRACT changes — receivers conform to the committed bytes.
