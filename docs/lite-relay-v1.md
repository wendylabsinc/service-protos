# Lite relay v1 (WDY-3512)

The relay runs in TunnelBroker. The outer TLS connection authenticates the
provisioned device and the configured broker hostname. Device trust comes from
its enrollment-provisioned HTTPS roots. Grant keys arrive only through this
connection, after TLS authentication. Neither the CLI nor an inner TLS peer can
install a grant key. Each fresh control connection installs a fresh key set.

## Tier

Tier C is an asset registered `wendy-lite` at enrollment: a device that
terminates mTLS itself and cannot verify ML-DSA. Only Tier-C assets enter this
lane, and only they are issued P-256 grants. Cloud refuses the Lite lane, and
any P-256 grant, for a Tier-A or Tier-B asset; those stay on the ML-DSA tunnel-v2
lane. The tier is a property of the enrolled asset, never caller input, and is
never negotiated on the wire.

## Outer control records

All records begin with the four bytes `57 52 03 opcode`. No v1 or v2 records are
accepted. Integers are unsigned, big endian. Reads may split or combine records.

* `01` ping and `02` pong have no body. Send ping every 20 seconds; require pong
  within 10 seconds. The first ping follows the key-set record.
* `04` key set precedes the first ping. Its body starts with a one-byte count
  in 1..2, followed by that many entries. Each entry is a one-byte key-ID length
  in 1..128, the ASCII key ID, and exactly 65 uncompressed SEC1 P-256 public-key bytes (`04 || x[32] || y[32]`).
  Reject duplicate IDs and invalid lengths. This replaces all previous keys.
* `03` upgrade has a 16-byte session ID and a 32-byte SHA-256 hash of the exact
  compact grant record. The device retains both values with this socket.
  The broker then sends TLS close_notify and waits for the peer close_notify.
  Both preserve TCP and discard the outer TLS state. The device becomes an mTLS
  server; the CLI is the client. The device accepts no further outer records.

Key IDs contain only ASCII letters, digits, period, underscore, and hyphen.
The keys belong to the dedicated Lite Cloud signer, including an optional previous
key for rotation overlap. They are separate from ML-DSA control-plane keys. A broker that
cannot obtain its current key must not publish device presence.

## Compact grant record

The Lite grant is the same AAA §5.8 grant in a compact binary encoding signed
ES256 (Tier C).

The first application bytes after the inner mTLS handshake are exactly one
record with the following layout. There is no JSON, JWS, CBOR, padding, or
trailing data within the record. The key-ID length determines the record length.

| Field | Bytes |
| --- | ---: |
| ASCII `WLG3` | 4 |
| Key-ID length | 1 |
| Key ID | 1..128 |
| Issued at, Unix seconds | 8 |
| Expires at (present-by), Unix seconds | 8 |
| Random session ID | 16 |
| Grant ID (`jti`), random, single-use | 16 |
| Correlation ID | 16 |
| SHA-256 of exact device SPIFFE URI UTF-8 | 32 |
| SHA-256 of exact operator SPIFFE URI UTF-8 | 32 |
| SHA-256 of operator caller key SubjectPublicKeyInfo DER | 32 |
| SHA-256 of decoded signed principal descriptor payload | 32 |
| SHA-256 of the exact pki-core attestation compact JWS (ASCII) | 32 |
| P-256 ECDSA signature, raw `r[32] || s[32]` | 64 |

The signature is ES256: ECDSA P-256 over SHA-256 of every preceding
byte, starting with `WLG3`. The P-256 Lite grant key signs only these Tier-C
grant records, never a JWS artifact; the magic keeps the record distinct from
every other signed format. Total length is
`293 + key_id_length` bytes. Unknown versions, algorithms and key IDs fail closed.

The device URI hash is the record's only device identifier (WDY-3919). A device
has one id, the UUID segment of `spiffe://wendy.sh/tenant/<tenant>/device/<uuid>`,
which is also its cloud asset id; the record carries no separate asset UUID.
The hash binds tenant and UUID in 32 bytes the device compares against the
SHA-256 of its own certificate's SAN URI, with no UUID parsing on the device.

**WLG2 (retired).** WLG2 was this layout with a 16-byte asset UUID after the
correlation ID. It is retired at once, with no dual-accept window (sem
2026-10-19 17:27; every Lite device is test fleet): Cloud issues only WLG3, and
firmware and the CLI accept only WLG3 and refuse a WLG2 record by its magic.

The correlation ID is the request's §11.2 `correlation_id`: its 16 UUID bytes
when it is exactly the 36-character hyphenated 8-4-4-4-12 form (hex digits case-insensitive, mixed included),
else the first 16 bytes of SHA-256 of its UTF-8. Braced, URN and bare-hex
forms are not that form and take the hash. Cloud never
mints a second one for the grant. The attestation hash binds the exact
`tunnel-principal-attestation+jwt` pki-core returned for this request.
`expires_at` bounds presentation only: it is at most 60 seconds after
`issued_at` and never later than the attestation's `exp`, as for every §5.8
grant. The 1800-second limit is a session property (Session bounds), not grant
validity.

Cloud first authorizes the resolved `tunnel:connect` permission, verifies the
operator-signed request through pki-core (tunnel-v2 body, descriptor operation
`create_lite_tunnel`, never `create_tunnel`), and checks that the returned
attestation binds the exact descriptor payload and the caller signing key (the
Lite leaf's P-256 key, also the inner TLS client key; see Operator dual-key). The
service is `wendycom`. The operator envelope uses ES256; this exception does not
permit classical signatures for other tunnel-v2 services or device requests. Only after successful attestation may Cloud derive the
operator URI (or a service account's, see Service accounts), and only from the
`AttestTunnelPrincipalResponse` operator fields pki-core fills from its
validation of that same x5c leaf. Cloud refuses the
Lite lane when those fields are empty and never falls back to another validator;
`operator_leaf_spki_sha256` must equal the attested caller key hash, and pki-core
requires that caller key to be the x5c leaf key. It must be a single operator or
service identity in the device's tenant. It must never derive this identity from unsigned metadata.

The device verifies the signature using the key set from this socket's outer
TLS connection. It checks the grant's SHA-256 and session ID against the upgrade
record, device URI against its own certificate, and operator URI against the
validated same-tenant inner TLS client certificate. Different operator signing
and TLS leaf certificates may represent the same PKI-issued principal, but not
different keys: Cloud fills the key hash from the caller signing key the
attestation binds, and the device MUST match this hash against the SHA-256 of
the SubjectPublicKeyInfo DER of the inner TLS leaf it accepted; a mismatch MUST
be refused before WendyCom is exposed. A URI match alone never admits the session.
The device MUST refuse the grant unless both `issued_at - 60 s <= now < expires_at + 60 s`
and `0 < expires_at - issued_at <= 60` hold.
The ±60-second clock-skew allowance (the v2 broker's replay retention skew, one
number for both lanes) applies to that validity window only, never
to the 60-second ceiling, the session limit or any other check.
It MUST refuse a `jti` it has already accepted: it keeps accepted `jti` values
in a bounded cache until their `expires_at` plus the 60-second skew, which the
60-second validity bounds (firmware WDY-3565). When the cache is full it MUST
refuse new grants; it MUST NOT evict an entry before that retention ends. It rejects a grant before exposing WendyCom.
The upgrade binding additionally ties a grant to one device socket. A repeated
preface is an invalid WendyCom frame.

After verification the device writes `57 4c 41 32` (`WLA2`). The CLI waits for
this acknowledgement before sending the established stream message and before
sending any WendyCom frame. Missing/invalid grant or acknowledgement closes TLS.

## Session bounds and routing

Cloud enforces at most four concurrent sessions per authenticated user and one
per asset across broker processes. Admission and release are atomic; stale
reservations expire. A replacement control connection does not bypass a claim.
The session closes no later than 1800 seconds after the grant's `issued_at`, and
never after the operator leaf or device certificate expires; the broker enforces
this, and the device closes WendyCom at most 1800 seconds after it accepted the
grant.

A session has 10 seconds from claim to established, including outer shutdown,
inner TLS and grant verification. Afterwards it has a 60-second inactivity
limit, reset by bytes in either direction. The device independently enforces
its handshake deadline, the grant's present-by time and the session limit. Established is not an authentication
proof; the operator principal proof is verified before claim, and the device
performs its own verification before accepting application traffic.

Presence records identify an exact routable broker endpoint. A different broker
returns a route only after asset authorization, before attestation or claim.
Clients verify TLS for that endpoint, authenticate a new stream, and limit route
retries to three. Deployments must advertise an endpoint that reaches the owning
process; a load-balanced endpoint without instance affinity is invalid.

## Operator dual-key

An operator has one identity (one SPIFFE URI) and two certificates: an ML-DSA
**primary** under the tenant Operator Authority for every operator call except
the Lite lane, including the request for the second; and a P-256 **Lite** leaf
with the same SPIFFE URI and tenant, used only for the ES256
`create_lite_tunnel` envelope and as the inner TLS client certificate.

**Lite leaf profile.** keyUsage `digitalSignature` only (critical); extKeyUsage
exactly {`id-kp-clientAuth`, `id-kp-wendyLiteOperator` =
`1.3.6.1.4.1.65441.1.9`}, never anyExtendedKeyUsage. That EKU is the marker:
pki-core sets it on every P-256 operator leaf and on no other certificate.
Verifiers require the EKU extension and both OIDs literally (mbedTLS: iterate
`ext_key_usage`, not the helper, which passes when absent).

**Lite Operator Authority.** Each tenant may hold one active Lite Operator
Authority: a self-signed P-256 CA (pathLen 0) that pki-core creates per tenant
and keeps beside the ML-DSA chain, not under it, because a Tier-C device cannot
parse an ML-DSA-signed certificate. It issues only Lite leaves and signs its own
CRL, published like other tenant CRLs. A Tier-C device holds its tenant's Lite
Operator Authority certificate as its operator trust anchor and refuses every
Lite session without one. It accepts that anchor only from pki-core's enrollment
response over the TLS channel its enrollment roots authenticate, bound to its
own identity; BLE provisioning, local configuration and the CLI never set it.
The CLI sends only the Lite leaf in the inner TLS Certificate message.

**Anchor delivery.** A successful `device-tier-c` response from EST
`simpleenroll` or `simplereenroll`, CSR `/v1/{tenant_id}/enroll` or
`/v1/{tenant_id}/renew`, or `/v1/renew` carries that certificate in the HTTP
header `X-Wendy-Lite-Operator-Authority`, standard base64 of its DER; pki-core
creates the authority on first use. No other response carries it, so a Tier-C
device enrolls and renews over EST or CSR. An enrollment that cannot attach it
fails; a renewal that cannot goes on without it. The device MUST pin it as its
only operator anchor and MUST refuse one that is not a self-signed P-256 CA
certificate. Rotation: when a later renewal response carries the header, the
device MUST replace its pinned anchor with it, so a new Lite Operator Authority
reaches a device at its next renewal; a renewal without the header keeps the
pinned anchor. The header is additive: a client that ignores it is unaffected.

**Issuance.** pki-core issues a P-256 operator leaf only from `POST
/v1/identity/certificate`, and only when the access token's `cnf.jkt` and the
DPoP proof key are an ML-DSA key equal to the key of at least one active,
unrevoked primary of the same principal and tenant. Every other issuance path
(RelayIssuance, entitled and over-duration certificates, bootstrap) refuses a
non-ML-DSA operator CSR. The CSR carries the P-256 key and proves possession;
this is the only waiver of thumbprint(CSR key) == `cnf.jkt`. SPIFFE URI and
tenant come from the token and those primaries; CSR subject and extensions are
ignored. pki-core never certifies a key it has revoked.

**Lifetime and revocation.** notAfter is clamped to the earliest notAfter of
those primaries, never extended; renewal meets the same precondition. Revoking
any of those primaries, disabling the principal, or offboarding the tenant
revokes the Lite leaf. pki-core checks revocation on every `create_lite_tunnel`
attestation; an established session is not cut (at most 1800 s).

**Verifiers.** Each service validates operator leaves in one place. By default
it refuses a non-ML-DSA leaf, a leaf with the marker, and any chain through a
Lite Operator Authority; no other trust pool contains one. The opt-in is keyed
by the credential class pki-core issued (marker plus Lite Operator Authority
chain, which no caller can mint) and the signed
`create_lite_tunnel`/`wendycom`/ES256 descriptor; pki-core alone opts in, and
requires a P-256 leaf with the marker, chaining to the admitted tenant's active
Lite Operator Authority, SAN tenant equal, unrevoked. Three barriers keep it
Tier-C only: Cloud's tier gate (the immutable `wendy-lite` asset type, §Tier),
pki-core's Lite-only pool, and the device anchor. pki-core is not a target-tier
gate today (WDY-3640). Cloud takes the operator identity from the attestation
response, never from `ValidateOperatorCertificate`, which has no opt-in. A
Tier-C device requires the inner TLS leaf to chain to its anchor with the Lite
profile, then applies the grant checks above.

**Service accounts.** A service-account identity (SPIFFE kind `service`)
follows the same rules: an ML-DSA primary, and at most the same Lite leaf
(marker, Lite Operator Authority, ML-DSA session of that same service principal,
linked lifetime and revocation). Every operator-class verifier applies the same
default deny to service leaves, so an unmarked non-ML-DSA service leaf is
refused wherever an operator leaf would be; that refusal, not issuance, is the
guarantee. It breaks any EC service-account credential. `create_lite_tunnel`
admits a service principal holding that Lite leaf exactly as an operator
(WDY-3651): pki-core fills `AttestTunnelPrincipalResponse` fields 16-18 for it,
`operator_principal_uri` being the service SPIFFE URI, whose kind segment
carries `service`; Cloud takes the principal and its kind from that URI, never
from unsigned metadata. A service account signs no other tunnel operation, and
an unmarked service leaf stays refused there.

**Audit.** Lite issuance, its refusals and every Lite grant record operator URI,
tenant, key algorithm, leaf and primary serials, `correlation_id`.
