# Lite relay v1 (WDY-3512)

The relay runs in TunnelBroker. The outer TLS connection authenticates the
provisioned device and the configured broker hostname. Device trust comes from
its enrollment-provisioned HTTPS roots. Grant keys arrive only through this
connection, after TLS authentication. Neither the CLI nor an inner TLS peer can
install a grant key. Each fresh control connection installs a fresh key set.

## Outer control records

All records begin with the four bytes `57 52 02 opcode`. No v1 records are
accepted. Integers are unsigned, big endian. Reads may split or combine records.

* `01` ping and `02` pong have no body. Send ping every 20 seconds; require pong
  within 10 seconds. The first ping follows the key-set record.
* `04` key set precedes the first ping. Its body starts with a one-byte count
  in 1..2, followed by that many entries. Each entry is a one-byte key-ID length
  in 1..128, the ASCII key ID, and exactly 1952 ML-DSA-65 public-key bytes.
  Reject duplicate IDs and invalid lengths. This replaces all previous keys.
* `03` upgrade has a 16-byte session ID and a 32-byte SHA-256 hash of the exact
  compact grant record. The device retains both values with this socket.
  The broker then sends TLS close_notify and waits for the peer close_notify.
  Both preserve TCP and discard the outer TLS state. The device becomes an mTLS
  server; the CLI is the client. The device accepts no further outer records.

Key IDs contain only ASCII letters, digits, period, underscore, and hyphen.
The keys are the existing Cloud grant keys, including an optional previous key
for rotation overlap. They are not new per-device signing keys. A broker that
cannot obtain its current key must not publish device presence.

## Compact grant record

The first application bytes after the inner mTLS handshake are exactly one
record with the following layout. There is no JSON, JWS, CBOR, padding, or
trailing data within the record. The key-ID length determines the record length.

| Field | Bytes |
| --- | ---: |
| ASCII `WLG1` | 4 |
| Key-ID length | 1 |
| Key ID | 1..128 |
| Issued at, Unix seconds | 8 |
| Expires at, Unix seconds | 8 |
| Random session ID | 16 |
| Asset UUID, network byte order | 16 |
| SHA-256 of exact device SPIFFE URI UTF-8 | 32 |
| SHA-256 of exact operator SPIFFE URI UTF-8 | 32 |
| SHA-256 of decoded signed principal descriptor payload | 32 |
| ML-DSA-65 signature | 3309 |

The signature is pure FIPS 204 ML-DSA-65 with empty context over every preceding
byte, starting with `WLG1`. The magic separates this artifact from all JWS
artifacts signed by the same KMS-held Cloud grant key. Total length is
`3458 + key_id_length` bytes. Unknown versions, algorithms and key IDs fail closed.

Cloud first authorizes the resolved `tunnel:connect` permission, verifies the
operator-signed tunnel-v2 request through pki-core, and checks that the returned
attestation binds the exact descriptor payload and ephemeral caller key. The
service is `wendycom`. Only after successful attestation may Cloud derive the
operator URI from pki-core validation of that same x5c leaf. It must be a single operator identity in
the device's tenant. It must never derive this identity from unsigned metadata.

The device verifies the signature using the key set from this socket's outer
TLS connection. It checks the grant's SHA-256 and session ID against the upgrade
record, device URI against its own certificate, and operator URI against the
validated same-tenant inner TLS client certificate. Different operator signing
and TLS leaf certificates may represent the same PKI-issued principal.
It checks `issued_at <= now < expires_at` and
`0 < expires_at - issued_at <= 1800`. It rejects a grant before exposing WendyCom.
The upgrade binding makes grants single-use across device sockets without
persistent device replay storage. A repeated preface is an invalid WendyCom frame.

After verification the device writes `57 4c 41 31` (`WLA1`). The CLI waits for
this acknowledgement before sending the established stream message and before
sending any WendyCom frame. Missing/invalid grant or acknowledgement closes TLS.

## Session bounds and routing

Cloud enforces at most four concurrent sessions per authenticated user and one
per asset across broker processes. Admission and release are atomic; stale
reservations expire. A replacement control connection does not bypass a claim.
The session closes at its signed expiry, no later than 1800 seconds after issue.

A session has 10 seconds from claim to established, including outer shutdown,
inner TLS and grant verification. Afterwards it has a 60-second inactivity
limit, reset by bytes in either direction. The device independently enforces
its handshake deadline and grant expiry. Established is not an authentication
proof; the operator principal proof is verified before claim, and the device
performs its own verification before accepting application traffic.

Presence records identify an exact routable broker endpoint. A different broker
returns a route only after asset authorization, before attestation or claim.
Clients verify TLS for that endpoint, authenticate a new stream, and limit route
retries to three. Deployments must advertise an endpoint that reaches the owning
process; a load-balanced endpoint without instance affinity is invalid.
