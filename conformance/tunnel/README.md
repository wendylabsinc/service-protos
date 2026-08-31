# Tunnel v1 wire conformance

The authoritative contract is
[`wendycloud/tunnel/v1/tunnel.proto`](../../wendycloud/tunnel/v1/tunnel.proto).
It fixes the identity-blind broker boundary, canonical proof inputs, ephemeral
principal request, pki-core attestation, HPKE envelope, session admission, and
presence ownership rules.

Implementations must test these invariants before enabling the v1 services:

- `tunnel.proto` in the repository root remains the unchanged legacy API.
- The principal's existing §4.1 cert-bound request signature covers the complete
  request body, including target, symbolic service, and ephemeral caller key.
  Cloud submits both to pki-core; neither crosses the broker boundary. Pki-core
  returns a short-lived identity-free attestation over the exact request and key
  bindings. The broker independently verifies that signature and Cloud's KMS
  session-grant signature and requires their audience/request/key bindings to
  agree. Thus Cloud cannot fabricate principal authority. Other broker-facing
  messages and signed grants contain no user, organization, asset, service,
  hostname, port, `sub`, certificate, or Wendy identity.
- The signed §4.1 descriptor `nonce` is pki-core's sole single-use replay key;
  first use consumes it and an identical duplicate is rejected. The body's
  16-byte `request_id` is only an opaque caller request/idempotency identifier,
  never a second replay key. Replay state is retained through descriptor expiry
  plus verifier clock skew and then reaped.
- Pki-core derives the request verifier and algorithm from the validated leaf
  and extracts its tenant from the Wendy SPIFFE SAN. Tunnel v1 permits only
  RFC 9964 ML-DSA-44/65/87 (default ML-DSA-65); ES256 is not authorized for
  this purpose. Header/leaf algorithm substitution and downgrade fail closed.
- Every P-256 SPKI uses one canonical strict-DER form: `id-ecPublicKey`, named
  `prime256v1`, and an uncompressed point. Ingress parse/re-serialize equality
  is mandatory and bindings hash only those canonical bytes.
- Agent signing and HPKE key-agreement SPKIs are distinct P-256 keys. Presence
  open supplies the signing SPKI whose exact DER hash is lease-bound; a proven
  route retains it for agent-role join proofs. Caller join proofs use the SPKI
  supplied to CreateSession after both pki attestation and Cloud grant bind it.
- HPKE is RFC 9180 base mode
  `DHKEM(P-256,HKDF-SHA256)+HKDF-SHA256+AES-128-GCM`; envelope info, AAD,
  encapsulated key, and ciphertext reproduce GrantKit's exact canonical tuple
  and grant binding hash. AAD contains session/request context only; service
  data exists only inside the bound HPKE plaintext and Cloud audit.
- HPKE base mode is not Cloud sender authentication. Before decrypt or dial,
  the agent independently resolves the grant `kid` through Cloud's rotating,
  issuer-pinned JWKS and verifies Cloud KMS signature, exact issuer/current
  boot audience/session/routing/presence/key bindings, time bounds, canonical
  envelope hash, and HPKE context. Any failure performs no decrypt and no dial.
- Broker audiences are 256-bit CSPRNG boot-incarnation identifiers, never
  persisted or reused. Cloud selects only a current live incarnation; restart
  makes every old grant/attestation fail audience even if still unexpired.
- HPKE info/AAD exactly match typed GrantKit `TunnelHPKEContext`: session and
  opaque route plus raw SHA-256 of the agent key-agreement SPKI DER in info;
  session plus raw SHA-256 of the exact decoded caller payload in AAD. GrantKit
  reconstructs and verifies that context rather than accepting caller bytes.
- Canonical `DialInstruction` plaintext is exactly 4096 bytes using a final
  random authenticated padding field; HPKE ciphertext plus GCM tag is exactly
  4112 bytes. Receivers validate AEAD, exact size, and canonical/semantic fields
  before ignoring padding.
- DATAGRAM `RequestTunnelResponse` exposes 1..32 opaque destination ids to the
  caller without ports, hosts, agent, or target details. Cloud verifies that
  their unique set exactly equals the encrypted instruction's authorized
  destination-id set before broker session creation and before responding. The
  broker never receives this Cloud-to-caller list; TCP responses keep it empty.
- Presence and join proof preimages use the documented domain strings and
  32-bit big-endian length prefixes. Roles, exact artifact bytes, audience,
  opaque handles, and one-use challenge bytes are covered by signatures.
- Presence reconnect creates a fresh challenge and never steals an active
  owner. Renewal preserves route/key bindings while rotating lease `jti`.
- Logical session offers have stable opaque offer/session ids and at-least-once
  delivery across presence reconnects until admission expiry. Acknowledgement
  is idempotent receipt only and never consumes the session grant `jti`.
- CreateSession consumes the pki-core attestation `jti` and exact attestation
  hash when it first reserves the session. Only a byte-identical full request is
  an idempotent retry; conflicting attestation, grant, caller key, or envelope
  reuse is rejected. Session grant `jti` is consumed only by the atomic
  active-pair transition. Admission ends at `exp` and an active relay ends at
  `relay_exp`, which is no more than 3600 seconds after `iat`.
- Dial/frame compatibility covers TCP byte streams plus the legacy DATAGRAM
  UDP-flow and agent ICMP echo modes with transport-specific field limits.
  DATAGRAM ports occur only in up to 32 encrypted Cloud-authorized destination
  mappings; frames carry opaque destination ids. Sessions allow 64 live flows,
  16 new flows per rolling second, and expire flows after 2 minutes idle.

## Vector file

[`blind-attestation-vectors-v1.json`](blind-attestation-vectors-v1.json) is the
authoritative cross-language golden fixture. It pins the full two-signer path:
a complete protobuf request body and cert-bound request signature, the mandatory
audited Cloud-to-pki Envelope, an identity-free pki-core attestation, a Cloud KMS
session grant, a real HPKE seal, role proofs, attestation consumption/retry, and
negative cases that prove neither signer can substitute for the other.
The pki-core attestation protected `typ` is exactly
`tunnel-principal-attestation+jwt`; the Cloud session grant is a compact JWS
whose protected `typ` is exactly `tunnel-session-grant+jws`.

The authoritative blind-attestation fixture is organized as:

- `keys`: fixed test-only P-256 private scalars plus a pinned ML-DSA-65 key,
  DER SubjectPublicKeyInfo values, and the raw-hex plus unpadded-base64url
  SHA-256 SPKI bindings. Signing, key-agreement, Cloud signing, and HPKE sender
  keys are distinct.
- `principal_request`: the complete policy-bearing protobuf body, cert-bound
  request descriptor, root/leaf test chain, exact protected header and ML-DSA-65
  signature, request/key hashes, and the boundary marking runtime certificate
  status as authoritative.
- `cloud_to_pki_envelope` and `pki_attestation`: the exact audited Envelope,
  principal request in `signed_artifact`, payload bytes, dedicated pki signing
  key, identity-free claims, and alternate valid attestation signature.
- `dial_instruction`: the exact 4096-byte canonical protobuf plaintext,
  authenticated padding from one fixed, one-time CSPRNG sample (never a
  repeated-byte pattern), two ordered authorized DATAGRAM mappings, and the
  exact caller-visible opaque destination-id list.
- `hpke_envelope`: exact info and AAD, a valid fixed P-256 encapsulated key, a
  real RFC 9180 base-mode 4112-byte seal, component digests, and the canonical
  envelope-preimage length/hash. Every preimage byte is reconstructable from
  the listed components. `alternate_valid` is a second real seal used by the
  conflicting-envelope case.
- `cloud_artifacts`: exact sorted-key presence/session JSON, protected JOSE
  headers, pinned valid Cloud ES256 compact JWS values, and the exact JWKS that
  verifies them. Alternate valid grant signatures distinguish exact bytes from
  equivalent claims. The alternate-envelope grant retains the same `jti` and
  `session_id` while binding the second valid envelope.
- `proofs`: presence, caller-join, and agent-join domains, roles, challenges,
  exact canonical preimages/digests, and valid raw P-256 signatures.
- `principal_request_replay_cases`: first use consumes the signed descriptor
  nonce and an identical duplicate is rejected without changing replay state;
  the body `request_id` remains the same opaque idempotency identifier in both.
- `malformed_protobuf_cases`: compact deterministic mutation recipes against
  the canonical dial fixture, covering invalid padding size, string/control/descriptor bounds, and
  transport/destination semantic violations. Except for the dedicated size
  failure, each dial recipe rebalances padding from the fixed sample to remain
  exactly 4096 bytes and declares the precise semantic rule it must reach.
- `create_session_cases` and `reference_replay_cases`: first reservation,
  exact retry, attestation consumption, conflicting grant/attestation/key/
  envelope reuse, a valid second session rejected by the broker-global
  attestation replay index, plus exhaustive
  typed reference events for acknowledgement, failed/partial proofs,
  disconnects, fingerprint-aware exact create retry versus conflicting create,
  atomic ACTIVE consumption, replay rejection, retention, unknown events, and
  invalid transitions. Every agent proof attempt requires prior offer
  acknowledgement. Exact fingerprint retries return the current reservation
  unchanged in both WAITING and ACTIVE; conflicting fingerprints return
  `ALREADY_EXISTS` unchanged in both states. The replay model is a process-local
  conformance oracle, not the broker's runtime persistence implementation.
- `negative_cases`: named header, claim, Envelope-kind, target/body semantic, expiry,
  audience, signer, request/key/attestation/envelope binding, HPKE context,
  proof, and attestation-replay substitutions.

Standard-base64 fields end in `_b64`; unpadded base64url fields say `_b64url`.
Large plaintext/ciphertext values, both envelope preimages, and the fixed
padding sample are stored in full, not as illustrative prefixes. Malformed
protobuf values are represented as recipes to avoid duplicating the 4096-byte
fixture for every negative case.

## Verification requirements

Consumers must load this checked-in JSON and reconstruct values with their
production protobuf, JOSE, P-256, SHA-256, HPKE, and canonical proof-input
implementations. Comparing duplicated constants without parsing, hashing, or
signature verification is not conformance. In particular, a receiver should:

1. Strictly decode and re-encode both protobuf payloads byte-for-byte, including
   omitted proto3 defaults and the final authenticated padding field. Reject
   unknown fields, duplicate/nonascending fields, explicit defaults, overlong
   varints, and every named semantic violation by reconstructing the malformed
   recipes. Confirm that every semantic mutation other than the dedicated size
   failure is still exactly 4096 bytes and reaches its declared rule.
2. Derive classical public keys from fixed scalars, parse the ML-DSA leaf,
   reproduce each SPKI binding, and verify the principal request, pki
   attestation, Cloud artifacts, and join
   signatures,
   including every `alternate_valid*` signature over its declared payload or
   claims.
3. Rebuild HPKE info/AAD and every explicit envelope preimage, verify their
   lengths and hashes, then open every real seal to its exact 4096-byte
   plaintext.
4. Enforce exact protected headers, validated-leaf request keys, certificate
   tenant/Envelope tenant equality, exact issuer/audience/type, claim windows,
   request/key/envelope bindings, role/challenge separation, and every named
   negative.
5. Drive every typed reference replay event and invalid transition, failing
   unknown events closed, distinguishing a byte-identical fingerprint retry
   from conflicting reuse, requiring acknowledgement before every agent proof
   attempt, preserving state/fingerprint after every rejected event, and
   checking retry/conflict behavior before and after ACTIVE consumption.
6. Consume the pki-core attestation `jti` and exact attestation hash on initial
   reservation. Treat only byte-identical grant, attestation, caller key, and
   envelope input as an exact retry; preserve the original reservation on every
   conflicting reuse. Enforce both replay indexes broker-wide, including across
   distinct otherwise-valid session/grant ids. Consume the Cloud session-grant
   `jti` only at the atomic verified caller+agent ACTIVE transition.

Certificate-chain and signature checks are reproducible offline. Certificate
status/revocation is intentionally not: implementations must obtain an
authoritative status result from pki-core's runtime trust path and must not treat
the fixture's status recipe as evidence of current certificate validity.

ECDSA and ML-DSA signing are randomized, so pinned signatures are snapshots to verify, not
bytes to reproduce by re-signing. The canonical payloads, bindings, proof
preimages, HPKE seal (fixed test sender scalar), and all hashes are deterministic.
Regenerate only for an intentional wire-contract revision, generate twice to
confirm all non-ECDSA bytes are stable, and have at least one independent
implementation verify the proposed replacement before committing it.

All private test material represented by the JSON is public fixture data. It MUST NOT be used
for production, development credentials, examples that might be copied into a
deployment, or any purpose beyond conformance testing.
