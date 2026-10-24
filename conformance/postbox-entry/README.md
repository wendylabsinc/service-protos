# Postbox entry: operator CA, validity, target and signing time (WDY-4015 items 1, 3, 7, 8)

How a device resolves the CA behind an operator-signed postbox entry, how
long an entry stays valid, which target it binds, and which time it was
signed at. Rulings: sem 2026-10-23 22:27 (items 1, 3), corrected 22:30
(operator CA); orchestrator 2026-10-24 03:25 under D9 (signing time).
`PostboxEntry` is unchanged.

## Operator CA on request (item 1)

An entry's `request_jws` carries only the operator leaf in `x5c`. The leaf is
issued by the tenant's Operator Authority CA, a sibling of the Device Identity
CA under the tenant CA. The device holds the tenant CA from enrollment but not
necessarily the Operator CA. Nothing is attached to the entry (a chain is too
heavy for Lite devices).

1. The device asks `DevicePostboxService.GetOrgCAs` (`wendycloud/v2/postbox.proto`)
   with `issuer` = the leaf's DER issuer Name, or empty for every CA its tenant
   CA has issued. pki-core's ML-DSA leaves carry no authority key identifier
   (`buildManualLeafExts`, pki-core `e5db2982`), so the name is the lookup key.
2. The answer is cloud-asserted. The device caches a returned certificate only
   if it is a CA (`not_a_ca`) issued directly by the tenant CA it already
   holds and valid now (`not_under_org_ca`). A refused certificate is not
   cached.
3. The device then chains the leaf through the cached CA to its tenant CA at
   the entry's signing time (`genTime`, item 8).
4. A non-empty `issuer` that matches no CA is `NOT_FOUND`. An entry whose
   issuer the device cannot resolve is **held, not consumed**: not applied,
   not acked, not refused, and the high-water mark does not pass it. The
   device asks again on its next pull. Cloud can stall a device this way, but
   it can withhold the entry anyway.

Ways A (pki-core: a device with a valid cert fetches its org's CAs, WDY-4016)
and B (cloud sends the org CAs at enrollment and on rotation, WDY-4017) fill
the same cache.

## Instruction validity (item 3)

Devices can be offline for weeks, so the 30 s request-signing `expiry` cannot
be an instruction's lifetime. Each postbox-relayed request carries its own
validity, set by the signing operator client inside the signed payload:

| request | field |
|---|---|
| `DeploymentService.CreateDeployment` | `CreateDeploymentRequest.valid_until` (8) |
| `DeploymentService.ControlContainer` | `ControlContainerRequest.valid_until` (5) |
| `ArtifactRegistryService.AssignDevice` | `DeviceAssignment.expires_at` (10), which already existed and cloud already requires |
| `ArtifactRegistryService.UnassignDevice` | `UnassignDeviceRequest.valid_until` (4) |

**Why the payload and not a JWS claim:** the JWS claims are the call to cloud.
They are shared by every verifier of the generic gate, and `expiry` already
lives there. An instruction validity next to it would invite the confusion the
ruling removes, and a new claim would touch every reqsig producer and verifier.
The payload is the instruction the device decodes and applies, it is already
under the signature (`body_sha256`), and a field there is additive per message.
`PostboxEntry` has no operator-signed body of its own.

Rules:

- **Caps.** Platform cap 1 year (365 days, 31 536 000 s). Tenant cap: default
  2 months (60 days, 5 184 000 s), configurable per tenant in the cloud
  dashboard, never above the platform cap. Cloud measures both from the
  signed `iat` at accept; the device measures the platform cap from the
  entry's `genTime` (item 8). The operator client defaults `valid_until` to
  `iat` + the tenant cap.
- **Cloud, at accept** (on top of the generic gate, whose 30 s `expiry`
  stays): refuse when `valid_until` is absent (`validity_missing`; enforced
  once the CLI and console set it, see the contract ledger), above the
  platform cap (`above_platform_cap`) or above the tenant cap
  (`above_tenant_cap`). A cap equal to `valid_until − iat` passes.
- **Cloud, queue.** A queued entry is kept until the device is deleted.
- **Device.** Checks, after the chain, signature, target and signing time:
  `valid_until` present (`validity_missing`), `valid_until − genTime` within
  the platform cap (`above_platform_cap`, so a cloud that skipped the accept
  check gains nothing), and trusted now `< valid_until` (`stale`; strict,
  like `expiry`). Trusted now is the TSA/checkpoint time when present, else
  the device clock.
- **The device does not check the request `expiry` or the ±60 s `iat` window
  on a postbox entry.** Its former 10-minute `expiry − iat` cap is gone.
- A `stale` entry is refused and consumed (reported `REJECTED_STALE`); a held
  entry (items 1, 8) is not.

## Target (item 7)

A relayed `ControlContainer` names the container it acts on:
`target.resource` = `asset/<asset_id>/container/<container_name>`, both taken
from the signed `ControlContainerRequest`, and `target.tenant` = its
`organization_id`. It is not the device SPIFFE URI; that form belongs to the
device-signed profile (`conformance/reqsig`).

- **Cloud, at accept**, requires exactly this resource (cloud #919,
  `b462cda1`: `DeploymentServiceHandler.controlContainer` →
  `enforceRequestSignature`).
- **Device** requires it too, and that `asset_id` is its own UUID and
  `organization_id` its tenant (WendyOS #2478, `354abbdd`: `bindsThisDevice`).
  A request for another device is refused and consumed (`target`, reported
  `REJECTED_TARGET`), even when its resource and payload agree.

## Signing time (item 8)

Ruling 2026-10-24 03:25 under D9: the device takes an entry's trusted signing
time from its `tsr_response`, never from the signer's `iat`. This closes the
back-dated-`iat` hole once the `iat` window was dropped (item 3). No new
field.

- **The token.** Cloud takes it at accept over the fabric (`RelayTimestamp`,
  `certReq` true, with a nonce) for the exact `request_jws` bytes:
  `MessageImprint` = SHA-256(`request_jws`), which is cloud's
  `PostboxHashChain.requestHash` (cloud #919). It is not the request
  descriptor hash, nor a hash of `request_payload`. The token embeds only the
  TSA signer leaf (`id-kp-timeStamping`, critical). The device chains it to
  its pinned platform root at `genTime`, with the TSA Intermediate from its
  checkpoint (`x5c[1]`, `conformance/postbox`) as the candidate intermediate.
  The CMS checks are those of `conformance/postbox` verification step 4.
- **Missing or unverifiable token: hold.** The entry is not applied, not
  acked, not refused, and the high-water mark does not pass it, as for an
  unresolved issuer (item 1). Codes: `timestamp_missing`, `timestamp`,
  `imprint_mismatch`.
- **Operator chain at `genTime`.** The leaf and the Operator CA must chain to
  the tenant CA at `genTime`, so a back-dated `iat` cannot revive an expired
  operator cert (`operator_chain`, reported `REJECTED_SIGNATURE`).
- **`iat` ≤ `genTime` + 5 s** (the checkpoint skew; exactly 5 s passes). A
  later `iat` claims a time the TSA does not attest (`iat_after_timestamp`,
  reported `REJECTED_STALE`).
- **The platform cap counts from `genTime`** (item 3).

Device order: chain link, token (hold), issuer (hold), signature and
operator chain at `genTime`, target, `iat` against `genTime`, validity,
nonce.

## Vectors: `postbox-entry-vectors-v1.json`

`{version, contract, generation, organization_id, asset_id, device, aud,
org_ca_cert_der_b64, verify_at, org_ca_vectors[], operator_ca_cert_der_b64,
platform_root_cert_der_b64, tsa_intermediate_cert_der_b64,
max_iat_skew_seconds, platform_cap_seconds, default_tenant_cap_seconds,
validity_vectors[], timestamp_vectors[]}`. The device holds
`org_ca_cert_der_b64` (its tenant CA), pins `platform_root_cert_der_b64`, and
has `tsa_intermediate_cert_der_b64` from its checkpoint; `asset_id` is its
UUID. Each invalid or held vector names the one check that must fail in
`refusal`. The codes are vector labels, not wire values: a device may report
`timestamp_missing` as `timestamp`, and `operator_chain` as a signature
refusal.

`org_ca_vectors[]`: `request_b64` (a serialized `GetOrgCAsRequest`), then
`response_b64` (a serialized `GetOrgCAsResponse`) or `status`, checked at
`verify_at`:

| name | expect (`refusal`) |
|---|---|
| `operator-ca-valid` | valid: the Operator CA, issued by the tenant CA; cached |
| `other-tenant-ca-invalid` | `not_under_org_ca`: another tenant's Operator CA under the same platform root |
| `not-a-ca-invalid` | `not_a_ca`: a leaf issued directly by the tenant CA |
| `unknown-issuer-not-found-hold` | hold: `NOT_FOUND`; the entry is kept |

`validity_vectors[]` and `timestamp_vectors[]`: `signed_request_b64` (a
serialized `SignedRequest` for `ControlContainer`: `asset_id` = `asset_id`,
`container_name` `myapp`, operator leaf under `operator_ca_cert_der_b64`,
`iat` 1790000000, `expiry` `iat` + 30, `target.resource`
`asset/<asset_id>/container/myapp` unless the vector says otherwise) and
`stage`. Its `payload`, `payload_type` and `signature` are the entry's
`request_payload`, `payload_type` and `request_jws`. At `device`,
`tsr_response_b64` is the entry's `tsr_response` (absent when missing) and
`trusted_now` is the device's trusted time; `genTime` is `iat` + 2 s unless the
vector says otherwise. At `accept`, `tenant_cap_seconds` is the tenant's cap.

| name | stage | expect (`refusal`) |
|---|---|---|
| `control-container-valid` | device | valid: `valid_until` = `iat` + 60 days, trusted now `iat` + 10 s |
| `call-expiry-ignored-valid` | device | valid: the same entry 14 days later, long past the 30 s `expiry` |
| `past-valid-until-invalid` | device | `stale`: trusted now = `valid_until` |
| `valid-until-missing-invalid` | device | `validity_missing` |
| `above-platform-cap-device-invalid` | device | `above_platform_cap`: `valid_until` = `genTime` + 365 days + 1 s |
| `target-device-uri-invalid` | device | `target`: `target.resource` = the device SPIFFE URI |
| `target-other-device-invalid` | device | `target`: another device's `asset_id`, with a resource that matches it |
| `tenant-cap-boundary-accept-valid` | accept | valid: `valid_until − iat` = the 60-day tenant cap |
| `above-tenant-cap-accept-invalid` | accept | `above_tenant_cap`: 61 days against the 60-day cap |
| `above-platform-cap-accept-invalid` | accept | `above_platform_cap`: 365 days + 1 s, tenant cap at the platform cap |
| `target-device-uri-accept-invalid` | accept | `target`: `target.resource` = the device SPIFFE URI |

`timestamp_vectors[]` (all `device`):

| name | expect (`refusal`) |
|---|---|
| `timestamp-valid` | valid. Broken out in `breakdown`: `request_jws`, `request_hash_hex` (the imprint), `gen_time`, `target_resource`. |
| `timestamp-imprint-mismatch-hold` | hold (`imprint_mismatch`): a genuine token over SHA-256(`request_payload`) |
| `timestamp-unknown-tsa-hold` | hold (`timestamp`): right imprint, TSA signer under a foreign root |
| `timestamp-missing-hold` | hold (`timestamp_missing`): no `tsr_response` |
| `iat-skew-boundary-valid` | valid: `genTime` = `iat` − 5 s |
| `iat-after-timestamp-invalid` | `iat_after_timestamp`: `genTime` = `iat` − 6 s |
| `operator-cert-expired-at-gen-time-invalid` | `operator_chain`: the operator leaf expires at `iat` + 60 s, valid at `iat`, `genTime` = `iat` + 61 s |
| `platform-cap-from-gen-time-invalid` | `above_platform_cap`: `valid_until` = `iat` + 365 days − 4 s, `genTime` = `iat` − 5 s (within the cap from `iat`, 1 s over from `genTime`) |

Generation: `go run conformance/postbox-entry/generate.go conformance` (Go 1.27,
standard library). Every key is ML-DSA-65 from `SHA-256(<label>)` (the TSA
too; `conformance/postbox` covers an ML-DSA-87 TSA) and every certificate,
JWS and CMS signature is deterministic, so a rerun is byte-identical. **The
labels are test private keys.** `go run conformance/postbox-entry/verify.go
conformance` checks each vector's outcome and refusal code.

Cross-checked against WendyOS #2478 at `354abbdd`: its
`verifyTimestampToken`, `resolveIssuer` and `verifyPostboxRequest` give every
`device` vector its `expect`, and the same code except the two named above.
