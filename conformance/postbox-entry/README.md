# Postbox entry: operator CA and instruction validity (WDY-4015 items 1, 3)

How a device resolves the CA behind an operator-signed postbox entry, and how
long an entry stays valid. Rulings: sem 2026-10-23 22:27 (both), corrected
22:30 (operator CA). `PostboxEntry` is unchanged.

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
   the entry's signed `iat`, as before.
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
  dashboard, never above the platform cap. Both are measured as
  `valid_until − iat` (the signed `iat`). The operator client defaults
  `valid_until` to `iat` + the tenant cap.
- **Cloud, at accept** (on top of the generic gate, whose 30 s `expiry`
  stays): refuse when `valid_until` is absent (`validity_missing`; enforced
  once the CLI and console set it, see the contract ledger), above the
  platform cap (`above_platform_cap`) or above the tenant cap
  (`above_tenant_cap`). A cap equal to `valid_until − iat` passes.
- **Cloud, queue.** A queued entry is kept until the device is deleted.
- **Device.** Checks, after the chain and signature: `valid_until` present
  (`validity_missing`), `valid_until − iat` within the platform cap
  (`above_platform_cap`, so a cloud that skipped the accept check gains
  nothing), and trusted now `< valid_until` (`stale`; strict, like `expiry`).
  Trusted now is the TSA/checkpoint time when present, else the device clock.
- **The device does not check the request `expiry` or the ±60 s `iat` window
  on a postbox entry.** Its former 10-minute `expiry − iat` cap is gone.
- A `stale` entry is refused and consumed (reported `REJECTED_STALE`); a held
  entry (item 1) is not.

## Vectors: `postbox-entry-vectors-v1.json`

`{version, contract, generation, organization_id, device, aud,
org_ca_cert_der_b64, verify_at, org_ca_vectors[], operator_ca_cert_der_b64,
platform_cap_seconds, default_tenant_cap_seconds, validity_vectors[]}`. The
device holds `org_ca_cert_der_b64` (its tenant CA). Each invalid vector names
the one check that must fail in `refusal`; the codes are vector labels, not
wire values.

`org_ca_vectors[]`: `request_b64` (a serialized `GetOrgCAsRequest`), then
`response_b64` (a serialized `GetOrgCAsResponse`) or `status`, checked at
`verify_at`:

| name | expect (`refusal`) |
|---|---|
| `operator-ca-valid` | valid: the Operator CA, issued by the tenant CA; cached |
| `other-tenant-ca-invalid` | `not_under_org_ca`: another tenant's Operator CA under the same platform root |
| `not-a-ca-invalid` | `not_a_ca`: a leaf issued directly by the tenant CA |
| `unknown-issuer-not-found-hold` | hold: `NOT_FOUND`; the entry is kept |

`validity_vectors[]`: `signed_request_b64` (a serialized `SignedRequest` for
`ControlContainer`, operator leaf under `operator_ca_cert_der_b64`, `iat`
1790000000, `expiry` `iat` + 30) and `stage`. At `device`, `trusted_now` is the
device's trusted time; at `accept`, `tenant_cap_seconds` is the tenant's cap.

| name | stage | expect (`refusal`) |
|---|---|---|
| `control-container-valid` | device | valid: `valid_until` = `iat` + 60 days, trusted now `iat` + 10 s |
| `call-expiry-ignored-valid` | device | valid: the same entry 14 days later, long past the 30 s `expiry` |
| `past-valid-until-invalid` | device | `stale`: trusted now = `valid_until` |
| `valid-until-missing-invalid` | device | `validity_missing` |
| `above-platform-cap-device-invalid` | device | `above_platform_cap`: `valid_until` = `iat` + 365 days + 1 s |
| `tenant-cap-boundary-accept-valid` | accept | valid: `valid_until − iat` = the 60-day tenant cap |
| `above-tenant-cap-accept-invalid` | accept | `above_tenant_cap`: 61 days against the 60-day cap |
| `above-platform-cap-accept-invalid` | accept | `above_platform_cap`: 365 days + 1 s, tenant cap at the platform cap |

Generation: `go run conformance/postbox-entry/generate.go conformance` (Go 1.27,
standard library). Every key is ML-DSA-65 from `SHA-256(<label>)` and every
signature is deterministic, so a rerun is byte-identical. **The labels are test
private keys.** `go run conformance/postbox-entry/verify.go conformance` checks
each vector's outcome and refusal code.
