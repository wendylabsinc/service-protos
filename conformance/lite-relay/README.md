# Lite relay conformance vector

WDY-3512, WDY-3919: `grant.bin` is a WLG3 grant signed with ECDSA P-256 over SHA-256. `cloud-key.bin` is the raw public key. `vector.json` records
all fields and hex encodings. The fixed private scalar is public test material,
never a deployment key, and so is the operator caller key whose SPKI DER is
`operator_spki_hex`. The attestation is the ASCII string `conformance.pki.attestation` (a stand-in
for pki-core's compact JWS; only its SHA-256 is in the record). The principal payload is the UTF-8 string
`conformance principal descriptor`.
The device principal is `device/00000000-0000-4000-8000-000000000004`: that UUID
is the device's one id, bound only through the device URI hash. WLG3 has no
asset UUID; the WLG2 vector it replaces carried one (`asset_id_hex`) and a
non-UUID device segment.

The generator uses the Go standard library. Run:

```sh
go run /path/to/service-protos/conformance/lite-relay/generate.go /path/to/service-protos/conformance/lite-relay
```

Cloud tests verify the Go signature and compare Swift's encoded unsigned body.
Firmware tests verify the same record with mbedTLS and reject truncated,
modified, expired and identity-mismatched records. ECDSA signatures produced
with randomized signing need not equal the fixture signature byte-for-byte.
