//go:build ignore

// Generates conformance/postbox-entry/postbox-entry-vectors-v1.json (WDY-4015
// items 1 and 3): the device's check of a CA served by
// DevicePostboxService.GetOrgCAs, and the validity of a postbox-relayed
// instruction; and (WDY-4374) a DeviceAssignment carrying an app secret. Go
// standard library only (Go 1.27+: crypto/mldsa, crypto/hpke, ML-DSA in
// crypto/x509). Every key and signature is ML-DSA and deterministic. HPKE
// encapsulation is randomized: a rerun keeps the committed wraps while their
// inputs are unchanged, so it is byte-identical.
// Run: go run conformance/postbox-entry/generate.go conformance
package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	tenant      = "2558fd76-afc7-466e-9613-6b715296a526"
	otherTenant = "6a1f0c3e-8d2b-4f7a-9e5c-3b1d0a8f6e4c"
	deviceID    = "7c1d3e5f-2a4b-4c6d-8e9f-0a1b2c3d4e5f"
	aud         = "https://cloud.wendy.sh/broker"
	iat         = 1790000000
	day         = 86400

	platformCap      = 365 * day
	defaultTenantCap = 60 * day
	// The device tolerates this much over the platform cap (two clocks: the
	// client signs iat on its own clock); cloud's accept check stays exact.
	deviceCapTolerance = 5 * 60

	controlContainer = "wendycloud.v2.DeploymentService/ControlContainer"
	assignDevice     = "wendycloud.v2.DeploymentService/AssignDevice"
)

var (
	b64  = base64.StdEncoding.EncodeToString
	b64u = base64.RawURLEncoding.EncodeToString
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func seed(label string) []byte { s := sha256.Sum256([]byte(label)); return s[:] }

type detSigner struct{ *mldsa.PrivateKey }

func (s detSigner) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignDeterministic(msg, opts)
}

func key(label string) detSigner {
	return detSigner{must(mldsa.NewPrivateKey(mldsa.MLDSA65(), seed("wendy-postbox-entry-vector-"+label+"-2026-10")))}
}

type cert struct {
	der    []byte
	parsed *x509.Certificate
	signer crypto.Signer
}

func issue(serial int64, cn, uri string, k detSigner, parent *cert) *cert {
	t := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(1767225600, 0).UTC(), // 2026-01-01
		NotAfter:     time.Unix(2082758400, 0).UTC(), // 2036-01-01
	}
	if uri == "" {
		t.IsCA, t.BasicConstraintsValid = true, true
		t.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		t.KeyUsage = x509.KeyUsageDigitalSignature
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		t.URIs = []*url.URL{must(url.Parse(uri))}
	}
	p, s := t, crypto.Signer(k)
	if parent != nil {
		p, s = parent.parsed, parent.signer
	}
	der := must(x509.CreateCertificate(rand.Reader, t, p, k.Public(), s))
	return &cert{der, must(x509.ParseCertificate(der)), k}
}

// Minimal protobuf encoding (field order = field number, as protoc emits).
func tag(f, wt int) []byte { return binary.AppendUvarint(nil, uint64(f<<3|wt)) }
func pbBytes(f int, v []byte) []byte {
	return append(append(tag(f, 2), binary.AppendUvarint(nil, uint64(len(v)))...), v...)
}
func pbVarint(f int, v uint64) []byte { return append(tag(f, 0), binary.AppendUvarint(nil, v)...) }
func cat(parts ...[]byte) (out []byte) {
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// sign returns the compact JWS; encoding/json sorts keys and every value is
// ASCII or an integer, so the claims are RFC 8785 JCS.
func sign(k detSigner, leaf *cert, claims map[string]any) string {
	h := must(json.Marshal(map[string]any{"alg": "ML-DSA-65", "x5c": []string{b64(leaf.der)}}))
	input := b64u(h) + "." + b64u(must(json.Marshal(claims)))
	return input + "." + b64u(must(k.SignDeterministic([]byte(input), nil)))
}

func writeJSON(path string, v any) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		panic(err)
	}
}

func main() {
	out := os.Args[1]
	type vec = map[string]any

	root := issue(1, "Postbox Entry Vector Root", "", key("root"), nil)
	orgCA := issue(2, "Vector Tenant CA", "", key("tenant-ca"), root)
	operatorCA := issue(3, "Vector Operator Authority CA", "", key("operator-ca"), orgCA)
	otherOrgCA := issue(4, "Vector Tenant CA (other tenant)", "", key("other-tenant-ca"), root)
	otherOperatorCA := issue(5, "Vector Operator Authority CA (other tenant)", "", key("other-operator-ca"), otherOrgCA)
	opKey := key("operator")
	opURI := "spiffe://wendy.sh/tenant/" + tenant + "/operator/0e4f8a2c-6b1d-4c3e-9a7f-5d2b8e1c4a63"
	opLeaf := issue(10, "vector operator", opURI, opKey, operatorCA)
	device := "spiffe://wendy.sh/tenant/" + tenant + "/device/" + deviceID

	// ---------- item 1: GetOrgCAs ----------
	resp := func(cas ...*cert) string {
		var m []byte
		for _, c := range cas {
			m = append(m, pbBytes(1, c.der)...)
		}
		return b64(m)
	}
	unknown := must(x509.ParseCertificate(issue(6, "Vector CA cloud does not hold", "", key("unknown-ca"), orgCA).der)).RawSubject
	caVectors := []vec{
		{"name": "operator-ca-valid", "request_b64": b64(pbBytes(1, opLeaf.parsed.RawIssuer)), "response_b64": resp(operatorCA),
			"expect": "valid", "expected_cached_subject_cn": "Vector Operator Authority CA"},
		{"name": "other-tenant-ca-invalid", "request_b64": b64(pbBytes(1, opLeaf.parsed.RawIssuer)), "response_b64": resp(otherOperatorCA),
			"expect": "invalid", "refusal": "not_under_org_ca",
			"invalid_reason": "the served CA is another tenant's Operator Authority CA: valid, under the same platform root, but not issued by this device's tenant CA"},
		{"name": "not-a-ca-invalid", "request_b64": b64(pbBytes(1, opLeaf.parsed.RawIssuer)), "response_b64": resp(issue(7, "vector leaf", device, key("leaf-under-tenant-ca"), orgCA)),
			"expect": "invalid", "refusal": "not_a_ca",
			"invalid_reason": "the served certificate is issued directly by this tenant's CA and valid, but it is a leaf, not a CA"},
		{"name": "unknown-issuer-not-found-hold", "request_b64": b64(pbBytes(1, unknown)), "status": "NOT_FOUND",
			"expect": "hold", "invalid_reason": "cloud holds no CA with this subject: NOT_FOUND; the device holds the entry (not applied, not acked, not consumed) and asks again on its next pull"},
	}

	// ---------- item 3: instruction validity ----------
	// ControlContainerRequest: asset_id 1, organization_id 2, container_name 3,
	// action 4 (START = 1), valid_until 5 (Timestamp: seconds 1).
	payload := func(validUntil int64) []byte {
		m := cat(pbBytes(1, []byte(deviceID)), pbBytes(2, []byte(tenant)), pbBytes(3, []byte("myapp")), pbVarint(4, 1))
		if validUntil != 0 {
			m = append(m, pbBytes(5, pbVarint(1, uint64(validUntil)))...)
		}
		return m
	}
	request := func(validUntil int64, nonce string) string {
		p := payload(validUntil)
		body := sha256.Sum256(p)
		j := sign(opKey, opLeaf, map[string]any{
			"aud": aud, "body_sha256": b64u(body[:]), "correlation_id": "3c8e1f5a-9b2d-4e7c-a6f0-2d4b8e1a5c97",
			"expiry": iat + 30, "iat": iat, "nonce": nonce, "operation": controlContainer,
			"target": map[string]any{"tenant": tenant, "resource": device},
		})
		return b64(cat(pbBytes(1, p), pbBytes(2, []byte("wendycloud.v2.ControlContainerRequest")), pbBytes(3, []byte(j))))
	}
	twoMonths := request(iat+defaultTenantCap, "a1c5e9f3-2b6d-4a8e-9c1f-7d3b5e9a1c42")
	pastPlatform := request(iat+platformCap+1, "b7d3f1a9-5c2e-4b6d-8f0a-3e9c1d7b5f28")
	deviceCapEdge := request(iat+platformCap+deviceCapTolerance, "e3a7c1f5-9d2b-4e8a-b6c0-4f8d2a6e1b37")
	pastDeviceCap := request(iat+platformCap+deviceCapTolerance+1, "f9b5d3a7-1e4c-4a6f-8d2b-7c0e5a9f3d16")
	onDevice := func(name, sr string, now int64, expect, refusal, reason string) vec {
		v := vec{"name": name, "stage": "device", "signed_request_b64": sr, "trusted_now": now, "expect": expect}
		if refusal != "" {
			v["refusal"], v["invalid_reason"] = refusal, reason
		}
		return v
	}
	atAccept := func(name, sr string, tenantCap int64, expect, refusal, reason string) vec {
		v := vec{"name": name, "stage": "accept", "signed_request_b64": sr, "tenant_cap_seconds": tenantCap, "expect": expect}
		if refusal != "" {
			v["refusal"], v["invalid_reason"] = refusal, reason
		}
		return v
	}
	validityVectors := []vec{
		onDevice("control-container-valid", twoMonths, iat+10, "valid", "", ""),
		onDevice("call-expiry-ignored-valid", twoMonths, iat+14*day, "valid", "", ""),
		onDevice("past-valid-until-invalid", twoMonths, iat+defaultTenantCap, "invalid", "stale",
			"trusted now equals valid_until (iat + 60 days); valid_until is strict, like expiry"),
		onDevice("valid-until-missing-invalid", request(0, "c2e6a0b4-8d3f-4c7a-9e1b-5f2d6a0c4e83"), iat+10, "invalid", "validity_missing",
			"ControlContainerRequest without valid_until"),
		onDevice("platform-cap-tolerance-boundary-device-valid", deviceCapEdge, iat+10, "valid", "", ""),
		onDevice("above-platform-cap-device-invalid", pastDeviceCap, iat+10, "invalid", "above_platform_cap",
			"valid_until = iat + 365 days + 5 min + 1 s: above the platform cap plus the device's 5-minute tolerance, which the device checks too (cloud should have refused it at accept)"),
		atAccept("tenant-cap-boundary-accept-valid", twoMonths, defaultTenantCap, "valid", "", ""),
		atAccept("above-tenant-cap-accept-invalid", request(iat+defaultTenantCap+day, "d8f4b2c6-0a5e-4d9b-8c3f-6e1a7b2d9f54"), defaultTenantCap, "invalid", "above_tenant_cap",
			"valid_until = iat + 61 days; the tenant cap is the 60-day default"),
		atAccept("above-platform-cap-accept-invalid", pastPlatform, platformCap, "invalid", "above_platform_cap",
			"valid_until = iat + 365 days + 1 s; the tenant cap is set to the platform cap, which it can never exceed"),
	}

	// ---------- WDY-4374: an app secret in a DeviceAssignment ----------
	path := filepath.Join(out, "postbox-entry", "postbox-entry-vectors-v1.json")
	prev := previous(path)
	kem := hpke.MLKEM768X25519()
	kdf, aead := hpke.HKDFSHA256(), hpke.AES256GCM()
	devIKM := seed("wendy-postbox-entry-vector-device-kem-2026-11")
	devKEM := must(kem.DeriveKeyPair(devIKM))
	devKeyID := hexID(devKEM.PublicKey().Bytes())
	// wrap seals key to the device under the registry wrap info, reusing the
	// committed encapsulation for the same info and key.
	wrap := func(name string, scopeField int, scopeKind byte, scopeID string, key []byte) []byte {
		keyID := hexID(key)
		info := wrapInfo(tenant, scopeKind, scopeID, keyID, 1, device, devKeyID)
		var enc, ct []byte
		if old, _ := prev["secret_material"].(map[string]any); old != nil && old[name+"_info_hex"] == hex.EncodeToString(info) && old[name+"_key_hex"] == hex.EncodeToString(key) {
			enc, ct = unhex(old[name+"_enc_hex"]), unhex(old[name+"_ciphertext_hex"])
		} else {
			e, sender, err := hpke.NewSender(devKEM.PublicKey(), kdf, aead, info)
			if err != nil {
				panic(err)
			}
			enc, ct = e, must(sender.Seal(nil, key))
		}
		material[name+"_info_hex"], material[name+"_key_hex"] = hex.EncodeToString(info), hex.EncodeToString(key)
		material[name+"_enc_hex"], material[name+"_ciphertext_hex"] = hex.EncodeToString(enc), hex.EncodeToString(ct)
		// KeyWrap: scope 1 (WrapScope), recipient_kind 2 (DEVICE), recipient 3,
		// recipient_key_id 4, suite 5 (MLKEM768_X25519), enc 6, ciphertext 7.
		// WrapScope fields in number order: the oneof field and key_id 3.
		sc := cat(pbBytes(scopeField, []byte(scopeID)), pbBytes(3, []byte(keyID)))
		if scopeField > 3 {
			sc = cat(pbBytes(3, []byte(keyID)), pbBytes(scopeField, []byte(scopeID)))
		}
		return cat(pbBytes(1, sc), pbVarint(2, 1), pbBytes(3, []byte(device)), pbBytes(4, []byte(devKeyID)), pbVarint(5, 1), pbBytes(6, enc), pbBytes(7, ct))
	}
	const (
		appID        = "5d3b1f9e-7a2c-4e8d-b6f0-1c9a3e7d5b24"
		deploymentID = "4b2d8f6e-1c3a-4e5b-9d7f-2a6c8e0b1d3f"
		secretName   = "DB_PASSWORD"
		secretValue  = "correct horse battery staple"
	)
	deploymentKey := seed("wendy-postbox-entry-vector-deployment-key-2026-11")
	secretKey := seed("wendy-postbox-entry-vector-secret-key-2026-11")
	secretKeyID := hexID(secretKey)
	secretScope := appID + "/" + secretName + "/1"
	sealNonce := seed("wendy-postbox-entry-vector-secret-nonce-2026-11")[:12]
	sealed := must(cipher.NewGCM(must(aes.NewCipher(secretKey)))).Seal(nil, sealNonce, []byte(secretValue), secretAAD(tenant, appID, secretName, 1, secretKeyID))
	// SealedSecret: app_id 1, name 2, version 3, secret_key_id 4, nonce 5,
	// ciphertext 6. DeviceSecret: value 1, device_wrap 2.
	sealedSecret := func(ct []byte) []byte {
		return cat(pbBytes(1, []byte(appID)), pbBytes(2, []byte(secretName)), pbVarint(3, 1), pbBytes(4, []byte(secretKeyID)), pbBytes(5, sealNonce), pbBytes(6, ct))
	}
	secretWrap := wrap("secret_wrap", 4, 3, secretScope, secretKey)
	depWrap := wrap("deployment_wrap", 1, 1, deploymentID, deploymentKey)
	md := sha256.Sum256([]byte("vector manifest"))
	// DeviceAssignment fields 1-12 and 15 (registry.proto).
	assignment := func(ct []byte) []byte {
		return cat(pbBytes(1, []byte(tenant)), pbBytes(2, []byte(deploymentID)), pbBytes(3, []byte(device)), pbBytes(4, []byte(appID)),
			pbBytes(5, []byte("9e1f3a5c-7b2d-4c6e-8f0a-1b3d5e7f9a2c")), pbBytes(6, []byte("sha256:"+hex.EncodeToString(md[:]))),
			pbBytes(7, []byte(hexID(deploymentKey))), pbVarint(8, 1), pbBytes(9, depWrap), pbBytes(10, pbVarint(1, iat+defaultTenantCap)),
			pbBytes(11, []byte(`{"LOG_LEVEL":"info"}`)), pbVarint(12, 1),
			pbBytes(15, cat(pbBytes(1, sealedSecret(ct)), pbBytes(2, secretWrap))))
	}
	assignResource := "org/" + tenant + "/deployment/" + deploymentID
	signedAssign := assignment(sealed)
	body := sha256.Sum256(signedAssign)
	assignJWS := sign(opKey, opLeaf, map[string]any{
		"aud": aud, "body_sha256": b64u(body[:]), "correlation_id": "6f2a8c4e-1b7d-4a3f-9e5c-8d0b2f6a4c19",
		"expiry": iat + 30, "iat": iat, "nonce": "7a3e9c1f-5b2d-4f8a-a6c4-2e0d8b6f4a71", "operation": assignDevice,
		"target": map[string]any{"tenant": tenant, "resource": assignResource},
	})
	tampered := bytes.Clone(sealed)
	tampered[0] ^= 1
	assignSR := func(payload []byte) string {
		return b64(cat(pbBytes(1, payload), pbBytes(2, []byte("wendycloud.v2.DeviceAssignment")), pbBytes(3, []byte(assignJWS))))
	}
	secretVectors := []vec{
		{"name": "assign-with-secret-valid", "stage": "device", "signed_request_b64": assignSR(signedAssign), "expect": "valid",
			"expected_secrets": []vec{{"name": secretName, "version": 1, "value": secretValue}}},
		{"name": "secret-ciphertext-tampered-invalid", "stage": "device", "signed_request_b64": assignSR(assignment(tampered)), "expect": "invalid",
			"refusal": "body_sha256", "invalid_reason": "one bit of DeviceAssignment.secrets[0].value.ciphertext flipped after the operator signed: the payload no longer matches the signed body_sha256"},
	}
	material["device_kem_ikm_hex"] = hex.EncodeToString(devIKM)
	material["device_key_id"] = devKeyID

	// ---------- WDY-4374: signed readback of a secret version ----------
	// SignedSecretVersion: set_request 1 (SignedRequest: payload 1,
	// payload_type 2, signature 3), chain_der 2. SetSecretRequest:
	// organization_id 1, value 2 (SealedSecret).
	setResource := "org/" + tenant + "/app/" + appID // placeholder: the readback check ignores resource
	setSecret := func(k detSigner, leaf *cert, value []byte, nonce string) []byte {
		p := cat(pbBytes(1, []byte(tenant)), pbBytes(2, value))
		body := sha256.Sum256(p)
		j := sign(k, leaf, map[string]any{
			"aud": aud, "body_sha256": b64u(body[:]), "correlation_id": "2d6f0a4c-8e1b-4c5d-9a3f-7b1e5c9d3a60",
			"expiry": iat + 30, "iat": iat, "nonce": nonce, "operation": "wendycloud.v2.ArtifactRegistryService/SetSecret",
			"target": map[string]any{"tenant": tenant, "resource": setResource},
		})
		return cat(pbBytes(1, p), pbBytes(2, []byte("wendycloud.v2.SetSecretRequest")), pbBytes(3, []byte(j)))
	}
	ssv := func(sr []byte, chain ...*cert) string {
		m := pbBytes(1, sr)
		for _, c := range chain {
			m = append(m, pbBytes(2, c.der)...)
		}
		return b64(m)
	}
	leftKey := key("operator-left")
	leftLeaf := issue(11, "vector operator (left the tenant)", "spiffe://wendy.sh/tenant/"+tenant+"/operator/9b3d5f7a-1c2e-4a6b-8d0f-3e5a7c9b1d24", leftKey, operatorCA)
	otherOpKey := key("other-operator")
	otherOpLeaf := issue(12, "vector operator (other tenant)", "spiffe://wendy.sh/tenant/"+otherTenant+"/operator/5e7a9c1b-3d4f-4b8a-a2c6-1f3b5d7e9a08", otherOpKey, otherOperatorCA)
	// Cloud's own chain, under a root the client does not pin, claiming the
	// real operator's identity.
	cloudTenantCA := issue(21, "Vector Tenant CA", "", key("cloud-tenant-ca"), issue(20, "Cloud-made root", "", key("cloud-root"), nil))
	cloudOpCA := issue(22, "Vector Operator Authority CA", "", key("cloud-operator-ca"), cloudTenantCA)
	cloudKey := key("cloud-planted")
	cloudLeaf := issue(23, "vector operator", opURI, cloudKey, cloudOpCA)
	value := sealedSecret(sealed)
	plantKey := seed("wendy-postbox-entry-vector-planted-secret-key-2026-11")
	otherName := cat(pbBytes(1, []byte(appID)), pbBytes(2, []byte("API_TOKEN")), pbVarint(3, 1), pbBytes(4, []byte(secretKeyID)), pbBytes(5, sealNonce), pbBytes(6, sealed))
	tamperedSet := setSecret(opKey, opLeaf, value, "8c4e2a6f-0b1d-4e3a-9f5c-6d2b8a0e4c17")
	tamperedSet[bytes.Index(tamperedSet, sealed)] ^= 1
	readback := func(name, sv, openedKey, expect, refusal, reason string) vec {
		v := vec{"name": name, "secret_version_b64": sv, "scope": secretScope, "scope_key_id": secretKeyID, "opened_key_hex": openedKey, "expect": expect}
		if refusal != "" {
			v["refusal"], v["invalid_reason"] = refusal, reason
		} else {
			v["expected_sealed_secret_b64"] = b64(value)
		}
		return v
	}
	key1 := hex.EncodeToString(secretKey)
	readbackVectors := []vec{
		readback("secret-readback-valid", ssv(setSecret(opKey, opLeaf, value, "8c4e2a6f-0b1d-4e3a-9f5c-6d2b8a0e4c17"), operatorCA, orgCA), key1, "valid", "", ""),
		readback("secret-readback-unpinned-root-invalid", ssv(setSecret(cloudKey, cloudLeaf, value, "1a5c9e3f-7b2d-4f6a-8c0e-4d8b2f6a0c35"), cloudOpCA, cloudTenantCA), key1, "invalid", "chain",
			"Cloud planted the version: a leaf with the real operator's identity, under a tenant CA Cloud made and a root the client does not pin"),
		readback("secret-readback-other-tenant-invalid", ssv(setSecret(otherOpKey, otherOpLeaf, value, "3e7b1d5a-9c2f-4a8e-b6d0-5f1a3c7e9b42"), otherOperatorCA, otherOrgCA), key1, "invalid", "tenant",
			"the signer is a real operator under the pinned root, but of another tenant"),
		readback("secret-readback-setter-left-valid", ssv(setSecret(leftKey, leftLeaf, value, "5f9d3b7e-1a4c-4e2b-8f6a-7c3e9a1d5b80"), operatorCA, orgCA), key1, "valid", "", ""),
		readback("secret-readback-wrong-name-invalid", ssv(setSecret(opKey, opLeaf, otherName, "7b1f5d9a-3c6e-4a0b-9d2f-8e4a0c6b2d91"), operatorCA, orgCA), key1, "invalid", "scope",
			"a valid signed request for API_TOKEN served for the requested DB_PASSWORD scope"),
		readback("secret-readback-key-mismatch-invalid", ssv(setSecret(opKey, opLeaf, value, "9d3b7f1c-5e8a-4c2d-a0f4-1b6e2c8d4f03"), operatorCA, orgCA), hex.EncodeToString(plantKey), "invalid", "key_id",
			"the signed request is real, but the caller's wrap opens to a key Cloud chose: its SHA-256 is not the signed secret_key_id"),
		readback("secret-readback-ciphertext-tampered-invalid", ssv(tamperedSet, operatorCA, orgCA), key1, "invalid", "body_sha256",
			"one bit of the signed SealedSecret.ciphertext flipped after signing"),
	}

	writeJSON(path, map[string]any{
		"version":  "postbox-entry-vectors-v1",
		"contract": "conformance/postbox-entry/README.md; wendycloud/v2/postbox.proto (GetOrgCAs); valid_until on the postbox-relayed requests",
		"generation": map[string]any{
			"tool":          "go run conformance/postbox-entry/generate.go conformance (Go 1.27, standard library only)",
			"deterministic": "ML-DSA-65 keys from seed = SHA-256(label); certificates and JWS signed deterministically; a rerun is byte-identical",
			"warning":       "TEST KEYS ONLY: the seed labels in the generator ARE the private keys.",
		},
		"organization_id":              tenant,
		"device":                       device,
		"aud":                          aud,
		"org_ca_cert_der_b64":          b64(orgCA.der),
		"verify_at":                    iat,
		"org_ca_vectors":               caVectors,
		"operator_ca_cert_der_b64":     b64(operatorCA.der),
		"platform_cap_seconds":         platformCap,
		"device_cap_tolerance_seconds": deviceCapTolerance,
		"default_tenant_cap_seconds":   defaultTenantCap,
		"validity_vectors":             validityVectors,
		"assign_resource":              assignResource,
		"secret_material":              material,
		"secret_vectors":               secretVectors,
		"platform_root_cert_der_b64":   b64(root.der),
		"secret_readback_vectors":      readbackVectors,
	})
}

var material = map[string]any{}

func hexID(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func unhex(v any) []byte { s, _ := v.(string); return must(hex.DecodeString(s)) }

func previous(path string) map[string]any {
	var m map[string]any
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

// lp, wrapInfo: conformance/registry/README.md (key wrap); secretAAD: the
// secret seal row there.
func lp(b []byte, fields ...string) []byte {
	for _, f := range fields {
		b = append(binary.BigEndian.AppendUint16(b, uint16(len(f))), f...)
	}
	return b
}

func wrapInfo(org string, scopeKind byte, scopeID, keyID string, recipientKind byte, recipient, recipientKeyID string) []byte {
	b := append(lp([]byte("wendy-registry-wrap-v1"), org), scopeKind)
	b = append(lp(b, scopeID, keyID), recipientKind)
	return lp(b, recipient, recipientKeyID)
}

func secretAAD(org, appID, name string, version int, secretKeyID string) []byte {
	return lp([]byte("wendy-secret-seal-v1"), org, appID, name, strconv.Itoa(version), secretKeyID)
}
