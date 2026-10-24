//go:build ignore

// Generates conformance/postbox-entry/postbox-entry-vectors-v1.json (WDY-4015
// items 1, 3, 7 and 8): the device's check of a CA served by
// DevicePostboxService.GetOrgCAs, the validity and target of a
// postbox-relayed instruction, and the entry's RFC 3161 timestamp token. Go
// standard library only (Go 1.27+: crypto/mldsa, ML-DSA in crypto/x509). Every
// key and signature is ML-DSA and deterministic, so a rerun is byte-identical.
// Run: go run conformance/postbox-entry/generate.go conformance
package main

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	tenant      = "2558fd76-afc7-466e-9613-6b715296a526"
	otherTenant = "6a1f0c3e-8d2b-4f7a-9e5c-3b1d0a8f6e4c"
	deviceID    = "7c1d3e5f-2a4b-4c6d-8e9f-0a1b2c3d4e5f"
	aud         = "https://cloud.wendy.sh/broker"
	iat         = 1790000000
	genTime     = iat + 2 // cloud takes the token at accept, just after the operator signed
	day         = 86400
	iatSkew     = 5 // iat may run this far past genTime (the checkpoint skew)

	platformCap      = 365 * day
	defaultTenantCap = 60 * day

	controlContainer = "wendycloud.v2.DeploymentService/ControlContainer"
	container        = "myapp"
)

var (
	b64  = base64.StdEncoding.EncodeToString
	b64u = base64.RawURLEncoding.EncodeToString

	oidTimeStamping  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidEKU           = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidTSAPolicy     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65441, 2, 1} // pki-core config.OIDTSAPolicyWendy
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidMLDSA65       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
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
	signer detSigner
}

// issue mints a CA (uri == "") or an operator-shaped leaf; tweak adjusts the
// template last (the TSA signer, the expired operator leaf).
func issue(serial int64, cn, uri string, k detSigner, parent *cert, tweak ...func(*x509.Certificate)) *cert {
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
	for _, f := range tweak {
		f(t)
	}
	p, s := t, crypto.Signer(k)
	if parent != nil {
		p, s = parent.parsed, parent.signer
	}
	der := must(x509.CreateCertificate(rand.Reader, t, p, k.Public(), s))
	return &cert{der, must(x509.ParseCertificate(der)), k}
}

// tsaLeaf makes a leaf the way pki-core mints its TSA signer: one critical
// id-kp-timeStamping EKU.
func tsaLeaf(t *x509.Certificate) {
	t.IsCA, t.BasicConstraintsValid = false, false
	t.KeyUsage = x509.KeyUsageDigitalSignature
	t.ExtraExtensions = []pkix.Extension{{Id: oidEKU, Critical: true, Value: must(asn1.Marshal([]asn1.ObjectIdentifier{oidTimeStamping}))}}
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
func sign(leaf *cert, claims map[string]any) string {
	h := must(json.Marshal(map[string]any{"alg": "ML-DSA-65", "x5c": []string{b64(leaf.der)}}))
	input := b64u(h) + "." + b64u(must(json.Marshal(claims)))
	return input + "." + b64u(must(leaf.signer.SignDeterministic([]byte(input), nil)))
}

// ---------- timestamp token (pki-core Engine.IssueTimestamp via RelayTimestamp) ----------

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint struct {
		HashAlgorithm algID
		HashedMessage []byte
	}
	SerialNumber *big.Int
	GenTime      time.Time `asn1:"generalized"`
	Nonce        *big.Int  // cloud's TimeStampReq always carries one; pki-core echoes it
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version int
	SID     struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}
	DigestAlgorithm    algID
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algID
	Signature          []byte
}

type signedData struct {
	Version          int
	DigestAlgorithms []algID `asn1:"set"`
	EncapContentInfo struct {
		EContentType asn1.ObjectIdentifier
		EContent     []byte `asn1:"explicit,tag:0,optional"`
	}
	Certificates asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos  []signerInfo  `asn1:"set"`
}

func wrap(tag byte, b []byte) []byte {
	n := len(b)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, b...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, b...)
	case n < 0x10000:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, b...)
	}
	return append([]byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}, b...)
}

func attr(t asn1.ObjectIdentifier, v any) []byte {
	return must(asn1.Marshal(attribute{t, asn1.RawValue{FullBytes: wrap(0x31, must(asn1.Marshal(v)))}}))
}

// timestamp returns a granted TimeStampResp over SHA-256(stamped), signed by
// tsa with only the signer certificate embedded (cloud sends certReq=true).
func timestamp(tsa *cert, stamped []byte, gen, serial int64) []byte {
	imprint := sha256.Sum256(stamped)
	var tst tstInfo
	tst.Version, tst.Policy = 1, oidTSAPolicy
	tst.MessageImprint.HashAlgorithm = algID{Algorithm: oidSHA256}
	tst.MessageImprint.HashedMessage = imprint[:]
	tst.SerialNumber, tst.GenTime = big.NewInt(serial), time.Unix(gen, 0).UTC()
	tst.Nonce = big.NewInt(0x5eed0000 + serial)
	tstDER := must(asn1.Marshal(tst))

	md := sha256.Sum256(tstDER)
	ch := sha256.Sum256(tsa.der)
	ess := struct {
		Certs []struct {
			HashAlgorithm algID
			CertHash      []byte
		}
	}{Certs: []struct {
		HashAlgorithm algID
		CertHash      []byte
	}{{algID{Algorithm: oidSHA256}, ch[:]}}}
	attrs := [][]byte{
		attr(oidContentType, oidTSTInfo),
		attr(oidMessageDigest, md[:]),
		attr(oidSigningTime, time.Unix(gen, 0).UTC()),
		attr(oidSigningCertV2, ess),
	}
	sort.Slice(attrs, func(i, j int) bool { return bytes.Compare(attrs[i], attrs[j]) < 0 })
	set := bytes.Join(attrs, nil)

	var si signerInfo
	si.Version = 1
	si.SID.Issuer = asn1.RawValue{FullBytes: tsa.parsed.RawIssuer}
	si.SID.SerialNumber = tsa.parsed.SerialNumber
	si.DigestAlgorithm = algID{Algorithm: oidSHA256}
	si.SignedAttrs = asn1.RawValue{FullBytes: wrap(0xA0, set)}
	si.SignatureAlgorithm = algID{Algorithm: oidMLDSA65}
	si.Signature = must(tsa.signer.SignDeterministic(wrap(0x31, set), nil))

	var sd signedData
	sd.Version = 3
	sd.DigestAlgorithms = []algID{{Algorithm: oidSHA256}}
	sd.EncapContentInfo.EContentType, sd.EncapContentInfo.EContent = oidTSTInfo, tstDER
	sd.Certificates = asn1.RawValue{FullBytes: wrap(0xA0, tsa.der)}
	sd.SignerInfos = []signerInfo{si}

	ci := must(asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: must(asn1.Marshal(sd))}}))
	return must(asn1.Marshal(struct {
		Status         struct{ Status int }
		TimeStampToken asn1.RawValue
	}{TimeStampToken: asn1.RawValue{FullBytes: ci}}))
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
	tsaCA := issue(8, "Vector Platform TSA Intermediate", "", key("tsa-ca"), root)
	tsaSigner := issue(9, "Vector Platform TSA Signer", "", key("tsa-signer"), tsaCA, tsaLeaf)
	foreignRoot := issue(1, "Foreign TSA Vector Root", "", key("foreign-root"), nil)
	foreignTSA := issue(2, "Foreign TSA Signer", "", key("foreign-tsa-signer"), foreignRoot, tsaLeaf)
	opURI := "spiffe://wendy.sh/tenant/" + tenant + "/operator/0e4f8a2c-6b1d-4c3e-9a7f-5d2b8e1c4a63"
	opLeaf := issue(10, "vector operator", opURI, key("operator"), operatorCA)
	const expiredAt = iat + 60
	expiredLeaf := issue(11, "vector operator (short-lived)", opURI, key("operator-short-lived"), operatorCA,
		func(t *x509.Certificate) {
			t.NotBefore, t.NotAfter = time.Unix(iat-3600, 0).UTC(), time.Unix(expiredAt, 0).UTC()
		})
	device := "spiffe://wendy.sh/tenant/" + tenant + "/device/" + deviceID
	resource := "asset/" + deviceID + "/container/" + container

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

	// ---------- items 3, 7, 8: the relayed ControlContainer and its entry ----------
	// ControlContainerRequest: asset_id 1, organization_id 2, container_name 3,
	// action 4 (START = 1), valid_until 5 (Timestamp: seconds 1).
	type req struct {
		validUntil int64
		nonce      string
		asset      string // asset_id; this device when empty
		resource   string // target.resource; the asset/<asset_id>/container/<name> form when empty
		leaf       *cert  // the operator leaf; opLeaf when nil
	}
	type signed struct {
		b64     string // the serialized SignedRequest
		jws     []byte // request_jws: what the entry's token stamps
		payload []byte
	}
	request := func(r req) signed {
		if r.asset == "" {
			r.asset = deviceID
		}
		p := cat(pbBytes(1, []byte(r.asset)), pbBytes(2, []byte(tenant)), pbBytes(3, []byte(container)), pbVarint(4, 1))
		if r.validUntil != 0 {
			p = append(p, pbBytes(5, pbVarint(1, uint64(r.validUntil)))...)
		}
		if r.resource == "" {
			r.resource = "asset/" + r.asset + "/container/" + container
		}
		if r.leaf == nil {
			r.leaf = opLeaf
		}
		body := sha256.Sum256(p)
		j := sign(r.leaf, map[string]any{
			"aud": aud, "body_sha256": b64u(body[:]), "correlation_id": "3c8e1f5a-9b2d-4e7c-a6f0-2d4b8e1a5c97",
			"expiry": iat + 30, "iat": iat, "nonce": r.nonce, "operation": controlContainer,
			"target": map[string]any{"tenant": tenant, "resource": r.resource},
		})
		return signed{b64(cat(pbBytes(1, p), pbBytes(2, []byte("wendycloud.v2.ControlContainerRequest")), pbBytes(3, []byte(j)))), []byte(j), p}
	}
	serial := int64(1000)
	stamp := func(tsa *cert, stamped []byte, gen int64) []byte {
		serial++
		return timestamp(tsa, stamped, gen, serial)
	}

	// onDevice is an entry the device pulled: the SignedRequest's three fields
	// are PostboxEntry.request_payload / payload_type / request_jws, and token
	// is PostboxEntry.tsr_response (nil = absent).
	onDevice := func(name string, sr signed, token []byte, now int64, expect, refusal, reason string) vec {
		v := vec{"name": name, "stage": "device", "signed_request_b64": sr.b64, "trusted_now": now, "expect": expect}
		if token != nil {
			v["tsr_response_b64"] = b64(token)
		}
		if refusal != "" {
			v["refusal"], v["invalid_reason"] = refusal, reason
		}
		return v
	}
	atAccept := func(name string, sr signed, tenantCap int64, expect, refusal, reason string) vec {
		v := vec{"name": name, "stage": "accept", "signed_request_b64": sr.b64, "tenant_cap_seconds": tenantCap, "expect": expect}
		if refusal != "" {
			v["refusal"], v["invalid_reason"] = refusal, reason
		}
		return v
	}

	twoMonths := request(req{validUntil: iat + defaultTenantCap, nonce: "a1c5e9f3-2b6d-4a8e-9c1f-7d3b5e9a1c42"})
	twoMonthsTSR := stamp(tsaSigner, twoMonths.jws, genTime)
	pastPlatform := request(req{validUntil: iat + platformCap + 1, nonce: "b7d3f1a9-5c2e-4b6d-8f0a-3e9c1d7b5f28"})
	pastPlatformGen := request(req{validUntil: genTime + platformCap + 1, nonce: "e4a8c2f6-1b5d-4e9a-8c3f-7a2e6b0d4c19"})
	spiffeTarget := request(req{validUntil: iat + defaultTenantCap, nonce: "f0b6d2a8-4c1e-4f7b-9a5d-8e3c1b7f0a26", resource: device})
	otherDevice := request(req{validUntil: iat + defaultTenantCap, nonce: "5c9a1e7d-0f3b-4a6c-8d2e-1b7f4a9c3e60", asset: "3f8e2d1c-9b7a-4e6f-8d5c-4b3a2f1e0d9c"})
	noValidity := request(req{nonce: "c2e6a0b4-8d3f-4c7a-9e1b-5f2d6a0c4e83"})

	validityVectors := []vec{
		onDevice("control-container-valid", twoMonths, twoMonthsTSR, iat+10, "valid", "", ""),
		onDevice("call-expiry-ignored-valid", twoMonths, twoMonthsTSR, iat+14*day, "valid", "", ""),
		onDevice("past-valid-until-invalid", twoMonths, twoMonthsTSR, iat+defaultTenantCap, "invalid", "stale",
			"trusted now equals valid_until (iat + 60 days); valid_until is strict, like expiry"),
		onDevice("valid-until-missing-invalid", noValidity, stamp(tsaSigner, noValidity.jws, genTime), iat+10, "invalid", "validity_missing",
			"ControlContainerRequest without valid_until"),
		onDevice("above-platform-cap-device-invalid", pastPlatformGen, stamp(tsaSigner, pastPlatformGen.jws, genTime), iat+10, "invalid", "above_platform_cap",
			"valid_until = genTime + 365 days + 1 s: above the platform cap, which the device checks too (cloud should have refused it at accept)"),
		onDevice("target-device-uri-invalid", spiffeTarget, stamp(tsaSigner, spiffeTarget.jws, genTime), iat+10, "invalid", "target",
			"target.resource is the device SPIFFE URI; a ControlContainer is bound to asset/<asset_id>/container/<container_name>"),
		onDevice("target-other-device-invalid", otherDevice, stamp(tsaSigner, otherDevice.jws, genTime), iat+10, "invalid", "target",
			"a consistent ControlContainer for another device of the same tenant (asset_id and target.resource both name it), relayed to this device"),
		atAccept("tenant-cap-boundary-accept-valid", twoMonths, defaultTenantCap, "valid", "", ""),
		atAccept("above-tenant-cap-accept-invalid", request(req{validUntil: iat + defaultTenantCap + day, nonce: "d8f4b2c6-0a5e-4d9b-8c3f-6e1a7b2d9f54"}), defaultTenantCap, "invalid", "above_tenant_cap",
			"valid_until = iat + 61 days; the tenant cap is the 60-day default"),
		atAccept("above-platform-cap-accept-invalid", pastPlatform, platformCap, "invalid", "above_platform_cap",
			"valid_until = iat + 365 days + 1 s; the tenant cap is set to the platform cap, which it can never exceed"),
		atAccept("target-device-uri-accept-invalid", spiffeTarget, defaultTenantCap, "invalid", "target",
			"target.resource is the device SPIFFE URI, not the asset/<asset_id>/container/<container_name> cloud binds"),
	}

	// ---------- item 8: the entry's timestamp token ----------
	expired := request(req{validUntil: iat + defaultTenantCap, nonce: "9d5b1f7c-3e8a-4b2d-a6c0-4f9e2b8d1a73", leaf: expiredLeaf})
	capFromGen := request(req{validUntil: iat + platformCap - iatSkew + 1, nonce: "2a7e3c9f-6d1b-4f8e-b5a2-0c4d8f1e6b37"})
	imprint := sha256.Sum256(twoMonths.jws)
	tsVectors := []vec{
		onDevice("timestamp-valid", twoMonths, twoMonthsTSR, iat+10, "valid", "", ""),
		onDevice("timestamp-imprint-mismatch-hold", twoMonths, stamp(tsaSigner, twoMonths.payload, genTime), iat+10, "hold", "imprint_mismatch",
			"a genuine token over SHA-256 of request_payload, not of request_jws: held, not consumed"),
		onDevice("timestamp-unknown-tsa-hold", twoMonths, stamp(foreignTSA, twoMonths.jws, genTime), iat+10, "hold", "timestamp",
			"right imprint, signed by a timestamping leaf under a root the device does not pin: held, not consumed"),
		onDevice("timestamp-missing-hold", twoMonths, nil, iat+10, "hold", "timestamp_missing",
			"no tsr_response: held, not consumed"),
		onDevice("iat-skew-boundary-valid", twoMonths, stamp(tsaSigner, twoMonths.jws, iat-iatSkew), iat+10, "valid", "", ""),
		onDevice("iat-after-timestamp-invalid", twoMonths, stamp(tsaSigner, twoMonths.jws, iat-iatSkew-1), iat+10, "invalid", "iat_after_timestamp",
			"genTime = iat - 6 s: the signer claims a time more than 5 s after the TSA's"),
		onDevice("operator-cert-expired-at-gen-time-invalid", expired, stamp(tsaSigner, expired.jws, expiredAt+1), iat+100, "invalid", "operator_chain",
			"the operator leaf expired at iat + 60 s: valid at the signed iat, expired at genTime (iat + 61 s); the chain is checked at genTime"),
		onDevice("platform-cap-from-gen-time-invalid", capFromGen, stamp(tsaSigner, capFromGen.jws, iat-iatSkew), iat+10, "invalid", "above_platform_cap",
			"valid_until = iat + 365 days - 4 s with genTime = iat - 5 s: within the cap from iat, 1 s above it from genTime, which the device counts from"),
	}
	tsVectors[0]["breakdown"] = map[string]any{
		"request_jws":      string(twoMonths.jws),
		"request_hash_hex": hex.EncodeToString(imprint[:]),
		"gen_time":         genTime,
		"target_resource":  resource,
	}

	writeJSON(filepath.Join(out, "postbox-entry", "postbox-entry-vectors-v1.json"), map[string]any{
		"version":  "postbox-entry-vectors-v1",
		"contract": "conformance/postbox-entry/README.md; wendycloud/v2/postbox.proto (GetOrgCAs, PostboxEntry.tsr_response); valid_until on the postbox-relayed requests",
		"generation": map[string]any{
			"tool":          "go run conformance/postbox-entry/generate.go conformance (Go 1.27, standard library only)",
			"deterministic": "ML-DSA-65 keys from seed = SHA-256(label); certificates, JWS and CMS signed deterministically; a rerun is byte-identical",
			"warning":       "TEST KEYS ONLY: the seed labels in the generator ARE the private keys.",
		},
		"organization_id":               tenant,
		"asset_id":                      deviceID,
		"device":                        device,
		"aud":                           aud,
		"org_ca_cert_der_b64":           b64(orgCA.der),
		"verify_at":                     iat,
		"org_ca_vectors":                caVectors,
		"operator_ca_cert_der_b64":      b64(operatorCA.der),
		"platform_root_cert_der_b64":    b64(root.der),
		"tsa_intermediate_cert_der_b64": b64(tsaCA.der),
		"max_iat_skew_seconds":          iatSkew,
		"platform_cap_seconds":          platformCap,
		"default_tenant_cap_seconds":    defaultTenantCap,
		"validity_vectors":              validityVectors,
		"timestamp_vectors":             tsVectors,
	})
}
