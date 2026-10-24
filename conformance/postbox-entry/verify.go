//go:build ignore

// Reference check for postbox-entry-vectors-v1.json (WDY-4015 items 1, 3, 7
// and 8): applies the device's GetOrgCAs check and the entry rules of
// conformance/postbox-entry/README.md (timestamp token, signature, target,
// signing time, instruction validity) to every vector and exits non-zero when
// an outcome or refusal code disagrees with the vector.
// Run: go run conformance/postbox-entry/verify.go conformance
package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	method      = "wendycloud.v2.DeploymentService/ControlContainer"
	payloadType = "wendycloud.v2.ControlContainerRequest"
)

var (
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidMLDSA65       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

// fields decodes the length-delimited and varint fields of one protobuf message.
func fields(b []byte) (map[int][]byte, error) {
	out := map[int][]byte{}
	for len(b) > 0 {
		t, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("bad tag")
		}
		b = b[n:]
		switch t & 7 {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, errors.New("bad varint")
			}
			out[int(t>>3)] = binary.AppendUvarint(nil, v)
			b = b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return nil, errors.New("bad length")
			}
			out[int(t>>3)] = b[n : n+int(l)]
			b = b[n+int(l):]
		default:
			return nil, errors.New("unexpected wire type")
		}
	}
	return out, nil
}

func num(v any) int64 { f, _ := v.(float64); return int64(f) }

func b64(v any) []byte { s, _ := v.(string); b, _ := base64.StdEncoding.DecodeString(s); return b }

// refusal is a failed check, named by the code its vector carries.
type refusal string

func (r refusal) Error() string { return string(r) }

// checkOrgCA is the device's check of each CA GetOrgCAs returns: issued
// directly by the tenant CA the device already holds and valid now. "hold"
// means the device keeps the entry and asks again on its next pull.
func checkOrgCA(orgCA *x509.Certificate, at int64, v map[string]any) (string, error) {
	if v["status"] == "NOT_FOUND" {
		return "hold", nil
	}
	resp, err := fields(b64(v["response_b64"]))
	if err != nil {
		return "", err
	}
	ca, err := x509.ParseCertificate(resp[1])
	if err != nil {
		return "", err
	}
	roots := x509.NewCertPool()
	roots.AddCert(orgCA)
	if !ca.IsCA {
		return "", refusal("not_a_ca")
	}
	if _, err := ca.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Unix(at, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return "", refusal("not_under_org_ca")
	}
	if want, ok := v["expected_cached_subject_cn"]; ok && ca.Subject.CommonName != want {
		return "", fmt.Errorf("cached %q, want %q", ca.Subject.CommonName, want)
	}
	return "valid", nil
}

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo struct {
		EContentType asn1.ObjectIdentifier
		EContent     []byte `asn1:"explicit,tag:0,optional"`
	}
	Certificates asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos  []struct {
		Version int
		SID     struct {
			Issuer       asn1.RawValue
			SerialNumber *big.Int
		}
		DigestAlgorithm    algID
		SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
		SignatureAlgorithm algID
		Signature          []byte
	} `asn1:"set"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint struct {
		HashAlgorithm algID
		HashedMessage []byte
	}
	SerialNumber *big.Int
	GenTime      time.Time     `asn1:"generalized"`
	Rest         asn1.RawValue `asn1:"optional"`
}

// verifyToken checks the entry's RFC 3161 TimeStampResp over SHA-256 of the
// exact request_jws bytes and returns its genTime, the entry's trusted signing
// time. The token embeds only the TSA signer leaf; the TSA Intermediate comes
// from the device's checkpoint (x5c[1]) and the chain ends at the pinned
// platform root. Every failure holds the entry.
func verifyToken(der, requestJWS []byte, tsaCA *x509.Certificate, roots *x509.CertPool) (time.Time, error) {
	if len(der) == 0 {
		return time.Time{}, refusal("timestamp_missing")
	}
	var resp struct {
		Status struct {
			Status int
			Rest   asn1.RawValue `asn1:"optional"`
		}
		TimeStampToken asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(der, &resp); err != nil || resp.Status.Status != 0 || len(resp.TimeStampToken.FullBytes) == 0 {
		return time.Time{}, refusal("timestamp")
	}
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	var sd signedData
	if _, err := asn1.Unmarshal(resp.TimeStampToken.FullBytes, &ci); err != nil || !ci.ContentType.Equal(oidSignedData) {
		return time.Time{}, refusal("timestamp")
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(sd.SignerInfos) != 1 ||
		!sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) || len(sd.EncapContentInfo.EContent) == 0 {
		return time.Time{}, refusal("timestamp")
	}
	si := sd.SignerInfos[0]
	// The signer is the embedded certificate the SignerInfo names.
	var signer *x509.Certificate
	inter := x509.NewCertPool()
	inter.AddCert(tsaCA)
	for rest := sd.Certificates.Bytes; len(rest) > 0; {
		var raw asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return time.Time{}, refusal("timestamp")
		}
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return time.Time{}, refusal("timestamp")
		}
		if bytes.Equal(c.RawIssuer, si.SID.Issuer.FullBytes) && si.SID.SerialNumber != nil && c.SerialNumber.Cmp(si.SID.SerialNumber) == 0 {
			if signer != nil {
				return time.Time{}, refusal("timestamp")
			}
			signer = c
		} else {
			inter.AddCert(c)
		}
	}
	if signer == nil {
		return time.Time{}, refusal("timestamp")
	}
	pk, ok := signer.PublicKey.(*mldsa.PublicKey)
	if !ok || !si.SignatureAlgorithm.Algorithm.Equal(oidMLDSA65) || !si.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
		return time.Time{}, refusal("timestamp")
	}
	var ct asn1.ObjectIdentifier
	var md []byte
	for rest := si.SignedAttrs.Bytes; len(rest) > 0; {
		var at struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue `asn1:"set"`
		}
		var err error
		if rest, err = asn1.Unmarshal(rest, &at); err != nil {
			return time.Time{}, refusal("timestamp")
		}
		switch {
		case at.Type.Equal(oidContentType):
			asn1.Unmarshal(at.Value.Bytes, &ct)
		case at.Type.Equal(oidMessageDigest):
			asn1.Unmarshal(at.Value.Bytes, &md)
		}
	}
	sum := sha256.Sum256(sd.EncapContentInfo.EContent)
	if !ct.Equal(oidTSTInfo) || !bytes.Equal(md, sum[:]) || len(si.SignedAttrs.FullBytes) == 0 {
		return time.Time{}, refusal("timestamp")
	}
	// ML-DSA over the signed attributes re-tagged as a SET (RFC 5652 §5.4).
	if mldsa.Verify(pk, append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...), si.Signature, nil) != nil {
		return time.Time{}, refusal("timestamp")
	}
	var tst tstInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &tst); err != nil {
		return time.Time{}, refusal("timestamp")
	}
	if _, err := signer.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: tst.GenTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}); err != nil {
		return time.Time{}, refusal("timestamp")
	}
	h := sha256.Sum256(requestJWS)
	if !tst.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) || !bytes.Equal(tst.MessageImprint.HashedMessage, h[:]) {
		return time.Time{}, refusal("imprint_mismatch")
	}
	return tst.GenTime, nil
}

type anchors struct {
	orgCA, opCA, tsaCA *x509.Certificate
	platform           *x509.CertPool
}

// checkEntry verifies a postbox-relayed ControlContainer. At stage "device"
// it is the device's check of a pulled entry, in order: the timestamp token
// (a failure holds the entry), the operator signature with the x5c leaf
// chained through the cached Operator CA to the tenant CA at genTime, the
// claims and target, iat against genTime, then valid_until (never the 30 s
// request expiry) against the platform cap from genTime and trusted now. At
// stage "accept" it is cloud's check: chain at the signed iat, claims and
// target, and both caps from iat.
func checkEntry(a anchors, top, v map[string]any) (string, error) {
	sr, err := fields(b64(v["signed_request_b64"]))
	if err != nil {
		return "", err
	}
	device := v["stage"] == "device"
	var genTime time.Time
	if device {
		if genTime, err = verifyToken(b64(v["tsr_response_b64"]), sr[3], a.tsaCA, a.platform); err != nil {
			return "hold", err
		}
	}

	parts := strings.Split(string(sr[3]), ".")
	if len(parts) != 3 {
		return "", errors.New("not compact JWS")
	}
	var header, claims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(cb, &claims) != nil || header["alg"] != "ML-DSA-65" {
		return "", errors.New("bad JWS")
	}
	x5c, _ := header["x5c"].([]any)
	if len(x5c) != 1 {
		return "", errors.New("x5c must carry exactly the leaf")
	}
	leaf, err := x509.ParseCertificate(b64(x5c[0]))
	if err != nil {
		return "", err
	}
	pk, ok := leaf.PublicKey.(*mldsa.PublicKey)
	if !ok || mldsa.Verify(pk, []byte(parts[0]+"."+parts[1]), sig, nil) != nil {
		return "invalid", refusal("signature")
	}
	iat := time.Unix(num(claims["iat"]), 0)
	signedAt := iat
	if device {
		signedAt = genTime
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(a.orgCA)
	inter.AddCert(a.opCA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: signedAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return "invalid", refusal("operator_chain")
	}
	body := sha256.Sum256(sr[1])
	if claims["operation"] != method || claims["aud"] != top["aud"] || claims["body_sha256"] != base64.RawURLEncoding.EncodeToString(body[:]) || string(sr[2]) != payloadType {
		return "", errors.New("claims")
	}
	p, err := fields(sr[1])
	if err != nil {
		return "", err
	}
	// Target: asset/<asset_id>/container/<container_name> from the signed
	// payload, the tenant on both sides, and (device) asset_id = this device.
	target, _ := claims["target"].(map[string]any)
	if target["resource"] != "asset/"+string(p[1])+"/container/"+string(p[3]) || target["tenant"] != string(p[2]) ||
		string(p[2]) != top["organization_id"] || device && string(p[1]) != top["asset_id"] {
		return "invalid", refusal("target")
	}
	// No iat window and no expiry here: the 30 s expiry bound the call to cloud.
	if device && iat.After(genTime.Add(time.Duration(num(top["max_iat_skew_seconds"]))*time.Second)) {
		return "invalid", refusal("iat_after_timestamp")
	}
	if p[5] == nil {
		return "invalid", refusal("validity_missing")
	}
	ts, err := fields(p[5])
	if err != nil {
		return "", err
	}
	u, _ := binary.Uvarint(ts[1])
	lifetime := int64(u) - signedAt.Unix()
	if lifetime > num(top["platform_cap_seconds"]) {
		return "invalid", refusal("above_platform_cap")
	}
	if !device {
		if lifetime > num(v["tenant_cap_seconds"]) {
			return "invalid", refusal("above_tenant_cap")
		}
		return "valid", nil
	}
	if num(v["trusted_now"]) >= int64(u) {
		return "invalid", refusal("stale")
	}
	return "valid", nil
}

func main() {
	var top map[string]any
	if err := json.Unmarshal(must(os.ReadFile(filepath.Join(os.Args[1], "postbox-entry", "postbox-entry-vectors-v1.json"))), &top); err != nil {
		panic(err)
	}
	cert := func(k string) *x509.Certificate { return must(x509.ParseCertificate(b64(top[k]))) }
	a := anchors{orgCA: cert("org_ca_cert_der_b64"), opCA: cert("operator_ca_cert_der_b64"), tsaCA: cert("tsa_intermediate_cert_der_b64"), platform: x509.NewCertPool()}
	a.platform.AddCert(cert("platform_root_cert_der_b64"))
	bad := 0
	report := func(section string, v map[string]any, got string, err error) {
		want, code := v["expect"].(string), v["refusal"]
		ok := got == want && (code == nil && (err == nil || got == "hold") || code != nil && err != nil && err.Error() == code)
		if !ok {
			bad++
		}
		fmt.Printf("%-4s %-18s %-42s expect=%-7s got=%-7s %v\n", map[bool]string{true: "ok", false: "FAIL"}[ok], section, v["name"], want, got, err)
	}
	for _, x := range top["org_ca_vectors"].([]any) {
		v := x.(map[string]any)
		got, err := checkOrgCA(a.orgCA, num(top["verify_at"]), v)
		if err != nil {
			got = "invalid"
		}
		report("org-ca", v, got, err)
	}
	for _, section := range []string{"validity_vectors", "timestamp_vectors"} {
		for _, x := range top[section].([]any) {
			v := x.(map[string]any)
			got, err := checkEntry(a, top, v)
			report(strings.TrimSuffix(section, "_vectors")+"/"+v["stage"].(string), v, got, err)
		}
	}
	if bad > 0 {
		fmt.Printf("%d vector(s) disagree\n", bad)
		os.Exit(1)
	}
	fmt.Println("all vectors agree with expect and refusal")
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
