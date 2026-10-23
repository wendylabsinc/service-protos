//go:build ignore

// Reference check for postbox-entry-vectors-v1.json (WDY-4015 items 1 and 3):
// applies the device's GetOrgCAs check and the instruction-validity rules of
// conformance/postbox-entry/README.md to every vector and exits non-zero when
// an outcome or refusal code disagrees with the vector.
// Run: go run conformance/postbox-entry/verify.go conformance
package main

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	method      = "wendycloud.v2.DeploymentService/ControlContainer"
	payloadType = "wendycloud.v2.ControlContainerRequest"
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

func b64(v any) []byte { b, _ := base64.StdEncoding.DecodeString(v.(string)); return b }

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

// checkEntry verifies a postbox-relayed ControlContainer the way the device
// does: the x5c leaf chains through the cached Operator CA to the tenant CA at
// the signed iat, the signature and claims hold, and valid_until (never the
// 30 s request expiry) is checked against trusted now and the platform cap. At
// stage "accept" it applies cloud's caps instead.
func checkEntry(orgCA, opCA *x509.Certificate, top, v map[string]any) error {
	sr, err := fields(b64(v["signed_request_b64"]))
	if err != nil {
		return err
	}
	parts := strings.Split(string(sr[3]), ".")
	if len(parts) != 3 {
		return errors.New("not compact JWS")
	}
	var header, claims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(cb, &claims) != nil || header["alg"] != "ML-DSA-65" {
		return errors.New("bad JWS")
	}
	x5c, _ := header["x5c"].([]any)
	if len(x5c) != 1 {
		return errors.New("x5c must carry exactly the leaf")
	}
	leaf, err := x509.ParseCertificate(b64(x5c[0]))
	if err != nil {
		return err
	}
	pk, ok := leaf.PublicKey.(*mldsa.PublicKey)
	if !ok || mldsa.Verify(pk, []byte(parts[0]+"."+parts[1]), sig, nil) != nil {
		return errors.New("signature")
	}
	iat := num(claims["iat"])
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(orgCA)
	inter.AddCert(opCA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: time.Unix(iat, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("chain to the tenant CA at iat: %w", err)
	}
	body := sha256.Sum256(sr[1])
	target, _ := claims["target"].(map[string]any)
	if claims["operation"] != method || claims["aud"] != top["aud"] || claims["body_sha256"] != base64.RawURLEncoding.EncodeToString(body[:]) ||
		target["tenant"] != top["organization_id"] || target["resource"] != top["device"] || string(sr[2]) != payloadType {
		return errors.New("claims")
	}
	// No iat window and no expiry here: the 30 s expiry bound the call to cloud.
	p, err := fields(sr[1])
	if err != nil {
		return err
	}
	if p[5] == nil {
		return refusal("validity_missing")
	}
	ts, err := fields(p[5])
	if err != nil {
		return err
	}
	u, _ := binary.Uvarint(ts[1])
	validUntil := int64(u)
	if validUntil-iat > num(top["platform_cap_seconds"]) {
		return refusal("above_platform_cap")
	}
	if v["stage"] == "accept" {
		if validUntil-iat > num(v["tenant_cap_seconds"]) {
			return refusal("above_tenant_cap")
		}
		return nil
	}
	if num(v["trusted_now"]) >= validUntil {
		return refusal("stale")
	}
	return nil
}

func main() {
	var top map[string]any
	if err := json.Unmarshal(must(os.ReadFile(filepath.Join(os.Args[1], "postbox-entry", "postbox-entry-vectors-v1.json"))), &top); err != nil {
		panic(err)
	}
	orgCA := must(x509.ParseCertificate(b64(top["org_ca_cert_der_b64"])))
	opCA := must(x509.ParseCertificate(b64(top["operator_ca_cert_der_b64"])))
	bad := 0
	report := func(section string, v map[string]any, got string, err error) {
		want, code := v["expect"].(string), v["refusal"]
		ok := got == want && (code == nil || err != nil && err.Error() == code)
		if !ok {
			bad++
		}
		fmt.Printf("%-4s %-18s %-36s expect=%-7s got=%-7s %v\n", map[bool]string{true: "ok", false: "FAIL"}[ok], section, v["name"], want, got, err)
	}
	for _, x := range top["org_ca_vectors"].([]any) {
		v := x.(map[string]any)
		got, err := checkOrgCA(orgCA, num(top["verify_at"]), v)
		if err != nil {
			got = "invalid"
		}
		report("org-ca", v, got, err)
	}
	for _, x := range top["validity_vectors"].([]any) {
		v := x.(map[string]any)
		err := checkEntry(orgCA, opCA, top, v)
		got := "valid"
		if err != nil {
			got = "invalid"
		}
		report("validity/"+v["stage"].(string), v, got, err)
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
