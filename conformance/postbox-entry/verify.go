//go:build ignore

// Reference check for postbox-entry-vectors-v1.json (WDY-4015 items 1 and 3;
// WDY-4374): applies the device's GetOrgCAs check and the instruction-validity
// rules of conformance/postbox-entry/README.md to every vector, opens the app
// secrets of the DeviceAssignment vectors, and exits non-zero when an outcome
// or refusal code disagrees with the vector.
// Run: go run conformance/postbox-entry/verify.go conformance
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	method      = "wendycloud.v2.DeploymentService/ControlContainer"
	payloadType = "wendycloud.v2.ControlContainerRequest"
)

// allFields decodes the length-delimited and varint fields of one protobuf
// message, every occurrence of each field in order.
func allFields(b []byte) (map[int][][]byte, error) {
	out := map[int][][]byte{}
	for len(b) > 0 {
		t, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("bad tag")
		}
		b = b[n:]
		f := int(t >> 3)
		switch t & 7 {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, errors.New("bad varint")
			}
			out[f] = append(out[f], binary.AppendUvarint(nil, v))
			b = b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return nil, errors.New("bad length")
			}
			out[f] = append(out[f], b[n:n+int(l)])
			b = b[n+int(l):]
		default:
			return nil, errors.New("unexpected wire type")
		}
	}
	return out, nil
}

// fields is allFields keeping the last occurrence of each field.
func fields(b []byte) (map[int][]byte, error) {
	all, err := allFields(b)
	out := map[int][]byte{}
	for f, vs := range all {
		out[f] = vs[len(vs)-1]
	}
	return out, err
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

// checkJWS verifies a postbox-relayed SignedRequest the way the device does:
// the x5c leaf chains through the cached Operator CA to the tenant CA at the
// signed iat, and the signature and claims hold. It returns the payload and
// the signed iat.
func checkJWS(orgCA, opCA *x509.Certificate, top, v map[string]any, op, ptype string, resource any) ([]byte, int64, error) {
	sr, err := fields(b64(v["signed_request_b64"]))
	if err != nil {
		return nil, 0, err
	}
	parts := strings.Split(string(sr[3]), ".")
	if len(parts) != 3 {
		return nil, 0, errors.New("not compact JWS")
	}
	var header, claims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(cb, &claims) != nil || header["alg"] != "ML-DSA-65" {
		return nil, 0, errors.New("bad JWS")
	}
	x5c, _ := header["x5c"].([]any)
	if len(x5c) != 1 {
		return nil, 0, errors.New("x5c must carry exactly the leaf")
	}
	leaf, err := x509.ParseCertificate(b64(x5c[0]))
	if err != nil {
		return nil, 0, err
	}
	pk, ok := leaf.PublicKey.(*mldsa.PublicKey)
	if !ok || mldsa.Verify(pk, []byte(parts[0]+"."+parts[1]), sig, nil) != nil {
		return nil, 0, errors.New("signature")
	}
	iat := num(claims["iat"])
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(orgCA)
	inter.AddCert(opCA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: time.Unix(iat, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, 0, fmt.Errorf("chain to the tenant CA at iat: %w", err)
	}
	target, _ := claims["target"].(map[string]any)
	if claims["operation"] != op || claims["aud"] != top["aud"] || target["tenant"] != top["organization_id"] || target["resource"] != resource || string(sr[2]) != ptype {
		return nil, 0, errors.New("claims")
	}
	body := sha256.Sum256(sr[1])
	if claims["body_sha256"] != base64.RawURLEncoding.EncodeToString(body[:]) {
		return nil, 0, refusal("body_sha256")
	}
	return sr[1], iat, nil
}

// checkEntry checks a relayed ControlContainer: the JWS, then valid_until
// (never the 30 s request expiry) against trusted now and the platform cap
// plus the device's tolerance. At stage "accept" it applies cloud's exact caps
// instead.
func checkEntry(orgCA, opCA *x509.Certificate, top, v map[string]any) error {
	payload, iat, err := checkJWS(orgCA, opCA, top, v, method, payloadType, top["device"])
	if err != nil {
		return err
	}
	// No iat window and no expiry here: the 30 s expiry bound the call to cloud.
	p, err := fields(payload)
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
	if v["stage"] == "accept" {
		if validUntil-iat > num(top["platform_cap_seconds"]) {
			return refusal("above_platform_cap")
		}
		if validUntil-iat > num(v["tenant_cap_seconds"]) {
			return refusal("above_tenant_cap")
		}
		return nil
	}
	if validUntil-iat > num(top["platform_cap_seconds"])+num(top["device_cap_tolerance_seconds"]) {
		return refusal("above_platform_cap")
	}
	if num(v["trusted_now"]) >= validUntil {
		return refusal("stale")
	}
	return nil
}

// checkSecrets is the device's handling of DeviceAssignment.secrets (15),
// after the statement's JWS: each secret's device wrap (scope kind 3) and
// sealed value must open and yield the vector's expected_secrets.
func checkSecrets(orgCA, opCA *x509.Certificate, top, v map[string]any) error {
	payload, _, err := checkJWS(orgCA, opCA, top, v, "wendycloud.v2.DeploymentService/AssignDevice", "wendycloud.v2.DeviceAssignment", top["assign_resource"])
	if err != nil {
		return err
	}
	a, err := allFields(payload)
	if err != nil {
		return err
	}
	org := top["organization_id"].(string)
	mat := top["secret_material"].(map[string]any)
	ikm, _ := hex.DecodeString(mat["device_kem_ikm_hex"].(string))
	devKEM, err := hpke.MLKEM768X25519().DeriveKeyPair(ikm)
	if err != nil {
		return err
	}
	got := []any{}
	for _, raw := range a[15] {
		ds, err := fields(raw)
		if err != nil {
			return err
		}
		sv, err := fields(ds[1]) // SealedSecret
		if err != nil {
			return err
		}
		w, err := fields(ds[2]) // KeyWrap
		if err != nil {
			return err
		}
		sc, err := fields(w[1]) // WrapScope
		if err != nil {
			return err
		}
		ver, _ := binary.Uvarint(sv[3])
		version := strconv.FormatUint(ver, 10)
		scope := string(sv[1]) + "/" + string(sv[2]) + "/" + version
		if string(sc[4]) != scope || !bytes.Equal(sc[3], sv[4]) || string(w[3]) != top["device"] || string(w[4]) != mat["device_key_id"] {
			return refusal("unwrap")
		}
		info := append(lp([]byte("wendy-registry-wrap-v1"), org), 3)
		info = append(lp(info, scope, string(sv[4])), 1)
		info = lp(info, string(w[3]), string(w[4]))
		r, err := hpke.NewRecipient(w[6], devKEM, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
		if err != nil {
			return refusal("unwrap")
		}
		key, err := r.Open(nil, w[7])
		if err != nil {
			return refusal("unwrap")
		}
		gcm := must(cipher.NewGCM(must(aes.NewCipher(key))))
		value, err := gcm.Open(nil, sv[5], sv[6], lp([]byte("wendy-secret-seal-v1"), org, string(sv[1]), string(sv[2]), version, string(sv[4])))
		if err != nil {
			return refusal("unwrap")
		}
		got = append(got, map[string]any{"name": string(sv[2]), "version": ver, "value": string(value)})
	}
	have, _ := json.Marshal(got)
	want, _ := json.Marshal(v["expected_secrets"])
	if !bytes.Equal(have, want) {
		return fmt.Errorf("secrets %s, want %s", have, want)
	}
	return nil
}

// checkReadback is an operator client's check of a SignedSecretVersion
// (registry.proto) before it wraps the key onward or places the value in a
// DeviceAssignment, in the order the contract lists.
func checkReadback(top, v map[string]any) error {
	ssv, err := allFields(b64(v["secret_version_b64"]))
	if err != nil || len(ssv[1]) != 1 {
		return errors.New("bad SignedSecretVersion")
	}
	sr, err := fields(ssv[1][0])
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
		return refusal("signature")
	}
	if string(sr[2]) != "wendycloud.v2.SetSecretRequest" || claims["operation"] != "wendycloud.v2.ArtifactRegistryService/SetSecret" {
		return errors.New("claims")
	}
	body := sha256.Sum256(sr[1])
	if claims["body_sha256"] != base64.RawURLEncoding.EncodeToString(body[:]) {
		return refusal("body_sha256")
	}
	// Chain through chain_der to the PINNED root at the signed iat.
	org := top["organization_id"].(string)
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(must(x509.ParseCertificate(b64(top["platform_root_cert_der_b64"]))))
	for _, der := range ssv[2] {
		inter.AddCert(must(x509.ParseCertificate(der)))
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: time.Unix(num(claims["iat"]), 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return refusal("chain")
	}
	// The caller's own tenant: its tenant CA, the leaf's tenant, the signed
	// target and payload organization.
	tenantCA := chains[0][len(chains[0])-2]
	target, _ := claims["target"].(map[string]any)
	p, err := fields(sr[1])
	if err != nil {
		return err
	}
	if len(leaf.URIs) != 1 || !bytes.Equal(tenantCA.Raw, b64(top["org_ca_cert_der_b64"])) ||
		!strings.HasPrefix(leaf.URIs[0].String(), "spiffe://wendy.sh/tenant/"+org+"/operator/") ||
		target["tenant"] != org || string(p[1]) != org {
		return refusal("tenant")
	}
	sv, err := fields(p[2])
	if err != nil {
		return err
	}
	ver, _ := binary.Uvarint(sv[3])
	version := strconv.FormatUint(ver, 10)
	if string(sv[1])+"/"+string(sv[2])+"/"+version != v["scope"] {
		return refusal("scope")
	}
	key, _ := hex.DecodeString(v["opened_key_hex"].(string))
	if string(sv[4]) != v["scope_key_id"] || string(sv[4]) != fmt.Sprintf("%x", sha256.Sum256(key)) {
		return refusal("key_id")
	}
	gcm := must(cipher.NewGCM(must(aes.NewCipher(key))))
	if _, err := gcm.Open(nil, sv[5], sv[6], lp([]byte("wendy-secret-seal-v1"), org, string(sv[1]), string(sv[2]), version, string(sv[4]))); err != nil {
		return refusal("ciphertext")
	}
	if !bytes.Equal(p[2], b64(v["expected_sealed_secret_b64"])) {
		return errors.New("placed SealedSecret differs from the signed one")
	}
	return nil
}

// lp: conformance/registry/README.md.
func lp(b []byte, fields ...string) []byte {
	for _, f := range fields {
		b = append(binary.BigEndian.AppendUint16(b, uint16(len(f))), f...)
	}
	return b
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
	for _, x := range top["secret_vectors"].([]any) {
		v := x.(map[string]any)
		err := checkSecrets(orgCA, opCA, top, v)
		got := "valid"
		if err != nil {
			got = "invalid"
		}
		report("secrets", v, got, err)
	}
	for _, x := range top["secret_readback_vectors"].([]any) {
		v := x.(map[string]any)
		err := checkReadback(top, v)
		got := "valid"
		if err != nil {
			got = "invalid"
		}
		report("secret-readback", v, got, err)
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
