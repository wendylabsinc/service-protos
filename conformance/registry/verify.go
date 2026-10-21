//go:build ignore

// Reference check for the vectors generate.go writes (WDY-3958): verifies every
// device-signer, RecipientKey, head-ack read and registry vector against the rules in
// conformance/reqsig/README.md and conformance/registry/README.md and exits
// non-zero on any disagreement with its `expect`.
// Run: go run conformance/registry/verify.go conformance
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hkdf"
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
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var payloadTypes = map[string]string{
	"wendycloud.v2.DevicePostboxService/AckHead":                    "wendycloud.v2.PostboxHeadAck",
	"wendycloud.v2.KeyDirectoryService/RegisterDeviceEncryptionKey": "wendycloud.v2.RegisterEncryptionKeyRequest",
}

// fields decodes the length-delimited and varint fields of one protobuf message.
func fields(b []byte) (map[int][][]byte, error) {
	out := map[int][][]byte{}
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
			out[int(t>>3)] = append(out[int(t>>3)], binary.AppendUvarint(nil, v))
			b = b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return nil, errors.New("bad length")
			}
			out[int(t>>3)] = append(out[int(t>>3)], b[n:n+int(l)])
			b = b[n+int(l):]
		default:
			return nil, errors.New("unexpected wire type")
		}
	}
	return out, nil
}

func one(f map[int][][]byte, n int) []byte {
	if len(f[n]) == 0 {
		return nil
	}
	return f[n][0]
}

type jws struct {
	header map[string]any
	claims map[string]any
	leaf   *x509.Certificate
	der    []byte
}

// parseAndVerify checks the JWS shape and the signature against the x5c leaf.
func parseAndVerify(compact string) (*jws, error) {
	p := strings.Split(compact, ".")
	if len(p) != 3 {
		return nil, errors.New("not compact JWS")
	}
	var j jws
	hb, err := base64.RawURLEncoding.DecodeString(p[0])
	if err != nil || json.Unmarshal(hb, &j.header) != nil {
		return nil, errors.New("bad header")
	}
	if _, ok := j.header["crit"]; ok {
		return nil, errors.New("crit")
	}
	if _, ok := j.header["kid"]; ok {
		return nil, errors.New("kid refused: device-signed requests are x5c only")
	}
	x5c, _ := j.header["x5c"].([]any)
	if len(x5c) != 1 {
		return nil, errors.New("x5c must carry exactly the leaf")
	}
	j.der, err = base64.StdEncoding.DecodeString(x5c[0].(string))
	if err != nil {
		return nil, err
	}
	if j.leaf, err = x509.ParseCertificate(j.der); err != nil {
		return nil, err
	}
	cb, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil || json.Unmarshal(cb, &j.claims) != nil {
		return nil, errors.New("bad claims")
	}
	sig, err := base64.RawURLEncoding.DecodeString(p[2])
	if err != nil {
		return nil, err
	}
	input := []byte(p[0] + "." + p[1])
	switch alg := j.header["alg"]; alg {
	case "ML-DSA-65":
		pk, ok := j.leaf.PublicKey.(*mldsa.PublicKey)
		if !ok || mldsa.Verify(pk, input, sig, nil) != nil {
			return nil, errors.New("ML-DSA-65 signature")
		}
	case "ES256":
		pk, ok := j.leaf.PublicKey.(*ecdsa.PublicKey)
		h := sha256.Sum256(input)
		if !ok || len(sig) != 64 || !ecdsa.Verify(pk, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, errors.New("ES256 signature")
		}
	default:
		return nil, fmt.Errorf("alg %v", alg)
	}
	return &j, nil
}

func chain(leaf *x509.Certificate, root []byte, intermediates [][]byte, at int64) error {
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	rc, err := x509.ParseCertificate(root)
	if err != nil {
		return err
	}
	roots.AddCert(rc)
	for _, d := range intermediates {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return err
		}
		inter.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: time.Unix(at, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

func leafURI(c *x509.Certificate) (uri, tenant string) {
	for _, u := range c.URIs {
		if s := u.String(); strings.HasPrefix(s, "spiffe://wendy.sh/tenant/") {
			return s, strings.Split(strings.TrimPrefix(s, "spiffe://wendy.sh/tenant/"), "/")[0]
		}
	}
	return "", ""
}

func num(v any) int64 { f, _ := v.(float64); return int64(f) }

// checkClaims applies the claim rules shared by the server and the RecipientKey client.
func checkClaims(j *jws, method, aud string, payload []byte, now int64, checkTime bool) error {
	c := j.claims
	if c["operation"] != method || c["aud"] != aud {
		return errors.New("operation/aud")
	}
	body := sha256.Sum256(payload)
	if c["body_sha256"] != base64.RawURLEncoding.EncodeToString(body[:]) {
		return errors.New("body_sha256")
	}
	if checkTime {
		if d := now - num(c["iat"]); d > 60 || d < -60 {
			return errors.New("iat skew")
		}
		if now >= num(c["expiry"]) {
			return errors.New("expired")
		}
	}
	uri, tenant := leafURI(j.leaf)
	t, _ := c["target"].(map[string]any)
	if t == nil || t["tenant"] != tenant || t["resource"] != uri {
		return errors.New("target is not the signing device")
	}
	if id, _ := c["correlation_id"].(string); id == "" || len(id) > 64 {
		return errors.New("correlation_id")
	}
	return nil
}

func verifyDevice(top map[string]any, v map[string]any, nonces map[string]bool) error {
	sr, _ := base64.StdEncoding.DecodeString(v["signed_request_b64"].(string))
	peer, _ := base64.StdEncoding.DecodeString(v["mtls_peer_cert_der_b64"].(string))
	f, err := fields(sr)
	if err != nil {
		return err
	}
	method := v["method"].(string)
	j, err := parseAndVerify(string(one(f, 3)))
	if err != nil {
		return err
	}
	if !bytes.Equal(j.der, peer) {
		return errors.New("x5c leaf is not the mTLS peer")
	}
	// Tier gate: the algorithm is fixed by the device's recorded tier.
	want := map[string]string{"A/B": "ML-DSA-65", "C": "ES256"}[v["device_tier"].(string)]
	if j.header["alg"] != want {
		return fmt.Errorf("tier %v requires %s", v["device_tier"], want)
	}
	root, _ := base64.StdEncoding.DecodeString(top["root_cert_der_b64"].(string))
	ca, _ := base64.StdEncoding.DecodeString(top["device_ca_cert_der_b64"].(string))
	at := num(v["verify_at"])
	if err := chain(j.leaf, root, [][]byte{ca}, at); err != nil {
		return err
	}
	if _, tenant := leafURI(j.leaf); tenant != v["expected_tenant"] {
		return errors.New("tenant")
	}
	if err := checkClaims(j, method, top["aud"].(string), one(f, 1), at, true); err != nil {
		return err
	}
	if string(one(f, 2)) != payloadTypes[method] {
		return errors.New("payload_type")
	}
	n := j.claims["nonce"].(string)
	if nonces[n] {
		return errors.New("nonce replayed")
	}
	nonces[n] = true
	return nil
}

// verifyStored checks a device-signed request that cloud stored and served
// back (RecipientKey.registration, GetLastHeadAckResponse.ack) against the
// pinned root, the expected principal and tenant, and the expected method.
// It returns the signed payload.
func verifyStored(root []byte, aud string, sr []byte, chainDER [][]byte, principal, org, method string, at int64) ([]byte, error) {
	reg, err := fields(sr)
	if err != nil {
		return nil, err
	}
	j, err := parseAndVerify(string(one(reg, 3)))
	if err != nil {
		return nil, err
	}
	if err := chain(j.leaf, root, chainDER, at); err != nil {
		return nil, fmt.Errorf("chain to pinned root: %w", err)
	}
	uri, tenant := leafURI(j.leaf)
	if uri != principal || tenant != org {
		return nil, errors.New("leaf identity is not the principal")
	}
	if string(one(reg, 2)) != payloadTypes[method] {
		return nil, errors.New("payload_type")
	}
	if err := checkClaims(j, method, aud, one(reg, 1), at, false); err != nil {
		return nil, err
	}
	return one(reg, 1), nil
}

func verifyHeadAckRead(root []byte, aud string, v map[string]any) error {
	b, _ := base64.StdEncoding.DecodeString(v["response_b64"].(string))
	resp, err := fields(b)
	if err != nil {
		return err
	}
	if one(resp, 1) == nil {
		return errors.New("no ack")
	}
	payload, err := verifyStored(root, aud, one(resp, 1), resp[2], v["device"].(string), v["organization_id"].(string),
		"wendycloud.v2.DevicePostboxService/AckHead", num(v["verify_at"]))
	if err != nil {
		return err
	}
	ack, err := fields(payload)
	if err != nil {
		return err
	}
	id, _ := binary.Uvarint(one(ack, 1))
	ts, err := fields(one(ack, 3))
	if err != nil {
		return err
	}
	sec, _ := binary.Uvarint(one(ts, 1))
	if int64(id) != num(v["expected_entry_id"]) || int64(sec) != num(v["expected_observed_at"]) {
		return errors.New("signed entry_id / observed_at")
	}
	return nil
}

func verifyRecipient(root []byte, aud string, v map[string]any) error {
	b, _ := base64.StdEncoding.DecodeString(v["recipient_key_b64"].(string))
	rk, err := fields(b)
	if err != nil {
		return err
	}
	if string(one(rk, 1)) != v["principal"] {
		return errors.New("principal field")
	}
	payload, err := verifyStored(root, aud, one(rk, 2), rk[3], v["principal"].(string), v["organization_id"].(string),
		"wendycloud.v2.KeyDirectoryService/RegisterDeviceEncryptionKey", num(v["verify_at"]))
	if err != nil {
		return err
	}
	req, err := fields(payload)
	if err != nil {
		return err
	}
	if string(one(req, 1)) != v["organization_id"] {
		return errors.New("organization_id")
	}
	id := sha256.Sum256(one(req, 3))
	if want, ok := v["expected_key_id"]; ok && hex.EncodeToString(id[:]) != want {
		return errors.New("key_id")
	}
	return nil
}

func load(path string) map[string]any {
	var m map[string]any
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &m) != nil {
		panic("read " + path)
	}
	return m
}

func hx(m map[string]any, k string) []byte { b, _ := hex.DecodeString(m[k].(string)); return b }

func main() {
	dir := os.Args[1]
	failed := 0
	report := func(name, expect string, err error) {
		got := "valid"
		if err != nil {
			got = "invalid"
		}
		mark := "ok  "
		if got != expect {
			mark, failed = "FAIL", failed+1
		}
		fmt.Printf("%s %-46s expect=%-7s got=%-7s %v\n", mark, name, expect, got, err)
	}

	top := load(filepath.Join(dir, "reqsig", "device-signed-request-vectors-v1.json"))
	nonces := map[string]bool{}
	for _, x := range top["vectors"].([]any) {
		v := x.(map[string]any)
		report(v["name"].(string), v["expect"].(string), verifyDevice(top, v, nonces))
	}
	root, _ := base64.StdEncoding.DecodeString(top["root_cert_der_b64"].(string))
	for _, x := range top["recipient_key_vectors"].([]any) {
		v := x.(map[string]any)
		report(v["name"].(string), v["expect"].(string), verifyRecipient(root, top["aud"].(string), v))
	}

	for _, x := range top["head_ack_read_vectors"].([]any) {
		v := x.(map[string]any)
		report(v["name"].(string), v["expect"].(string), verifyHeadAckRead(root, top["aud"].(string), v))
	}

	reg := load(filepath.Join(dir, "registry", "registry-vectors-v1.json"))
	pb := reg["per_blob_key"].(map[string]any)
	for _, x := range pb["blobs"].([]any) {
		b := x.(map[string]any)
		k, err := hkdf.Key(sha256.New, hx(pb, "content_key_hex"), nil, b["plaintext_digest"].(string), 32)
		if err == nil && !bytes.Equal(k, hx(b, "blob_key_hex")) {
			err = errors.New("blob key differs")
		}
		report("per-blob-key "+b["plaintext_digest"].(string)[:15], "valid", err)
	}
	ck := sha256.Sum256(hx(pb, "content_key_hex"))
	report("content-key-id", "valid", map[bool]error{true: nil, false: errors.New("content_key_id")}[hex.EncodeToString(ck[:]) == pb["content_key_id"]])

	h := reg["hybrid_kem"].(map[string]any)
	err := func() error {
		kem, err := hpke.NewKEM(uint16(num(h["kem_id"])))
		if err != nil {
			return err
		}
		kdf, err := hpke.NewKDF(uint16(num(h["kdf_id"])))
		if err != nil {
			return err
		}
		aead, err := hpke.NewAEAD(uint16(num(h["aead_id"])))
		if err != nil {
			return err
		}
		sk, err := kem.DeriveKeyPair(hx(h, "ikm_hex"))
		if err != nil {
			return err
		}
		if !bytes.Equal(sk.PublicKey().Bytes(), hx(h, "public_key_hex")) {
			return errors.New("derived public key")
		}
		id := sha256.Sum256(hx(h, "public_key_hex"))
		if hex.EncodeToString(id[:]) != h["key_id"] {
			return errors.New("key_id")
		}
		r, err := hpke.NewRecipient(hx(h, "enc_hex"), sk, kdf, aead, hx(h, "info_hex"))
		if err != nil {
			return err
		}
		pt, err := r.Open(hx(h, "aad_hex"), hx(h, "ciphertext_hex"))
		if err == nil && !bytes.Equal(pt, hx(h, "plaintext_hex")) {
			err = errors.New("plaintext")
		}
		return err
	}()
	report("hybrid-kem-open", "valid", err)

	if failed > 0 {
		fmt.Printf("%d vector(s) disagree with expect\n", failed)
		os.Exit(1)
	}
	fmt.Println("all vectors agree with expect")
}
