//go:build ignore

// Reference check for the vectors generate.go writes (WDY-3958): verifies every
// device-signer, RecipientKey, head-ack read and registry vector against the rules in
// conformance/reqsig/README.md and conformance/registry/README.md and exits
// non-zero on any disagreement with its `expect`.
// Run: go run conformance/registry/verify.go conformance
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// chain verifies leaf to root at time at and returns the leaf's issuing CA.
func chain(leaf *x509.Certificate, root []byte, intermediates [][]byte, at int64) (*x509.Certificate, error) {
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	rc, err := x509.ParseCertificate(root)
	if err != nil {
		return nil, err
	}
	roots.AddCert(rc)
	for _, d := range intermediates {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, err
		}
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: time.Unix(at, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return nil, err
	}
	return chains[0][1], nil
}

// issuerAlg is the one algorithm a device leaf under ca may sign with: the
// ML-DSA Device Identity CA issues ML-DSA-65 signers, its P-256 Lite sibling
// ES256 signers. Anything else issues no device signer ("").
func issuerAlg(ca *x509.Certificate) string {
	switch k := ca.PublicKey.(type) {
	case *mldsa.PublicKey:
		return "ML-DSA-65"
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return "ES256"
		}
	}
	return ""
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
	tier, _ := v["device_tier"].(string)
	want, ok := map[string]string{"A/B": "ML-DSA-65", "C": "ES256"}[tier]
	if !ok {
		return fmt.Errorf("unknown or absent tier %q", tier)
	}
	if j.header["alg"] != want {
		return fmt.Errorf("tier %v requires %s", tier, want)
	}
	root, _ := base64.StdEncoding.DecodeString(top["root_cert_der_b64"].(string))
	ca, _ := base64.StdEncoding.DecodeString(top["device_ca_cert_der_b64"].(string))
	at := num(v["verify_at"])
	issuer, err := chain(j.leaf, root, [][]byte{ca}, at)
	if err != nil {
		return err
	}
	if issuerAlg(issuer) != want {
		return errors.New("issuing CA does not issue signers of the tier's algorithm")
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
func verifyStored(root []byte, aud string, sr []byte, chainDER [][]byte, principal, org, method string) ([]byte, error) {
	reg, err := fields(sr)
	if err != nil {
		return nil, err
	}
	j, err := parseAndVerify(string(one(reg, 3)))
	if err != nil {
		return nil, err
	}
	// The chain must have been valid when the device signed: at the signed iat.
	at := num(j.claims["iat"])
	issuer, err := chain(j.leaf, root, chainDER, at)
	if err != nil {
		return nil, fmt.Errorf("chain to pinned root: %w", err)
	}
	if a := issuerAlg(issuer); a == "" || j.header["alg"] != a {
		return nil, errors.New("issuing CA does not issue signers of this algorithm")
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
		"wendycloud.v2.DevicePostboxService/AckHead")
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
		"wendycloud.v2.KeyDirectoryService/RegisterDeviceEncryptionKey")
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

func chunkNonce(index uint64, last bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[3:11], index)
	if last {
		n[11] = 1
	}
	return n
}

// lp appends each field as a uint16 big-endian length and its bytes; a field
// over 65535 bytes is refused.
func lp(b []byte, fields ...string) ([]byte, error) {
	for _, f := range fields {
		if len(f) > 65535 {
			return nil, errors.New("binding field over 65535 bytes")
		}
		b = append(binary.BigEndian.AppendUint16(b, uint16(len(f))), f...)
	}
	return b, nil
}

// blobKey = HKDF-SHA256(content key, info = plaintext_digest || u32 BE chunk_size).
func blobKey(contentKey []byte, digest string, chunkSize uint32) ([]byte, error) {
	return hkdf.Key(sha256.New, contentKey, nil, string(binary.BigEndian.AppendUint32([]byte(digest), chunkSize)), 32)
}

func gcmFor(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
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
		k, err := blobKey(hx(pb, "content_key_hex"), b["plaintext_digest"].(string), uint32(num(pb["chunk_size"])))
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

	// chunk_aead: decrypt chunk by chunk; the last chunk is the one the
	// ciphertext ends with, and only an empty blob has an empty last chunk.
	ca := reg["chunk_aead"].(map[string]any)
	chunk := int(num(ca["chunk_size"])) + 16
	for _, x := range ca["vectors"].([]any) {
		v := x.(map[string]any)
		err := func() error {
			ct := hx(v, "ciphertext_hex")
			key, err := blobKey(hx(ca, "content_key_hex"), v["plaintext_digest"].(string), uint32(num(ca["chunk_size"])))
			if err != nil {
				return err
			}
			gcm := gcmFor(key)
			var pt []byte
			for i := 0; ; i++ {
				rest := ct[min(i*chunk, len(ct)):]
				last := len(rest) <= chunk
				if len(rest) < 16 || last && len(rest) == 16 && i > 0 {
					return errors.New("truncated chunk")
				}
				c := rest[:min(chunk, len(rest))]
				if pt, err = gcm.Open(pt, chunkNonce(uint64(i), last), c, nil); err != nil {
					return err
				}
				if last {
					break
				}
			}
			pd := sha256.Sum256(pt)
			if "sha256:"+hex.EncodeToString(pd[:]) != v["plaintext_digest"] || !bytes.Equal(pt, hx(v, "plaintext_hex")) {
				return errors.New("plaintext")
			}
			return nil
		}()
		report("chunk-aead "+v["name"].(string), v["expect"].(string), err)
	}

	kw := reg["key_wrap"].(map[string]any)
	wsk, _ := hpke.MLKEM768X25519().DeriveKeyPair(hx(kw, "recipient_ikm_hex"))
	for _, x := range kw["vectors"].([]any) {
		v := x.(map[string]any)
		b := v["binding"].(map[string]any)
		str := func(k string) string { return b[k].(string) }
		err := func() error {
			info, err := lp([]byte("wendy-registry-wrap-v1"), str("organization_id"))
			if err != nil {
				return err
			}
			if info, err = lp(append(info, byte(num(b["scope_kind"]))), str("scope_id"), str("key_id")); err != nil {
				return err
			}
			if info, err = lp(append(info, byte(num(b["recipient_kind"]))), str("recipient"), str("recipient_key_id")); err != nil {
				return err
			}
			if !bytes.Equal(info, hx(v, "info_hex")) {
				return errors.New("info bytes")
			}
			r, err := hpke.NewRecipient(hx(v, "enc_hex"), wsk, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
			if err != nil {
				return err
			}
			key, err := r.Open(nil, hx(v, "ciphertext_hex"))
			if err == nil && !bytes.Equal(key, hx(v, "wrapped_key_hex")) {
				return errors.New("wrapped key")
			}
			return err
		}()
		report("key-wrap "+v["name"].(string), v["expect"].(string), err)
	}

	sc := reg["sealed_content_key"].(map[string]any)
	for _, x := range sc["vectors"].([]any) {
		v := x.(map[string]any)
		b := v["binding"].(map[string]any)
		str := func(k string) string { return b[k].(string) }
		err := func() error {
			aad, err := lp([]byte("wendy-registry-seal-v1"), str("organization_id"), str("deployment_id"), str("manifest_digest"), str("content_key_id"), str("deployment_key_id"))
			if err != nil {
				return err
			}
			if !bytes.Equal(aad, hx(v, "aad_hex")) {
				return errors.New("aad bytes")
			}
			key, err := gcmFor(hx(sc, "deployment_key_hex")).Open(nil, hx(v, "nonce_hex"), hx(v, "ciphertext_hex"), aad)
			if err == nil && !bytes.Equal(key, hx(v, "content_key_hex")) {
				return errors.New("content key")
			}
			return err
		}()
		report("sealed-content-key "+v["name"].(string), v["expect"].(string), err)
	}

	if failed > 0 {
		fmt.Printf("%d vector(s) disagree with expect\n", failed)
		os.Exit(1)
	}
	fmt.Println("all vectors agree with expect")
}
