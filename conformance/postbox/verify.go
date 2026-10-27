//go:build ignore

// Reference device-side check for checkpoint-vectors-v1.json (WDY-4015 item
// 2, WDY-2162): verifies every vector in the order conformance/postbox/README.md
// gives (pki-core postbox.Verifier.Verify) and exits non-zero unless each one
// ends in its `expect` and, for an invalid vector, its `refusal` code.
// Run: go run conformance/postbox/verify.go conformance/postbox
package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxSkew = 5 * time.Second

var (
	oidCheckpointEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65441, 1, 8}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	mldsaOIDs        = map[int]asn1.ObjectIdentifier{ // by public key length
		1312: {2, 16, 840, 1, 101, 3, 4, 3, 17},
		1952: {2, 16, 840, 1, 101, 3, 4, 3, 18},
		2592: {2, 16, 840, 1, 101, 3, 4, 3, 19},
	}
	jwsAlgs = map[int]string{1312: "ML-DSA-44", 1952: "ML-DSA-65", 2592: "ML-DSA-87"}
)

type refusal struct{ code, why string }

func (r refusal) Error() string { return r.code + ": " + r.why }

func refuse(code, format string, a ...any) error { return refusal{code, fmt.Sprintf(format, a...)} }

// b64any accepts standard or URL-safe base64, padded or not (postbox.DecodeArtifact).
func b64any(s string) ([]byte, error) {
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not base64")
}

type params struct {
	roots          *x509.CertPool
	tenant, target string
	hwm            uint64
	now            time.Time
}

type verdict struct {
	maxID   uint64
	genTime time.Time
}

func verifyCheckpoint(raw []byte, p params) (verdict, error) {
	// 1. Decode the artifact: all three members required.
	var a struct {
		Body           *string `json:"body"`
		Signature      *string `json:"signature"`
		TimestampToken *string `json:"timestamp_token"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return verdict{}, refuse("malformed", "artifact JSON: %v", err)
	}
	if a.Body == nil || a.Signature == nil || a.TimestampToken == nil || *a.Body == "" || *a.Signature == "" || *a.TimestampToken == "" {
		return verdict{}, refuse("malformed", "artifact requires body, signature and timestamp_token")
	}
	body, err := b64any(*a.Body)
	if err != nil {
		return verdict{}, refuse("malformed", "body: %v", err)
	}
	token, err := b64any(*a.TimestampToken)
	if err != nil {
		return verdict{}, refuse("malformed", "timestamp_token: %v", err)
	}

	// 2. Authorship: the JWS, its x5c chain to the pinned root, the
	// checkpoint-signer EKU, the signature.
	payload, chain, err := verifyJWS(*a.Signature, p)
	if err != nil {
		return verdict{}, err
	}

	// 3. The signed payload is the body, byte for byte.
	if !bytes.Equal(payload, body) {
		return verdict{}, refuse("signature_body_mismatch", "JWS payload is not the artifact body")
	}

	// 4. Trusted time: the RFC 3161 token over SHA-256(body as received).
	genTime, err := verifyToken(token, body, chain, p)
	if err != nil {
		return verdict{}, err
	}

	// 5. Decode the body; unknown members and an unknown v are refused.
	var b struct {
		V           *int    `json:"v"`
		Tenant      string  `json:"tenant"`
		Target      *string `json:"target"`
		MaxID       *uint64 `json:"max_id"`
		HashOfHead  string  `json:"hash_of_head"`
		NotarizedAt string  `json:"notarized_at"`
		ExpiresAt   string  `json:"expires_at"`
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&b); err != nil {
		return verdict{}, refuse("body", "decode: %v", err)
	}
	if b.V == nil || *b.V != 1 {
		return verdict{}, refuse("body", "unsupported version")
	}
	hh, err := base64.RawURLEncoding.DecodeString(b.HashOfHead)
	nat, err1 := time.Parse(time.RFC3339, b.NotarizedAt)
	exp, err2 := time.Parse(time.RFC3339, b.ExpiresAt)
	if err != nil || len(hh) != 32 || err1 != nil || err2 != nil || b.Tenant == "" || b.Target == nil || b.MaxID == nil || !exp.After(nat) {
		return verdict{}, refuse("body", "missing or malformed member")
	}

	// 6. Tenant.
	if b.Tenant != p.tenant {
		return verdict{}, refuse("tenant_mismatch", "tenant %s", b.Tenant)
	}
	// 7. Target: this device, or "" (tenant-wide).
	if *b.Target != p.target && *b.Target != "" {
		return verdict{}, refuse("target_mismatch", "target %s", *b.Target)
	}
	// 8. Skew: genTime no earlier than notarized_at - 5 s.
	if genTime.Before(nat.Add(-maxSkew)) {
		return verdict{}, refuse("skew", "genTime %s before notarized_at %s", genTime, nat)
	}
	// 9. Rollback.
	if *b.MaxID < p.hwm {
		return verdict{}, refuse("rollback", "max_id %d below high-water mark %d", *b.MaxID, p.hwm)
	}
	// 10. Stale: now > expires_at (now == expires_at is still fresh).
	if p.now.After(exp) {
		return verdict{}, refuse("stale", "expired at %s", exp)
	}
	return verdict{*b.MaxID, genTime}, nil
}

// verifyJWS returns the payload and the verified chain (leaf first).
func verifyJWS(compact string, p params) ([]byte, []*x509.Certificate, error) {
	seg := strings.Split(compact, ".")
	if len(seg) != 3 {
		return nil, nil, refuse("signature", "not a compact JWS")
	}
	var h struct {
		Alg  string   `json:"alg"`
		X5c  []string `json:"x5c"`
		Crit any      `json:"crit"`
		Kid  any      `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(seg[0])
	if err != nil || json.Unmarshal(hb, &h) != nil || h.Crit != nil || h.Kid != nil || len(h.X5c) == 0 {
		return nil, nil, refuse("signature", "bad protected header")
	}
	certs := make([]*x509.Certificate, len(h.X5c))
	inter := x509.NewCertPool()
	for i, s := range h.X5c {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, nil, refuse("signature", "x5c[%d]: %v", i, err)
		}
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return nil, nil, refuse("signature", "x5c[%d]: %v", i, err)
		}
		if i > 0 {
			inter.AddCert(certs[i])
		}
	}
	leaf := certs[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: p.roots, Intermediates: inter, CurrentTime: p.now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, nil, refuse("signature", "chain: %v", err)
	}
	hasEKU := false
	for _, oid := range leaf.UnknownExtKeyUsage {
		hasEKU = hasEKU || oid.Equal(oidCheckpointEKU)
	}
	if !hasEKU {
		return nil, nil, refuse("signer_role", "leaf %q lacks the checkpoint-signer EKU", leaf.Subject.CommonName)
	}
	pk, ok := leaf.PublicKey.(*mldsa.PublicKey)
	if !ok || jwsAlgs[len(pk.Bytes())] != h.Alg {
		return nil, nil, refuse("signature", "alg %q does not match the leaf key", h.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(seg[2])
	if err != nil || mldsa.Verify(pk, []byte(seg[0]+"."+seg[1]), sig, nil) != nil {
		return nil, nil, refuse("signature", "signature does not verify")
	}
	payload, err := base64.RawURLEncoding.DecodeString(seg[1])
	if err != nil {
		return nil, nil, refuse("signature", "payload: %v", err)
	}
	return payload, certs, nil
}

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type issuerSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type signerInfo struct {
	Version            int
	SID                issuerSerial
	DigestAlgorithm    algID
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algID
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo struct {
		EContentType asn1.ObjectIdentifier
		EContent     []byte `asn1:"explicit,tag:0,optional"`
	}
	Certificates asn1.RawValue `asn1:"optional,tag:0"`
	CRLs         asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos  []signerInfo  `asn1:"set"`
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

// verifyToken checks the RFC 3161 TimeStampResp and returns its genTime.
// The token embeds only the TSA signer leaf; candidate intermediates are the
// JWS chain beyond its leaf (the TSA Intermediate) and the token's own other
// certificates. Every one of them must still chain to the pinned root.
func verifyToken(der, body []byte, jwsChain []*x509.Certificate, p params) (time.Time, error) {
	var resp struct {
		Status struct {
			Status int
			Rest   asn1.RawValue `asn1:"optional"`
		}
		TimeStampToken asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(der, &resp); err != nil || resp.Status.Status != 0 || len(resp.TimeStampToken.FullBytes) == 0 {
		return time.Time{}, refuse("timestamp", "not a granted TimeStampResp")
	}
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	var sd signedData
	if _, err := asn1.Unmarshal(resp.TimeStampToken.FullBytes, &ci); err != nil || !ci.ContentType.Equal(oidSignedData) {
		return time.Time{}, refuse("timestamp", "token is not SignedData")
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return time.Time{}, refuse("timestamp", "SignedData: %v", err)
	}
	if len(sd.SignerInfos) != 1 || !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) || len(sd.EncapContentInfo.EContent) == 0 {
		return time.Time{}, refuse("timestamp", "want one SignerInfo over an attached TSTInfo")
	}
	si := sd.SignerInfos[0]

	// The signer is the embedded certificate the SignerInfo names, never a
	// position in the list.
	var signer *x509.Certificate
	inter := x509.NewCertPool()
	for _, c := range jwsChain[1:] {
		inter.AddCert(c)
	}
	for rest := sd.Certificates.Bytes; len(rest) > 0; {
		var raw asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return time.Time{}, refuse("timestamp", "certificates: %v", err)
		}
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return time.Time{}, refuse("timestamp", "certificates: %v", err)
		}
		if bytes.Equal(c.RawIssuer, si.SID.Issuer.FullBytes) && c.SerialNumber.Cmp(si.SID.SerialNumber) == 0 {
			if signer != nil {
				return time.Time{}, refuse("timestamp", "signer is ambiguous")
			}
			signer = c
		} else {
			inter.AddCert(c)
		}
	}
	if signer == nil {
		return time.Time{}, refuse("timestamp", "signer certificate not embedded")
	}
	pk, ok := signer.PublicKey.(*mldsa.PublicKey)
	if !ok || !si.SignatureAlgorithm.Algorithm.Equal(mldsaOIDs[len(pk.Bytes())]) {
		return time.Time{}, refuse("timestamp", "signature algorithm does not match the signer key")
	}

	// Signed attributes: content-type TSTInfo, message-digest = SHA-256(TSTInfo).
	if !si.DigestAlgorithm.Algorithm.Equal(oidSHA256) || len(si.SignedAttrs.FullBytes) == 0 {
		return time.Time{}, refuse("timestamp", "want SHA-256 signed attributes")
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
			return time.Time{}, refuse("timestamp", "signed attribute: %v", err)
		}
		switch {
		case at.Type.Equal(oidContentType):
			asn1.Unmarshal(at.Value.Bytes, &ct)
		case at.Type.Equal(oidMessageDigest):
			asn1.Unmarshal(at.Value.Bytes, &md)
		}
	}
	sum := sha256.Sum256(sd.EncapContentInfo.EContent)
	if !ct.Equal(oidTSTInfo) || !bytes.Equal(md, sum[:]) {
		return time.Time{}, refuse("timestamp", "signed attributes do not bind the TSTInfo")
	}
	// ML-DSA over the signed attributes re-tagged as a SET (RFC 5652 §5.4).
	set := append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
	if mldsa.Verify(pk, set, si.Signature, nil) != nil {
		return time.Time{}, refuse("timestamp", "CMS signature does not verify")
	}

	var tst tstInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &tst); err != nil {
		return time.Time{}, refuse("timestamp", "TSTInfo: %v", err)
	}
	// The TSA chain is checked at genTime, now that the signature vouches for it.
	if _, err := signer.Verify(x509.VerifyOptions{Roots: p.roots, Intermediates: inter, CurrentTime: tst.GenTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}); err != nil {
		return time.Time{}, refuse("timestamp", "TSA chain: %v", err)
	}
	h := sha256.Sum256(body)
	if !tst.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) || !bytes.Equal(tst.MessageImprint.HashedMessage, h[:]) {
		return time.Time{}, refuse("imprint_mismatch", "token imprint is not SHA-256(body)")
	}
	return tst.GenTime, nil
}

func main() {
	raw, err := os.ReadFile(filepath.Join(os.Args[1], "checkpoint-vectors-v1.json"))
	if err != nil {
		panic(err)
	}
	var doc struct {
		Root    string `json:"root_cert_der_b64"`
		Vectors []struct {
			Name       string `json:"name"`
			Expect     string `json:"expect"`
			Refusal    string `json:"refusal"`
			Tenant     string `json:"expected_tenant"`
			Target     string `json:"expected_target"`
			HWM        uint64 `json:"high_water_mark"`
			VerifyAt   int64  `json:"verify_at"`
			Checkpoint string `json:"checkpoint_b64"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		panic(err)
	}
	rootDER, _ := base64.StdEncoding.DecodeString(doc.Root)
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)

	failed := 0
	for _, v := range doc.Vectors {
		cp, _ := base64.StdEncoding.DecodeString(v.Checkpoint)
		_, err := verifyCheckpoint(cp, params{roots, v.Tenant, v.Target, v.HWM, time.Unix(v.VerifyAt, 0)})
		got, code := "valid", ""
		if err != nil {
			got = "invalid"
			if r, ok := err.(refusal); ok {
				code = r.code
			}
		}
		status := "ok  "
		if got != v.Expect || code != v.Refusal {
			status, failed = "FAIL", failed+1
		}
		fmt.Printf("%s %-34s expect=%s refusal=%q got=%s (%v)\n", status, v.Name, v.Expect, v.Refusal, got, err)
	}
	if failed > 0 {
		fmt.Printf("%d of %d vectors disagree\n", failed, len(doc.Vectors))
		os.Exit(1)
	}
	fmt.Printf("all %d vectors agree\n", len(doc.Vectors))
}
