//go:build ignore

// Generates conformance/registry/registry-vectors-v1.json and
// conformance/reqsig/device-signed-request-vectors-v1.json (WDY-3958).
// Go standard library only (Go 1.27+: crypto/mldsa, crypto/hpke, ML-DSA in
// crypto/x509). Run: go run conformance/registry/generate.go conformance
package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
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
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	tenant   = "2558fd76-afc7-466e-9613-6b715296a526"
	aud      = "https://cloud.wendy.sh/broker"
	iat      = 1790000000
	expiry   = 1790000300
	verifyAt = 1790000010

	ackHead     = "wendycloud.v2.DevicePostboxService/AckHead"
	registerKey = "wendycloud.v2.KeyDirectoryService/RegisterDeviceEncryptionKey"
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

func deviceURI(id string) string { return "spiffe://wendy.sh/tenant/" + tenant + "/device/" + id }

// detSigner signs ML-DSA certificates deterministically, so the ML-DSA half
// of the output is byte-for-byte reproducible.
type detSigner struct{ *mldsa.PrivateKey }

func (s detSigner) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignDeterministic(msg, opts)
}

func mldsaKey(label string) *mldsa.PrivateKey {
	return must(mldsa.NewPrivateKey(mldsa.MLDSA65(), seed(label)))
}

func p256Key(label string) *ecdsa.PrivateKey {
	return must(ecdsa.ParseRawPrivateKey(elliptic.P256(), seed(label)))
}

type cert struct {
	der    []byte
	parsed *x509.Certificate
	signer crypto.Signer
}

func issue(serial int64, cn, uri string, pub crypto.PublicKey, isCA bool, parent *cert, signer crypto.Signer) *cert {
	t := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(1767225600, 0).UTC(), // 2026-01-01
		NotAfter:     time.Unix(2082758400, 0).UTC(), // 2036-01-01
	}
	if isCA {
		t.IsCA, t.BasicConstraintsValid = true, true
		t.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		t.KeyUsage = x509.KeyUsageDigitalSignature
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		t.URIs = []*url.URL{must(url.Parse(uri))}
	}
	p := t
	if parent != nil {
		p = parent.parsed
	}
	der := must(x509.CreateCertificate(rand.Reader, t, p, pub, signer))
	return &cert{der: der, parsed: must(x509.ParseCertificate(der))}
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

func signedRequest(payload []byte, payloadType string, jws string) []byte {
	return cat(pbBytes(1, payload), pbBytes(2, []byte(payloadType)), pbBytes(3, []byte(jws)))
}

func jcs(v any) []byte {
	// encoding/json sorts map keys; every value here is ASCII without
	// characters JSON must escape, and every number is an integer, so this is
	// RFC 8785 output.
	return must(json.Marshal(v))
}

type jwsOut struct {
	header, claims map[string]any
	claimsJCS      []byte
	compact        string
}

func sign(key crypto.Signer, header map[string]any, claims map[string]any) jwsOut {
	cj := jcs(claims)
	input := b64u(must(json.Marshal(header))) + "." + b64u(cj)
	var sig []byte
	switch k := key.(type) {
	case detSigner:
		sig = must(k.SignDeterministic([]byte(input), nil))
	case *ecdsa.PrivateKey:
		h := sha256.Sum256([]byte(input))
		r, s := must2(ecdsa.Sign(rand.Reader, k, h[:]))
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	return jwsOut{header, claims, cj, input + "." + b64u(sig)}
}

func must2(r, s *big.Int, err error) (*big.Int, *big.Int) {
	if err != nil {
		panic(err)
	}
	return r, s
}

func claims(op, signer string, payload []byte, nonce string, iatV, expV int64) map[string]any {
	body := sha256.Sum256(payload)
	return map[string]any{
		"aud":            aud,
		"body_sha256":    b64u(body[:]),
		"correlation_id": "9e3b7c41-6a2d-4f8e-b5c0-1d7a2e9f4b63",
		"expiry":         expV,
		"iat":            iatV,
		"nonce":          nonce,
		"operation":      op,
		"target":         map[string]any{"tenant": tenant, "resource": signer},
	}
}

func writeJSON(path string, v any) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		panic(err)
	}
}

func main() {
	out := os.Args[1]

	// ---------- registry crypto ----------
	kem := hpke.MLKEM768X25519()
	kdf, aead := hpke.HKDFSHA256(), hpke.AES256GCM()
	devIKM := seed("wendy-registry-vector-device-kem-2026-10")
	devKEM := must(kem.DeriveKeyPair(devIKM))
	devPub := devKEM.PublicKey().Bytes()
	devPriv := must(devKEM.Bytes())
	devKeyID := sha256.Sum256(devPub)

	info := []byte("wendy conformance: HPKE suite check only, NOT the wrap info layout")
	aad := []byte("wendy conformance: suite check aad")
	plaintext := seed("wendy-registry-vector-deployment-key-2026-10")
	enc, sender := must2s(hpke.NewSender(devKEM.PublicKey(), kdf, aead, info))
	ct := must(sender.Seal(aad, plaintext))
	if pt, err := must(hpke.NewRecipient(enc, devKEM, kdf, aead, info)).Open(aad, ct); err != nil || string(pt) != string(plaintext) {
		panic("hpke round trip")
	}

	contentKey := seed("wendy-registry-vector-content-key-2026-10")
	ckID := sha256.Sum256(contentKey)
	var blobs []map[string]any
	for _, label := range []string{"vector layer one", "vector layer two"} {
		pd := sha256.Sum256([]byte(label))
		digest := "sha256:" + hex.EncodeToString(pd[:])
		k := must(hkdf.Key(sha256.New, contentKey, nil, digest, 32))
		blobs = append(blobs, map[string]any{"plaintext_digest": digest, "blob_key_hex": hex.EncodeToString(k)})
	}

	// ---------- chunk AEAD, key wrap, sealed content key ----------
	// Layouts: orchestrator ruling 2026-10-22 20:26 under the 2026-10-20
	// primitives decisions (README.md).
	const chunkSize = 16 // vectors only; the manifest default is 65536
	encryptBlob := func(pt []byte) (string, []byte) {
		pd := sha256.Sum256(pt)
		digest := "sha256:" + hex.EncodeToString(pd[:])
		gcm := gcmFor(must(hkdf.Key(sha256.New, contentKey, nil, digest, 32)))
		var ct []byte
		for i := 0; ; i++ {
			start, end := i*chunkSize, min((i+1)*chunkSize, len(pt))
			last := end == len(pt)
			ct = gcm.Seal(ct, chunkNonce(uint64(i), last), pt[start:end], nil)
			if last {
				return digest, ct
			}
		}
	}
	chunkVector := func(name, expect string, pt []byte, digest string, ct []byte) map[string]any {
		cd := sha256.Sum256(ct)
		return map[string]any{"name": name, "expect": expect, "plaintext_hex": hex.EncodeToString(pt), "plaintext_digest": digest,
			"plaintext_size": len(pt), "ciphertext_hex": hex.EncodeToString(ct), "ciphertext_digest": "sha256:" + hex.EncodeToString(cd[:])}
	}
	var chunkVectors []map[string]any
	for _, c := range []struct {
		name string
		size int
	}{{"empty-blob-valid", 0}, {"one-short-chunk-valid", 5}, {"two-full-chunks-valid", 32}, {"three-chunks-short-last-valid", 40}} {
		pt := []byte("wendy registry chunk vector plaintext, forty bytes!!")[:c.size]
		digest, ct := encryptBlob(pt)
		chunkVectors = append(chunkVectors, chunkVector(c.name, "valid", pt, digest, ct))
	}
	blobPT := []byte("wendy registry chunk vector plaintext, forty bytes!!")[:40]
	fullDigest, fullCT := encryptBlob(blobPT)
	otherPT := []byte("another blob of the same release")
	_, otherCT := encryptBlob(otherPT)
	const cc = chunkSize + 16
	chunkVectors = append(chunkVectors,
		chunkVector("truncated-last-chunk-invalid", "invalid", blobPT, fullDigest, fullCT[:2*cc]),
		chunkVector("reordered-chunks-invalid", "invalid", blobPT, fullDigest, cat(fullCT[cc:2*cc], fullCT[:cc], fullCT[2*cc:])),
		chunkVector("spliced-chunk-from-other-blob-invalid", "invalid", blobPT, fullDigest, cat(fullCT[:cc], otherCT[cc:2*cc], fullCT[2*cc:])),
	)

	deploymentKey := plaintext
	dkID := sha256.Sum256(deploymentKey)
	deploymentID := "4b2d8f6e-1c3a-4e5b-9d7f-2a6c8e0b1d3f"
	releaseID := "9e1f3a5c-7b2d-4c6e-8f0a-1b3d5e7f9a2c"
	type wrapBinding struct {
		OrganizationID string `json:"organization_id"`
		ScopeKind      byte   `json:"scope_kind"`
		ScopeID        string `json:"scope_id"`
		KeyID          string `json:"key_id"`
		RecipientKind  int    `json:"recipient_kind"`
		Recipient      string `json:"recipient"`
		RecipientKeyID string `json:"recipient_key_id"`
	}
	wrapVector := func(name, expect string, b wrapBinding, opened wrapBinding, key []byte) map[string]any {
		info := wrapInfo(b.OrganizationID, b.ScopeKind, b.ScopeID, b.KeyID, b.RecipientKind, b.Recipient, b.RecipientKeyID)
		enc, s := must2s(hpke.NewSender(devKEM.PublicKey(), kdf, aead, info))
		ct := must(s.Seal(nil, key))
		openInfo := wrapInfo(opened.OrganizationID, opened.ScopeKind, opened.ScopeID, opened.KeyID, opened.RecipientKind, opened.Recipient, opened.RecipientKeyID)
		return map[string]any{"name": name, "expect": expect, "binding": opened, "info_hex": hex.EncodeToString(openInfo),
			"wrapped_key_hex": hex.EncodeToString(key), "enc_hex": hex.EncodeToString(enc), "ciphertext_hex": hex.EncodeToString(ct)}
	}
	devWrap := wrapBinding{tenant, 1, deploymentID, hex.EncodeToString(dkID[:]), 1, deviceURI("7c1d3e5f-2a4b-4c6d-8e9f-0a1b2c3d4e5f"), hex.EncodeToString(devKeyID[:])}
	custodianWrap := wrapBinding{tenant, 2, releaseID, hex.EncodeToString(ckID[:]), 3, "", hex.EncodeToString(devKeyID[:])}
	movedWrap := devWrap
	movedWrap.ScopeID = "0d9c8b7a-6f5e-4d3c-8b2a-1f0e9d8c7b6a"
	wrapVectors := []map[string]any{
		wrapVector("device-deployment-wrap-valid", "valid", devWrap, devWrap, deploymentKey),
		wrapVector("custodian-release-wrap-valid", "valid", custodianWrap, custodianWrap, contentKey),
		wrapVector("wrong-scope-id-invalid", "invalid", devWrap, movedWrap, deploymentKey),
	}

	type sealBinding struct {
		OrganizationID  string `json:"organization_id"`
		DeploymentID    string `json:"deployment_id"`
		ManifestDigest  string `json:"manifest_digest"`
		ContentKeyID    string `json:"content_key_id"`
		DeploymentKeyID string `json:"deployment_key_id"`
	}
	md := sha256.Sum256([]byte("vector manifest"))
	seal := sealBinding{tenant, deploymentID, "sha256:" + hex.EncodeToString(md[:]), hex.EncodeToString(ckID[:]), hex.EncodeToString(dkID[:])}
	sealNonce := seed("wendy-registry-vector-seal-nonce-2026-10")[:12]
	sealCT := gcmFor(deploymentKey).Seal(nil, sealNonce, contentKey, sealAAD(seal.OrganizationID, seal.DeploymentID, seal.ManifestDigest, seal.ContentKeyID, seal.DeploymentKeyID))
	sealVector := func(name, expect string, b sealBinding) map[string]any {
		return map[string]any{"name": name, "expect": expect, "binding": b,
			"aad_hex":         hex.EncodeToString(sealAAD(b.OrganizationID, b.DeploymentID, b.ManifestDigest, b.ContentKeyID, b.DeploymentKeyID)),
			"nonce_hex":       hex.EncodeToString(sealNonce),
			"ciphertext_hex":  hex.EncodeToString(sealCT),
			"content_key_hex": hex.EncodeToString(contentKey)}
	}
	movedSeal := seal
	movedSeal.DeploymentID = movedWrap.ScopeID

	writeJSON(filepath.Join(out, "registry", "registry-vectors-v1.json"), map[string]any{
		"version":  "registry-vectors-v1",
		"contract": "conformance/registry/README.md; wendycloud/v2/registry.proto",
		"generation": map[string]any{
			"tool":    "go run conformance/registry/generate.go (Go 1.27, standard library only)",
			"seeds":   "every key below = SHA-256(<label>); labels are in the generator",
			"warning": "TEST KEYS ONLY. HPKE encapsulation is randomized: verify enc/ciphertext, do not regenerate to match.",
		},
		"per_blob_key": map[string]any{
			"rule":            "blob_key = HKDF-SHA256(IKM = content key, salt = none, info = UTF-8 of EncryptedBlob.plaintext_digest, L = 32)",
			"content_key_hex": hex.EncodeToString(contentKey),
			"content_key_id":  hex.EncodeToString(ckID[:]),
			"blobs":           blobs,
		},
		"hybrid_kem": map[string]any{
			"rule":            "HPKE base mode (RFC 9180), KEM MLKEM768-X25519 (X-Wing, draft-ietf-hpke-pq), HKDF-SHA256, AES-256-GCM",
			"kem_id":          kem.ID(),
			"kdf_id":          kdf.ID(),
			"aead_id":         aead.ID(),
			"ikm_hex":         hex.EncodeToString(devIKM),
			"private_key_hex": hex.EncodeToString(devPriv),
			"public_key_hex":  hex.EncodeToString(devPub),
			"key_id":          hex.EncodeToString(devKeyID[:]),
			"info_hex":        hex.EncodeToString(info),
			"aad_hex":         hex.EncodeToString(aad),
			"plaintext_hex":   hex.EncodeToString(plaintext),
			"enc_hex":         hex.EncodeToString(enc),
			"ciphertext_hex":  hex.EncodeToString(ct),
		},
		"chunk_aead": map[string]any{
			"rule":            "per chunk: AES-256-GCM under the per-blob key, nonce = 11-byte big-endian chunk index || last-chunk flag (0x01 last, else 0x00), no AAD; ciphertext = concatenated ct||16-byte tag per chunk; every chunk holds chunk_size plaintext bytes except the last (1..chunk_size); an empty blob is one empty last chunk; chunk index <= 2^32",
			"content_key_hex": hex.EncodeToString(contentKey),
			"chunk_size":      chunkSize,
			"vectors":         chunkVectors,
		},
		"key_wrap": map[string]any{
			"rule":              "HPKE base mode with the hybrid_kem suite; info = \"wendy-registry-wrap-v1\" || lp(organization_id) || u8 scope kind (1 deployment_id, 2 app_release_id) || lp(scope id) || lp(key_id) || lp(recipient_kind as decimal) || lp(recipient) || lp(recipient_key_id); lp = uint16 big-endian length || UTF-8 bytes; AAD empty; plaintext = the 32-byte key",
			"recipient_ikm_hex": hex.EncodeToString(devIKM),
			"vectors":           wrapVectors,
		},
		"sealed_content_key": map[string]any{
			"rule":               "AES-256-GCM under the 32-byte deployment key, 12-byte random nonce (SealedContentKey.nonce); AAD = \"wendy-registry-seal-v1\" || lp(organization_id) || lp(deployment_id) || lp(manifest_digest) || lp(content_key_id) || lp(deployment_key_id); plaintext = the 32-byte content key",
			"deployment_key_hex": hex.EncodeToString(deploymentKey),
			"vectors":            []map[string]any{sealVector("sealed-content-key-valid", "valid", seal), sealVector("wrong-deployment-id-invalid", "invalid", movedSeal)},
		},
	})

	// ---------- device-signer profile ----------
	root := &cert{signer: detSigner{mldsaKey("wendy-device-request-vector-root-2026-10")}}
	root = withSigner(issue(1, "Wendy Device Request Vector Root", "", root.signer.Public(), true, nil, root.signer), root.signer)
	caKey := detSigner{mldsaKey("wendy-device-request-vector-device-ca-2026-10")}
	deviceCA := withSigner(issue(2, "Vector Device Identity CA", "", caKey.Public(), true, root, root.signer), caKey)

	devA, devB := "7c1d3e5f-2a4b-4c6d-8e9f-0a1b2c3d4e5f", "3f8e2d1c-9b7a-4e6f-8d5c-4b3a2f1e0d9c"
	keyA := detSigner{mldsaKey("wendy-device-request-vector-device-a-2026-10")}
	keyB := detSigner{mldsaKey("wendy-device-request-vector-device-b-2026-10")}
	leafA := issue(10, devA, deviceURI(devA), keyA.Public(), false, deviceCA, deviceCA.signer)
	leafB := issue(11, devB, deviceURI(devB), keyB.Public(), false, deviceCA, deviceCA.signer)
	// A tier A/B device still on a P-256 leaf (before its ML-DSA renewal).
	ecKey := p256Key("wendy-device-request-vector-device-p256-2026-10")
	devEC := "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"
	leafEC := issue(12, devEC, deviceURI(devEC), ecKey.Public(), false, deviceCA, deviceCA.signer)
	// A rogue root a compromised cloud could serve, with a leaf for device A.
	rogueRoot := &cert{signer: detSigner{mldsaKey("wendy-device-request-vector-rogue-root-2026-10")}}
	rogueRoot = withSigner(issue(1, "Rogue Root", "", rogueRoot.signer.Public(), true, nil, rogueRoot.signer), rogueRoot.signer)
	rogueLeaf := issue(13, devA, deviceURI(devA), keyA.Public(), false, rogueRoot, rogueRoot.signer)

	ack := cat(pbVarint(1, 42), pbBytes(2, seed("vector postbox entry 42")), pbBytes(3, pbVarint(1, 1789999990)))
	reg := cat(pbBytes(1, []byte(tenant)), pbVarint(2, 1), pbBytes(3, devPub))
	x5c := func(c *cert) map[string]any { return map[string]any{"alg": "ML-DSA-65", "x5c": []string{b64(c.der)}} }

	type vec = map[string]any
	base := func(name, method string, peer *cert, expect string) vec {
		return vec{"name": name, "method": method, "verify_at": verifyAt, "expected_tenant": tenant, "device_tier": "A/B", "mtls_peer_cert_der_b64": b64(peer.der), "expect": expect}
	}
	full := func(v vec, payloadType string, payload []byte, j jwsOut, leaf *cert, uri string) vec {
		v["payload_type"], v["payload_b64"] = payloadType, b64(payload)
		h := map[string]any{}
		for k, x := range j.header {
			h[k] = x
		}
		if _, ok := h["x5c"]; ok {
			h["x5c"] = []string{"<leaf_cert_der_b64>"}
		}
		v["protected_header"], v["claims"], v["claims_jcs"], v["jws_compact"] = h, j.claims, string(j.claimsJCS), j.compact
		v["leaf_cert_der_b64"], v["spiffe_san"] = b64(leaf.der), uri
		v["signed_request_b64"] = b64(signedRequest(payload, payloadType, j.compact))
		return v
	}
	sr := func(v vec, payloadType string, payload []byte, j jwsOut, reason string) vec {
		v["signed_request_b64"] = b64(signedRequest(payload, payloadType, j.compact))
		v["invalid_reason"] = reason
		return v
	}

	ackValid := sign(keyA, x5c(leafA), claims(ackHead, deviceURI(devA), ack, "0f6c2b8e-4d1a-4e7b-9c3f-a5d8e2b1c7f4", iat, expiry))
	regValid := sign(keyA, x5c(leafA), claims(registerKey, deviceURI(devA), reg, "b2e7d4a1-8c3f-4a6e-9d1b-5f0c7e2a8b36", iat, expiry))
	kid := sha256.Sum256(leafA.der)
	ackKid := sign(keyA, map[string]any{"alg": "ML-DSA-65", "kid": b64u(kid[:])}, claims(ackHead, deviceURI(devA), ack, "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", iat, expiry))
	ackEC := sign(ecKey, map[string]any{"alg": "ES256", "x5c": []string{b64(leafEC.der)}}, claims(ackHead, deviceURI(devEC), ack, "6e5d4c3b-2a19-4f8e-9d7c-6b5a4f3e2d1c", iat, expiry))
	ackExpired := sign(keyA, x5c(leafA), claims(ackHead, deviceURI(devA), ack, "7d3a9e2f-1b6c-4d8e-a0f5-c2e4b7a9d1f3", 1789999990, 1790000005))
	// Fresh nonce: this vector must fail on the peer binding alone.
	ackOtherPeer := sign(keyA, x5c(leafA), claims(ackHead, deviceURI(devA), ack, "4c9e1a7b-3d5f-4b2e-8a6c-0f9d2b4e7a15", iat, expiry))
	ackWrongTarget := sign(keyA, x5c(leafA), claims(ackHead, deviceURI(devB), ack, "8e4b0f3a-2c7d-4e9f-b1a6-d3f5c8b0e2a4", iat, expiry))

	vectors := []vec{
		full(base("mldsa65-ack-head-valid", ackHead, leafA, "valid"), "wendycloud.v2.PostboxHeadAck", ack, ackValid, leafA, deviceURI(devA)),
		full(base("mldsa65-register-device-encryption-key-valid", registerKey, leafA, "valid"), "wendycloud.v2.RegisterEncryptionKeyRequest", reg, regValid, leafA, deviceURI(devA)),
		sr(base("replayed-nonce-invalid", ackHead, leafA, "invalid"), "wendycloud.v2.PostboxHeadAck", ack, ackValid,
			"replay: byte-identical to mldsa65-ack-head-valid; accept that vector first, then this one must fail on the already-claimed nonce"),
		sr(base("es256-tier-ab-invalid", ackHead, leafEC, "invalid"), "wendycloud.v2.PostboxHeadAck", ack, ackEC,
			"wrong algorithm for the tier: the device is tier A/B (recorded tier, never the request), which signs ML-DSA-65 only; the ES256 signature and the P-256 leaf chain are valid"),
		sr(base("kid-instead-of-x5c-invalid", ackHead, leafA, "invalid"), "wendycloud.v2.PostboxHeadAck", ack, ackKid,
			"device-signed requests carry the leaf in x5c; kid is refused even though it names the mTLS peer and the signature verifies"),
		sr(base("x5c-not-mtls-peer-invalid", ackHead, leafB, "invalid"), "wendycloud.v2.PostboxHeadAck", ack, ackOtherPeer,
			"x5c leaf (device A, the real signer; fresh nonce, signature verifies) is not byte-equal to the mTLS peer certificate (device B); both chain to the Device CA"),
		sr(base("expired-invalid", ackHead, leafA, "invalid"), "wendycloud.v2.PostboxHeadAck", ack, ackExpired,
			"expiry 1790000005 < verify_at 1790000010 (iat is within 60 s, the signature verifies)"),
		sr(base("target-not-signer-invalid", ackHead, leafA, "invalid"), "wendycloud.v2.PostboxHeadAck", ack, ackWrongTarget,
			"target.resource names device B; it must equal the signing leaf's SPIFFE URI (device A)"),
	}

	regSR := func(j jwsOut, payload []byte) []byte {
		return signedRequest(payload, "wendycloud.v2.RegisterEncryptionKeyRequest", j.compact)
	}
	recipient := func(principal string, registration []byte, chain ...*cert) string {
		m := cat(pbBytes(1, []byte(principal)), pbBytes(2, registration))
		for _, c := range chain {
			m = append(m, pbBytes(3, c.der)...)
		}
		return b64(m)
	}
	otherPub := must(kem.DeriveKeyPair(seed("wendy-registry-vector-other-kem-2026-10"))).PublicKey().Bytes()
	regSubst := cat(pbBytes(1, []byte(tenant)), pbVarint(2, 1), pbBytes(3, otherPub))
	regEC := sign(ecKey, map[string]any{"alg": "ES256", "x5c": []string{b64(leafEC.der)}}, claims(registerKey, deviceURI(devEC), reg, "d4a9f6c3-0e5b-4c8a-9f3d-7b2e9a4c0d58", iat, expiry))
	rogueReg := sign(keyA, x5c(rogueLeaf), claims(registerKey, deviceURI(devA), reg, "c3f8e5b2-9d4a-4b7f-8e2c-6a1d8f3b9c47", iat, expiry))
	rk := func(name, principal, body, expect, reason string) vec {
		v := vec{"name": name, "organization_id": tenant, "principal": principal, "recipient_key_b64": body, "expect": expect}
		if expect == "valid" {
			v["expected_key_id"] = hex.EncodeToString(devKeyID[:])
		} else {
			v["invalid_reason"] = reason
		}
		return v
	}
	recipientVectors := []vec{
		rk("recipient-key-valid", deviceURI(devA), recipient(deviceURI(devA), regSR(regValid, reg), deviceCA), "valid", ""),
		rk("recipient-key-chain-missing-invalid", deviceURI(devA), recipient(deviceURI(devA), regSR(regValid, reg)), "invalid",
			"chain_der is empty: the leaf cannot be chained to the pinned root"),
		rk("recipient-key-wrong-principal-invalid", deviceURI(devB), recipient(deviceURI(devB), regSR(regValid, reg), deviceCA), "invalid",
			"principal (device B) is not the registration leaf's identity (device A)"),
		rk("recipient-key-unpinned-root-invalid", deviceURI(devA), recipient(deviceURI(devA), regSR(rogueReg, reg), rogueRoot), "invalid",
			"the served chain ends in a root that is not the pinned root (a cloud-served CA)"),
		rk("recipient-key-substituted-key-invalid", deviceURI(devA), recipient(deviceURI(devA), regSR(regValid, regSubst), deviceCA), "invalid",
			"public_key replaced after signing: SHA-256(payload) != claims.body_sha256"),
		rk("recipient-key-es256-under-device-ca-invalid", deviceURI(devEC), recipient(deviceURI(devEC), regSR(regEC, reg), deviceCA), "invalid",
			"ES256 registration by a P-256 leaf under the ML-DSA Device Identity CA, which issues ML-DSA-65 signers only (signature and chain are valid)"),
	}

	// PostboxAckService.GetLastHeadAck: the stored AckHead request, verbatim,
	// with the chain to the tenant CA and the cloud-asserted hints.
	headAckRead := []vec{{
		"name": "last-head-ack-valid", "organization_id": tenant, "device": deviceURI(devA), "expect": "valid",
		"expected_entry_id": 42, "expected_observed_at": 1789999990,
		"response_b64": b64(cat(
			pbBytes(1, signedRequest(ack, "wendycloud.v2.PostboxHeadAck", ackValid.compact)),
			pbBytes(2, deviceCA.der),
			pbBytes(3, pbVarint(1, 1790000001)),
			pbVarint(4, 42),
		)),
	}}

	writeJSON(filepath.Join(out, "reqsig", "device-signed-request-vectors-v1.json"), map[string]any{
		"version":  "device-signed-request-vectors-v1",
		"contract": "conformance/reqsig/README.md (Device-signer profile)",
		"generation": map[string]any{
			"tool":          "go run conformance/registry/generate.go (Go 1.27, standard library only)",
			"deterministic": "ML-DSA keys from seed = SHA-256(label); ML-DSA certificates and JWS signed deterministically. ES256 and HPKE are randomized: verify those bytes, do not regenerate to match.",
			"warning":       "TEST KEYS ONLY: the seed labels in the generator ARE the private keys.",
		},
		"root_cert_der_b64":      b64(root.der),
		"device_ca_cert_der_b64": b64(deviceCA.der),
		"aud":                    aud,
		"vectors":                vectors,
		"recipient_key_vectors":  recipientVectors,
		"head_ack_read_vectors":  headAckRead,
		"todo": []map[string]string{
			{"name": "es256-tier-c-valid", "needs": "ruling: which device_signed_request methods a tier C (wendy-lite) device calls; today none (the registry is tier A/B only)."},
			{"name": "recipient-key-foreign-tenant-ca-invalid", "needs": "how a tenant CA certificate names its tenant (pki-core CA shape) so the client's CA-tenant check has bytes to test."},
		},
	})
}

func withSigner(c *cert, s crypto.Signer) *cert { c.signer = s; return c }

// chunkNonce, lp, wrapInfo and sealAAD are the ruled layouts (README.md).
func chunkNonce(index uint64, last bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[3:11], index)
	if last {
		n[11] = 1
	}
	return n
}

func lp(b []byte, fields ...string) []byte {
	for _, f := range fields {
		b = append(binary.BigEndian.AppendUint16(b, uint16(len(f))), f...)
	}
	return b
}

func wrapInfo(org string, scopeKind byte, scopeID, keyID string, recipientKind int, recipient, recipientKeyID string) []byte {
	b := append(lp([]byte("wendy-registry-wrap-v1"), org), scopeKind)
	return lp(b, scopeID, keyID, fmt.Sprint(recipientKind), recipient, recipientKeyID)
}

func sealAAD(org, deploymentID, manifestDigest, contentKeyID, deploymentKeyID string) []byte {
	return lp([]byte("wendy-registry-seal-v1"), org, deploymentID, manifestDigest, contentKeyID, deploymentKeyID)
}

func gcmFor(key []byte) cipher.AEAD { return must(cipher.NewGCM(must(aes.NewCipher(key)))) }

func must2s(enc []byte, s *hpke.Sender, err error) ([]byte, *hpke.Sender) {
	if err != nil {
		panic(err)
	}
	return enc, s
}
