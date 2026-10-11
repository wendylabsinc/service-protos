//go:build ignore

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
)

func main() {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	d := new(big.Int).SetBytes(seed)
	x, y := elliptic.P256().ScalarBaseMult(seed)
	sk := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	pub := elliptic.Marshal(elliptic.P256(), x, y)
	device := "spiffe://wendy.sh/tenant/00000000-0000-4000-8000-000000000001/device/lite-test"
	operator := "spiffe://wendy.sh/tenant/00000000-0000-4000-8000-000000000001/operator/00000000-0000-4000-8000-000000000002"
	kid := "conformance-cloud-key"
	// The operator caller key: a second fixed scalar, public test material.
	opSeed := make([]byte, 32)
	for i := range opSeed {
		opSeed[i] = byte(32 + i)
	}
	ox, oy := elliptic.P256().ScalarBaseMult(opSeed)
	opSPKI, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: ox, Y: oy})
	if err != nil {
		panic(err)
	}
	r := append([]byte("WLG2"), byte(len(kid)))
	r = append(r, []byte(kid)...)
	r = binary.BigEndian.AppendUint64(r, 1700000000)
	r = binary.BigEndian.AppendUint64(r, 1700000060)
	session := make([]byte, 16)
	session[15] = 3
	jti := make([]byte, 16)
	jti[15] = 5
	correlation := make([]byte, 16)
	correlation[15] = 6
	asset := make([]byte, 16)
	asset[15] = 4
	r = append(r, session...)
	r = append(r, jti...)
	r = append(r, correlation...)
	r = append(r, asset...)
	for _, b := range [][]byte{[]byte(device), []byte(operator), opSPKI, []byte("conformance principal descriptor"), []byte("conformance.pki.attestation")} {
		h := sha256.Sum256(b)
		r = append(r, h[:]...)
	}
	digest := sha256.Sum256(r)
	sr, ss, err := ecdsa.Sign(rand.Reader, sk, digest[:])
	if err != nil {
		panic(err)
	}
	r = append(r, sr.FillBytes(make([]byte, 32))...)
	r = append(r, ss.FillBytes(make([]byte, 32))...)
	hash := sha256.Sum256(r)
	root := os.Args[1] + "/"
	os.MkdirAll(root, 0755)
	os.WriteFile(root+"grant.bin", r, 0644)
	os.WriteFile(root+"cloud-key.bin", pub, 0644)
	v := map[string]any{"key_id": kid, "public_key_hex": hex.EncodeToString(pub), "record_hex": hex.EncodeToString(r), "grant_hash_hex": hex.EncodeToString(hash[:]), "device_uri": device, "operator_uri": operator, "operator_spki_hex": hex.EncodeToString(opSPKI), "issued_at": 1700000000, "expires_at": 1700000060, "jti_hex": hex.EncodeToString(jti), "correlation_id_hex": hex.EncodeToString(correlation), "attestation": "conformance.pki.attestation", "session_id_hex": hex.EncodeToString(session), "asset_id_hex": hex.EncodeToString(asset), "private_seed_hex": hex.EncodeToString(seed)}
	b, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(root+"vector.json", append(b, '\n'), 0644)
}
