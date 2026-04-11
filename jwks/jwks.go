// Package jwks provides a JWKS (JSON Web Key Set) endpoint handler that serves
// the tool's public keys so platforms can verify JWT assertions sent by the tool.
package jwks

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/robertjndw/go-lti"
)

// publicJWK is the JSON representation of a single RSA public key in JWK format.
type publicJWK struct {
	KTY string `json:"kty"`
	ALG string `json:"alg"`
	Use string `json:"use"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksDocument is the standard JWKS JSON envelope.
type jwksDocument struct {
	Keys []publicJWK `json:"keys"`
}

// KeySet holds one or more RSA private keys and can serve the corresponding
// public keys as a JWKS endpoint.
type KeySet struct {
	// keys maps KID → RSA private key.
	keys map[string]*rsa.PrivateKey
}

// NewKeySet creates a KeySet from a map of KID → private key.
func NewKeySet(keys map[string]*rsa.PrivateKey) *KeySet {
	return &KeySet{keys: keys}
}

// FromRegistration creates a KeySet from a single Registration.
func FromRegistration(reg *lti.Registration) *KeySet {
	return NewKeySet(map[string]*rsa.PrivateKey{
		reg.KID: reg.ToolPrivateKey,
	})
}

// Handler returns an http.Handler that serves the tool's public JWKS as JSON
// with Content-Type: application/json.
func (ks *KeySet) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := ks.PublicJWKS()
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to build JWKS: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data) //nolint:errcheck
	})
}

// PublicJWKS encodes the tool's public key set as a JSON JWKS document.
func (ks *KeySet) PublicJWKS() ([]byte, error) {
	doc := jwksDocument{}
	for kid, priv := range ks.keys {
		pub := &priv.PublicKey
		jwk := publicJWK{
			KTY: "RSA",
			ALG: "RS256",
			Use: "sig",
			KID: kid,
			N:   base64URLEncodeBigInt(pub.N),
			E:   base64URLEncodeInt(pub.E),
		}
		doc.Keys = append(doc.Keys, jwk)
	}
	return json.Marshal(doc)
}

// base64URLEncodeBigInt encodes a big.Int as an unpadded base64url string (JWK "n").
func base64URLEncodeBigInt(n *big.Int) string {
	return encodeBase64URL(n.Bytes())
}

// base64URLEncodeInt encodes an int as an unpadded base64url string (JWK "e").
func base64URLEncodeInt(e int) string {
	b := big.NewInt(int64(e)).Bytes()
	return encodeBase64URL(b)
}

// encodeBase64URL returns the RFC 4648 §5 (URL-safe, no padding) base64 encoding.
func encodeBase64URL(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, 0, (len(b)*4+2)/3)
	for i := 0; i < len(b); i += 3 {
		var b0, b1, b2 byte
		b0 = b[i]
		if i+1 < len(b) {
			b1 = b[i+1]
		}
		if i+2 < len(b) {
			b2 = b[i+2]
		}
		result = append(result, alphabet[b0>>2])
		result = append(result, alphabet[(b0&0x03)<<4|b1>>4])
		if i+1 < len(b) {
			result = append(result, alphabet[(b1&0x0f)<<2|b2>>6])
		}
		if i+2 < len(b) {
			result = append(result, alphabet[b2&0x3f])
		}
	}
	return string(result)
}
