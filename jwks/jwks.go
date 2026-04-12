// Package jwks provides a JWKS (JSON Web Key Set) endpoint handler that serves
// the tool's public keys so platforms can verify JWT assertions sent by the tool.
package jwks

import (
	"crypto/rsa"
	"encoding/base64"
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
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}
		doc.Keys = append(doc.Keys, jwk)
	}
	return json.Marshal(doc)
}
