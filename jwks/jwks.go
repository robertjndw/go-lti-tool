// Package jwks provides a JWKS (JSON Web Key Set) endpoint handler that serves
// the tool's public keys so platforms can verify JWT assertions sent by the tool.
package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"sync"

	"github.com/robertjndw/go-lti/internal/lticore"
)

// KeySetProvider serves the tool's public JWKS. *jwks.KeySet from the jwks
// sub-package satisfies this interface.
type KeySetProvider interface {
	AddKey(kid string, priv *rsa.PrivateKey)
	GetPrivateKey(kid string) (*rsa.PrivateKey, bool)
	PublicJWKS() ([]byte, error)
}

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
	mu   sync.RWMutex
	keys map[string]*rsa.PrivateKey
}

// NewKeySet creates a KeySet from a map of KID → private key.
func NewKeySet(keys map[string]*rsa.PrivateKey) *KeySet {
	return &KeySet{keys: keys}
}

// FromRegistration creates a KeySet from a single Registration.
func FromRegistration(reg *lticore.Registration) *KeySet {
	return NewKeySet(map[string]*rsa.PrivateKey{
		reg.KID: reg.ToolPrivateKey,
	})
}

// AddKey adds a new RSA private key to the KeySet with the given KID.
func (ks *KeySet) AddKey(kid string, priv *rsa.PrivateKey) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.keys == nil {
		ks.keys = make(map[string]*rsa.PrivateKey)
	}
	ks.keys[kid] = priv
}

// GetPrivateKey retrieves the RSA private key for the given KID, if it exists.
func (ks *KeySet) GetPrivateKey(kid string) (*rsa.PrivateKey, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	priv, ok := ks.keys[kid]
	return priv, ok
}

// PublicJWKS encodes the tool's public key set as a JSON JWKS document.
func (ks *KeySet) PublicJWKS() ([]byte, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
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
