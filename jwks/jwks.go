// Package jwks provides a JWKS (JSON Web Key Set) endpoint handler that serves
// the tool's public keys so platforms can verify JWT assertions sent by the tool.
package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/robertjndw/go-lti-tool/internal/lticore"
)

// KeySetProvider serves the tool's public JWKS.
// Implement this to supply a custom key backend; *KeySet satisfies it.
type KeySetProvider interface {
	PublicJWKS() ([]byte, error)
}

// PrivateKeyProvider extends KeySetProvider with private-key retrieval,
// needed by components such as dynamic registration.
// *KeySet satisfies this interface.
type PrivateKeyProvider interface {
	KeySetProvider
	GetPrivateKey(kid string) (*rsa.PrivateKey, bool)
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

// GetPrivateKey retrieves the RSA private key for the given KID, if it exists.
func (ks *KeySet) GetPrivateKey(kid string) (*rsa.PrivateKey, bool) {
	priv, ok := ks.keys[kid]
	return priv, ok
}

// PublicJWKS encodes the tool's public key set as a JSON JWKS document.
// Returns an error rather than panicking when a kid maps to a nil private
// key (e.g. a Registration with no ToolPrivateKey) — a misconfigured
// registration must fail JWKS generation cleanly, not crash the handler.
func (ks *KeySet) PublicJWKS() ([]byte, error) {
	doc := jwksDocument{}
	for kid, priv := range ks.keys {
		if kid == "" {
			return nil, fmt.Errorf("jwks: key has an empty kid; the Security Framework requires one so a JWT can select the exact key used during rotation")
		}
		if priv == nil {
			return nil, fmt.Errorf("jwks: no private key configured for kid %q", kid)
		}
		if priv.N.BitLen() < 2048 {
			return nil, fmt.Errorf("jwks: key %q is %d bits, want at least 2048", kid, priv.N.BitLen())
		}
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
