package lti

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Registration holds all configuration for one tool registered on one platform.
type Registration struct {
	// Issuer is the platform's issuer URL (e.g. "https://canvas.instructure.com").
	Issuer string

	// ClientID is the OAuth2 client_id assigned by the platform.
	ClientID string

	// KeySetURL is the platform's JWKS endpoint URL, used to verify platform-signed JWTs.
	KeySetURL string

	// AuthTokenURL is the platform's OAuth2 token endpoint, used for service authentication.
	AuthTokenURL string

	// AuthLoginURL is the platform's OIDC authorization endpoint, used during login initiation.
	AuthLoginURL string

	// AuthServer is the audience value for service assertion JWTs. Defaults to AuthTokenURL if empty.
	AuthServer string

	// ToolPrivateKey is the tool's RSA private key used to sign outgoing JWTs.
	ToolPrivateKey *rsa.PrivateKey

	// KID is the key ID sent in the JWT header and advertised in the tool's JWKS.
	// If empty, it is derived as a hash of Issuer+ClientID.
	KID string
}

// EffectiveAuthServer returns the auth server audience: AuthServer if set, otherwise AuthTokenURL.
func (r *Registration) EffectiveAuthServer() string {
	if r.AuthServer != "" {
		return r.AuthServer
	}
	return r.AuthTokenURL
}

// Deployment represents a specific instance of a registered tool within a platform context.
type Deployment struct {
	// DeploymentID is the unique deployment identifier assigned by the platform.
	DeploymentID string
}

// ParsePrivateKey parses a PEM-encoded RSA private key (PKCS#1 or PKCS#8).
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("lti: failed to decode PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("lti: PKCS#8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("lti: unsupported PEM block type %q", block.Type)
	}
}
