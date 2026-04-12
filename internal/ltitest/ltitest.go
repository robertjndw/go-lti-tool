// Package ltitest provides shared test helpers for the go-lti test suite.
// It is an internal package; only tests within github.com/robertjndw/go-lti may import it.
package ltitest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	lti "github.com/robertjndw/go-lti"
)

// NewKey generates a 2048-bit RSA key pair for use in tests.
func NewKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ltitest: failed to generate RSA key: %v", err)
	}
	return key
}

// jwkSet is the minimal JWKS JSON structure.
type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KTY string `json:"kty"`
	ALG string `json:"alg"`
	Use string `json:"use"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewJWKSServer starts a test HTTP server that serves a JWKS containing the
// public half of the given private key under the given kid.
func NewJWKSServer(t *testing.T, kid string, priv *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	pub := &priv.PublicKey
	doc := jwkSet{
		Keys: []jwkKey{{
			KTY: "RSA",
			ALG: "RS256",
			Use: "sig",
			KID: kid,
			N:   base64URLBigInt(pub.N),
			E:   base64URLInt(pub.E),
		}},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("ltitest: failed to marshal JWKS: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv
}

// NewJWKSServerMulti serves multiple keys (kid → private key).
func NewJWKSServerMulti(t *testing.T, keys map[string]*rsa.PrivateKey) *httptest.Server {
	t.Helper()
	var ks []jwkKey
	for kid, priv := range keys {
		pub := &priv.PublicKey
		ks = append(ks, jwkKey{
			KTY: "RSA", ALG: "RS256", Use: "sig",
			KID: kid,
			N:   base64URLBigInt(pub.N),
			E:   base64URLInt(pub.E),
		})
	}
	data, _ := json.Marshal(jwkSet{Keys: ks})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv
}

// NewRegistration returns a test Registration pointing at the given JWKS URL.
func NewRegistration(priv *rsa.PrivateKey, jwksURL string) *lti.Registration {
	return &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-123",
		KeySetURL:      jwksURL,
		AuthLoginURL:   "https://platform.example.com/auth",
		AuthTokenURL:   "https://platform.example.com/token",
		ToolPrivateKey: priv,
		KID:            "platform-key-1",
	}
}

// DefaultClaims returns a minimal valid LtiResourceLinkRequest claim set
// signed for the given registration.
func DefaultClaims(reg *lti.Registration, nonce string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   reg.Issuer,
		"sub":   "user-42",
		"aud":   reg.ClientID,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"nonce": nonce,
		"https://purl.imsglobal.org/spec/lti/claim/message_type":   "LtiResourceLinkRequest",
		"https://purl.imsglobal.org/spec/lti/claim/version":        "1.3.0",
		"https://purl.imsglobal.org/spec/lti/claim/deployment_id":  "deploy-1",
		"https://purl.imsglobal.org/spec/lti/claim/target_link_uri": "https://tool.example.com/launch",
		"https://purl.imsglobal.org/spec/lti/claim/roles":          []string{"http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"},
		"https://purl.imsglobal.org/spec/lti/claim/resource_link":  map[string]any{"id": "resource-link-1", "title": "Test Resource"},
	}
}

// DeepLinkClaims returns a minimal valid LtiDeepLinkingRequest claim set.
func DeepLinkClaims(reg *lti.Registration, nonce string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   reg.Issuer,
		"sub":   "user-42",
		"aud":   reg.ClientID,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"nonce": nonce,
		"https://purl.imsglobal.org/spec/lti/claim/message_type":  "LtiDeepLinkingRequest",
		"https://purl.imsglobal.org/spec/lti/claim/version":       "1.3.0",
		"https://purl.imsglobal.org/spec/lti/claim/deployment_id": "deploy-1",
		"https://purl.imsglobal.org/spec/lti/claim/target_link_uri": "https://tool.example.com/launch",
		"https://purl.imsglobal.org/spec/lti/claim/roles":          []string{},
		"https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings": map[string]any{
			"deep_link_return_url":                   "https://platform.example.com/dl-return",
			"accept_types":                           []string{"ltiResourceLink"},
			"accept_presentation_document_targets":   []string{"iframe"},
		},
	}
}

// SignJWT signs a JWT with the given RSA key and kid.
func SignJWT(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("ltitest: failed to sign JWT: %v", err)
	}
	return signed
}

// SimpleDatastore implements lti.Datastore with a single registration and
// a permissive deployment lookup.
type SimpleDatastore struct {
	Reg *lti.Registration
}

func (s *SimpleDatastore) FindRegistrationByIssuer(_ context.Context, issuer string) (*lti.Registration, error) {
	if s.Reg.Issuer == issuer {
		return s.Reg, nil
	}
	return nil, lti.ErrRegistrationNotFound
}

func (s *SimpleDatastore) FindDeployment(_ context.Context, _, deploymentID string) (*lti.Deployment, error) {
	if deploymentID == "" {
		return nil, lti.ErrDeploymentNotFound
	}
	return &lti.Deployment{DeploymentID: deploymentID}, nil
}

// StrictDatastore only accepts a known deployment ID.
type StrictDatastore struct {
	Reg          *lti.Registration
	DeploymentID string
}

func (s *StrictDatastore) FindRegistrationByIssuer(_ context.Context, issuer string) (*lti.Registration, error) {
	if s.Reg.Issuer == issuer {
		return s.Reg, nil
	}
	return nil, lti.ErrRegistrationNotFound
}

func (s *StrictDatastore) FindDeployment(_ context.Context, _, deploymentID string) (*lti.Deployment, error) {
	if deploymentID == s.DeploymentID {
		return &lti.Deployment{DeploymentID: deploymentID}, nil
	}
	return nil, lti.ErrDeploymentNotFound
}

// SimpleCookieHandler reads/writes cookies stored in a plain map. Suitable for
// tests where you need to simulate a browser's cookie jar across requests.
type SimpleCookieHandler struct {
	jar map[string]string
}

// NewCookieHandler creates a SimpleCookieHandler.
func NewCookieHandler() *SimpleCookieHandler {
	return &SimpleCookieHandler{jar: make(map[string]string)}
}

func (h *SimpleCookieHandler) GetCookie(_ *http.Request, name string) (string, error) {
	v, ok := h.jar[name]
	if !ok {
		return "", http.ErrNoCookie
	}
	return v, nil
}

func (h *SimpleCookieHandler) SetCookie(w http.ResponseWriter, name, value string, maxAge int) {
	h.jar[name] = value
	if w != nil {
		http.SetCookie(w, &http.Cookie{
			Name:   name,
			Value:  value,
			MaxAge: maxAge,
			Path:   "/",
		})
	}
}

// SetRaw sets a cookie value directly (for test setup).
func (h *SimpleCookieHandler) SetRaw(name, value string) {
	h.jar[name] = value
}

// MakeLaunchRequest builds a POST request simulating a platform launch callback
// with the given state and id_token values.
func MakeLaunchRequest(t *testing.T, state, idToken string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/lti/launch", nil)
	req.Form = map[string][]string{
		"state":    {state},
		"id_token": {idToken},
	}
	return req
}

// MakeLoginRequest builds a GET request simulating a platform login initiation.
func MakeLoginRequest(t *testing.T, params map[string]string) *http.Request {
	t.Helper()
	u := "https://tool.example.com/oidc/login?"
	first := true
	for k, v := range params {
		if !first {
			u += "&"
		}
		u += fmt.Sprintf("%s=%s", k, v)
		first = false
	}
	return httptest.NewRequest(http.MethodGet, u, nil)
}

func base64URLBigInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

func base64URLInt(e int) string {
	return base64.RawURLEncoding.EncodeToString(big.NewInt(int64(e)).Bytes())
}
