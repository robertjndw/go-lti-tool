package jwks_test

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	lti "github.com/robertjndw/go-lti"
	"github.com/robertjndw/go-lti/internal/ltitest"
	"github.com/robertjndw/go-lti/jwks"
)

func newReg(t *testing.T, kid string) (*lti.Registration, *rsa.PrivateKey) {
	t.Helper()
	key := ltitest.NewKey(t)
	return &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-abc",
		KeySetURL:      "https://platform.example.com/jwks",
		AuthLoginURL:   "https://platform.example.com/auth",
		AuthTokenURL:   "https://platform.example.com/token",
		ToolPrivateKey: key,
		KID:            kid,
	}, key
}

// ── PublicJWKS ────────────────────────────────────────────────────────────────

// The JWKS document must contain the registered key with the correct fields.
func TestPublicJWKS_ContainsRegisteredKey(t *testing.T) {
	reg, _ := newReg(t, "key-1")
	ks := jwks.FromRegistration(reg)
	data, err := ks.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS failed: %v", err)
	}
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to unmarshal JWKS: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k["kid"] != "key-1" {
		t.Errorf("kid = %q, want key-1", k["kid"])
	}
	if k["kty"] != "RSA" {
		t.Errorf("kty = %q, want RSA", k["kty"])
	}
	if k["alg"] != "RS256" {
		t.Errorf("alg = %q, want RS256", k["alg"])
	}
	if k["use"] != "sig" {
		t.Errorf("use = %q, want sig", k["use"])
	}
	if k["n"] == "" {
		t.Error("n (modulus) must be present and non-empty")
	}
	if k["e"] == "" {
		t.Error("e (exponent) must be present and non-empty")
	}
}

// Multiple keys must all appear in the JWKS output.
func TestPublicJWKS_MultipleKeys(t *testing.T) {
	key1 := ltitest.NewKey(t)
	key2 := ltitest.NewKey(t)
	ks := jwks.NewKeySet(map[string]*rsa.PrivateKey{
		"kid-1": key1,
		"kid-2": key2,
	})
	data, err := ks.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS failed: %v", err)
	}
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to unmarshal JWKS: %v", err)
	}
	if len(doc.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(doc.Keys))
	}
	kids := map[string]bool{}
	for _, k := range doc.Keys {
		kids[k["kid"]] = true
	}
	for _, want := range []string{"kid-1", "kid-2"} {
		if !kids[want] {
			t.Errorf("kid %q not found in JWKS", want)
		}
	}
}

// JWKS output must not include any private key material.
func TestPublicJWKS_NoPrivateKeyMaterial(t *testing.T) {
	reg, _ := newReg(t, "key-1")
	ks := jwks.FromRegistration(reg)
	data, err := ks.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS failed: %v", err)
	}
	// RSA private key fields are "d", "p", "q", "dp", "dq", "qi".
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	keys, _ := raw["keys"].([]any)
	for _, kRaw := range keys {
		k, _ := kRaw.(map[string]any)
		for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, found := k[priv]; found {
				t.Errorf("private key field %q must not appear in JWKS output", priv)
			}
		}
	}
}

// ── JWKS HTTP handler ─────────────────────────────────────────────────────────

// Handler must respond with status 200 and Content-Type: application/json.
func TestHandler_ContentTypeJSON(t *testing.T) {
	reg, _ := newReg(t, "key-1")
	ks := jwks.FromRegistration(reg)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	ks.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// Handler must return a valid JSON JWKS with a non-empty "keys" array.
func TestHandler_ResponseIsValidJWKS(t *testing.T) {
	reg, _ := newReg(t, "key-1")
	ks := jwks.FromRegistration(reg)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	ks.Handler().ServeHTTP(w, r)

	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, w.Body.String())
	}
	if len(doc.Keys) == 0 {
		t.Error("keys array must not be empty")
	}
}

// FromRegistration must use the registration's KID as the key identifier.
func TestFromRegistration_UsesRegistrationKID(t *testing.T) {
	reg, _ := newReg(t, "my-special-kid")
	ks := jwks.FromRegistration(reg)
	data, err := ks.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS failed: %v", err)
	}
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	json.Unmarshal(data, &doc) //nolint:errcheck
	if len(doc.Keys) != 1 || doc.Keys[0]["kid"] != "my-special-kid" {
		t.Errorf("expected kid=my-special-kid in JWKS, got %v", doc.Keys)
	}
}
