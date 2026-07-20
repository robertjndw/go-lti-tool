package jwks_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
	"github.com/robertjndw/go-lti-tool/jwks"
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

// A Registration with a nil ToolPrivateKey must fail JWKS generation with a
// clean error, not panic (a nil private key is a misconfiguration, but the
// JWKS handler must be able to recover from it and return a 500, not crash).
func TestPublicJWKS_NilPrivateKey_ReturnsError(t *testing.T) {
	ks := jwks.NewKeySet(map[string]*rsa.PrivateKey{"key-1": nil})
	_, err := ks.PublicJWKS()
	if err == nil {
		t.Fatal("expected an error for a nil private key, got nil")
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

// LTI's RS256 key profile requires at least 2048-bit RSA keys. Serving a weak
// key advertises a configuration the rest of the SDK promises not to support.
func TestPublicJWKS_RejectsRSAKeysBelow2048Bits(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak test key: %v", err)
	}
	ks := jwks.NewKeySet(map[string]*rsa.PrivateKey{"weak-key": key})
	if _, err := ks.PublicJWKS(); err == nil {
		t.Error("expected a sub-2048-bit RSA key to be rejected")
	}
}

// Security Framework §6.3 requires each advertised verification key to have
// a kid so a JWT can select the exact key used during rotation.
func TestPublicJWKS_RejectsEmptyKID(t *testing.T) {
	ks := jwks.NewKeySet(map[string]*rsa.PrivateKey{"": ltitest.NewKey(t)})
	if _, err := ks.PublicJWKS(); err == nil {
		t.Error("expected a JWKS key without kid to be rejected")
	}
}
