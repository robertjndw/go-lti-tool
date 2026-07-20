package launch_test

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
)

// countingJWKSServer serves the given kid→key map and counts requests. The
// keys map may be swapped via the swap function to simulate key rotation.
func countingJWKSServer(t *testing.T, keys map[string]*rsa.PrivateKey) (*httptest.Server, *atomic.Int32, func(map[string]*rsa.PrivateKey)) {
	t.Helper()
	var hits atomic.Int32
	var current atomic.Pointer[map[string]*rsa.PrivateKey]
	current.Store(&keys)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var doc struct {
			Keys []map[string]string `json:"keys"`
		}
		for kid, priv := range *current.Load() {
			pub := &priv.PublicKey
			doc.Keys = append(doc.Keys, map[string]string{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	swap := func(k map[string]*rsa.PrivateKey) { current.Store(&k) }
	return srv, &hits, swap
}

// The platform JWKS must be cached across launches instead of re-fetched
// every time.
func TestLaunch_JWKSCachedAcrossLaunches(t *testing.T) {
	f := newFixture(t)
	srv, hits, _ := countingJWKSServer(t, map[string]*rsa.PrivateKey{"platform-kid-1": f.platformKey})
	f.reg.KeySetURL = srv.URL
	f.ds.AddRegistration(t.Context(), *f.reg)

	for i, pair := range [][2]string{{"nonce-c1", "state-c1"}, {"nonce-c2", "state-c2"}} {
		f.storeNonce(t, pair[0])
		f.setStateCookie(pair[1])
		token := f.validToken(t, pair[0], nil)
		if _, err := f.validate(t, pair[1], token); err != nil {
			t.Fatalf("launch %d failed: %v", i+1, err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("JWKS endpoint hit %d times across 2 launches, want 1 (cached)", got)
	}
}

// A token signed with an unknown kid must trigger a cache refresh so platform
// key rotation is picked up immediately.
func TestLaunch_KeyRotation_RefreshesCache(t *testing.T) {
	f := newFixture(t)
	srv, _, swap := countingJWKSServer(t, map[string]*rsa.PrivateKey{"platform-kid-1": f.platformKey})
	f.reg.KeySetURL = srv.URL
	f.ds.AddRegistration(t.Context(), *f.reg)

	// Prime the cache with the old key set.
	f.storeNonce(t, "nonce-r1")
	f.setStateCookie("state-r1")
	if _, err := f.validate(t, "state-r1", f.validToken(t, "nonce-r1", nil)); err != nil {
		t.Fatalf("initial launch failed: %v", err)
	}

	// Rotate: new key under a new kid, old key removed.
	newKey := ltitest.NewKey(t)
	swap(map[string]*rsa.PrivateKey{"platform-kid-2": newKey})

	f.storeNonce(t, "nonce-r2")
	f.setStateCookie("state-r2")
	claims := ltitest.DefaultClaims(f.reg, "nonce-r2")
	token := ltitest.SignJWT(t, newKey, "platform-kid-2", claims)
	if _, err := f.validate(t, "state-r2", token); err != nil {
		t.Errorf("launch after key rotation failed: %v", err)
	}
}

// The Security Framework permits an issuer not to use kid, although every key
// in the advertised key set still has one. In that case the receiver must be
// able to find the signing key without weakening signature verification.
func TestLaunch_NoKidHeader_TriesAllKeys(t *testing.T) {
	f := newFixture(t)
	otherKey := ltitest.NewKey(t)
	srv, _, _ := countingJWKSServer(t, map[string]*rsa.PrivateKey{
		"platform-kid-a": otherKey,
		"platform-kid-b": f.platformKey,
	})
	f.reg.KeySetURL = srv.URL
	f.ds.AddRegistration(t.Context(), *f.reg)

	f.storeNonce(t, "nonce-nokid")
	f.setStateCookie("state-nokid")

	claims := ltitest.DefaultClaims(f.reg, "nonce-nokid")
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// No kid header on purpose.
	signed, err := tok.SignedString(f.platformKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := f.validate(t, "state-nokid", signed); err != nil {
		t.Errorf("launch without kid header failed: %v", err)
	}
}
