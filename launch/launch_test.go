package launch_test

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	lti "github.com/robertjndw/go-lti"
	"github.com/robertjndw/go-lti/internal/ltitest"
	"github.com/robertjndw/go-lti/launch"
)

// ── Test fixtures ─────────────────────────────────────────────────────────────

type fixture struct {
	platformKey *rsa.PrivateKey
	toolKey     *rsa.PrivateKey
	reg         *lti.Registration
	ds          *ltitest.SimpleDatastore
	nonces      *lti.MemoryNonceStore
	launches    *lti.MemoryLaunchDataStore
	cookies     *ltitest.SimpleCookieHandler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	platformKey := ltitest.NewKey(t)
	toolKey := ltitest.NewKey(t)
	jwksSrv := ltitest.NewJWKSServer(t, "platform-kid-1", platformKey)
	reg := ltitest.NewRegistration(toolKey, jwksSrv.URL)
	return &fixture{
		platformKey: platformKey,
		toolKey:     toolKey,
		reg:         reg,
		ds:          &ltitest.SimpleDatastore{Reg: reg},
		nonces:      lti.NewMemoryNonceStore(),
		launches:    lti.NewMemoryLaunchDataStore(),
		cookies:     ltitest.NewCookieHandler(),
	}
}

func (f *fixture) cfg() launch.Config {
	return launch.Config{
		Datastore:     f.ds,
		NonceStore:    f.nonces,
		LaunchStore:   f.launches,
		CookieHandler: f.cookies,
	}
}

// validToken signs a minimal LtiResourceLinkRequest JWT with optional overrides.
func (f *fixture) validToken(t *testing.T, nonce string, override func(jwt.MapClaims)) string {
	t.Helper()
	claims := ltitest.DefaultClaims(f.reg, nonce)
	if override != nil {
		override(claims)
	}
	return ltitest.SignJWT(t, f.platformKey, "platform-kid-1", claims)
}

func (f *fixture) storeNonce(t *testing.T, nonce string) {
	t.Helper()
	if err := f.nonces.StoreNonce(context.Background(), nonce); err != nil {
		t.Fatalf("storeNonce: %v", err)
	}
}

func (f *fixture) setStateCookie(state string) {
	f.cookies.SetRaw("lti1p3_"+state, state)
}

func (f *fixture) validate(t *testing.T, state, idToken string) (*lti.LaunchData, error) {
	t.Helper()
	req := ltitest.MakeLaunchRequest(t, state, idToken)
	return launch.ValidateLaunch(context.Background(), f.cfg(), req)
}

// ── LTI spec §4.1.3 — State / CSRF protection ────────────────────────────────

// Spec: The Tool MUST validate the state parameter to prevent CSRF.
// A launch without a state must be rejected.
func TestLaunch_MissingState_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-nostate"
	f.storeNonce(t, nonce)
	token := f.validToken(t, nonce, nil)

	_, err := f.validate(t, "", token)
	if !errors.Is(err, lti.ErrInvalidState) {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

// Spec: The state in the POST body must match the state stored in the cookie.
func TestLaunch_StateCookieMismatch_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-mismatch"
	f.storeNonce(t, nonce)
	token := f.validToken(t, nonce, nil)

	f.cookies.SetRaw("lti1p3_legit-state", "legit-state")

	_, err := f.validate(t, "tampered-state", token)
	if !errors.Is(err, lti.ErrInvalidState) {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

// A launch with no id_token in the body must be rejected.
func TestLaunch_MissingIDToken_Rejected(t *testing.T) {
	f := newFixture(t)
	state := "state-notoken"
	f.setStateCookie(state)

	_, err := f.validate(t, state, "")
	if err == nil {
		t.Error("expected error for missing id_token, got nil")
	}
}

// ── LTI spec §5.1.1 — JWT Signature Validation ───────────────────────────────

// Spec: The Tool MUST validate the JWT signature against the platform's JWKS.
// A JWT signed with an unknown key must be rejected.
func TestLaunch_SignedWithWrongKey_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-wrongkey"
	f.storeNonce(t, nonce)
	state := "state-wrongkey"
	f.setStateCookie(state)

	wrongKey := ltitest.NewKey(t) // not registered in the JWKS server
	token := ltitest.SignJWT(t, wrongKey, "platform-kid-1", ltitest.DefaultClaims(f.reg, nonce))

	_, err := f.validate(t, state, token)
	if !errors.Is(err, lti.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

// Spec: A JWT with a tampered payload must not pass signature validation.
func TestLaunch_TamperedPayload_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-tamper"
	f.storeNonce(t, nonce)
	state := "state-tamper"
	f.setStateCookie(state)

	token := f.validToken(t, nonce, nil)

	// Replace the payload segment with a different (malicious) payload.
	parts := strings.Split(token, ".")
	malicious := map[string]any{
		"iss":   f.reg.Issuer,
		"sub":   "admin", // privilege escalation attempt
		"aud":   f.reg.ClientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": nonce,
		"https://purl.imsglobal.org/spec/lti/claim/message_type":   "LtiResourceLinkRequest",
		"https://purl.imsglobal.org/spec/lti/claim/version":        "1.3.0",
		"https://purl.imsglobal.org/spec/lti/claim/deployment_id":  "deploy-1",
		"https://purl.imsglobal.org/spec/lti/claim/roles":          []string{},
		"https://purl.imsglobal.org/spec/lti/claim/resource_link":  map[string]any{"id": "link-1"},
		"https://purl.imsglobal.org/spec/lti/claim/target_link_uri": "https://tool.example.com/launch",
	}
	encoded, _ := json.Marshal(malicious)
	parts[1] = base64.RawURLEncoding.EncodeToString(encoded)
	tamperedToken := strings.Join(parts, ".")

	_, err := f.validate(t, state, tamperedToken)
	if !errors.Is(err, lti.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for tampered payload, got %v", err)
	}
}

// Spec: alg=none (unsigned JWT) must never be accepted.
// Ref: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
func TestLaunch_AlgorithmNone_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-algnone"
	f.storeNonce(t, nonce)
	state := "state-algnone"
	f.setStateCookie(state)

	claims := ltitest.DefaultClaims(f.reg, nonce)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(map[string]any(claims))
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsignedToken := header + "." + payload + "."

	_, err := f.validate(t, state, unsignedToken)
	if !errors.Is(err, lti.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for alg=none, got %v", err)
	}
}

// Spec: A JWT referencing a KID that does not exist in the platform JWKS must be rejected.
func TestLaunch_UnknownKID_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-kid"
	f.storeNonce(t, nonce)
	state := "state-kid"
	f.setStateCookie(state)

	// Use the correct signing key but claim a KID that doesn't exist in the served JWKS.
	token := ltitest.SignJWT(t, f.platformKey, "nonexistent-kid", ltitest.DefaultClaims(f.reg, nonce))

	_, err := f.validate(t, state, token)
	if !errors.Is(err, lti.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for unknown KID, got %v", err)
	}
}

// ── LTI spec §5.1.1 — Standard OIDC claim validation ────────────────────────

// Spec: iss claim must match the registered platform issuer.
func TestLaunch_IssuerMismatch_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-iss"
	f.storeNonce(t, nonce)
	state := "state-iss"
	f.setStateCookie(state)

	// Sign with the correct key but put a different issuer in the claims.
	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		c["iss"] = "https://evil-lms.example.com"
	})

	_, err := f.validate(t, state, token)
	if err == nil {
		t.Error("expected error for iss mismatch, got nil")
	}
}

// Spec: aud claim must contain the tool's client_id (string form).
func TestLaunch_AudienceStringMismatch_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-audmiss"
	f.storeNonce(t, nonce)
	state := "state-audmiss"
	f.setStateCookie(state)

	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		c["aud"] = "wrong-client-id"
	})

	_, err := f.validate(t, state, token)
	if !errors.Is(err, lti.ErrInvalidClaims) {
		t.Errorf("expected ErrInvalidClaims for aud mismatch, got %v", err)
	}
}

// Spec: aud may be an array; the tool's client_id must appear in that array.
func TestLaunch_AudienceArray_ContainsClientID_Accepted(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-audarray"
	f.storeNonce(t, nonce)
	state := "state-audarray"
	f.setStateCookie(state)

	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		c["aud"] = []string{"other-app", f.reg.ClientID, "third-app"}
	})

	ld, err := f.validate(t, state, token)
	if err != nil {
		t.Errorf("expected success for aud array containing client_id, got %v", err)
	}
	if ld == nil {
		t.Error("expected non-nil launch data")
	}
}

// Spec: Expired JWTs (exp in the past) must be rejected.
func TestLaunch_ExpiredJWT_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-exp"
	f.storeNonce(t, nonce)
	state := "state-exp"
	f.setStateCookie(state)

	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		c["exp"] = time.Now().Add(-2 * time.Minute).Unix()
		c["iat"] = time.Now().Add(-5 * time.Minute).Unix()
	})

	_, err := f.validate(t, state, token)
	if err == nil {
		t.Error("expected error for expired JWT, got nil")
	}
}

// Spec: The nonce claim must be present.
func TestLaunch_MissingNonce_Rejected(t *testing.T) {
	f := newFixture(t)
	state := "state-nononce"
	f.setStateCookie(state)

	token := f.validToken(t, "", func(c jwt.MapClaims) {
		delete(c, "nonce")
	})

	_, err := f.validate(t, state, token)
	if !errors.Is(err, lti.ErrMissingClaim) {
		t.Errorf("expected ErrMissingClaim for missing nonce, got %v", err)
	}
}

// ── LTI spec §5.1.2 — Nonce replay attack prevention ────────────────────────

// Spec: The nonce is single-use. Submitting the same id_token twice must fail
// on the second attempt to prevent replay attacks.
// Ref: https://www.imsglobal.org/spec/lti/v1p3/impl/#validating-the-nonce
func TestLaunch_NonceReplay_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-replay"
	f.storeNonce(t, nonce)

	state := "state-replay"
	f.setStateCookie(state)
	token := f.validToken(t, nonce, nil)

	// First launch must succeed and consume the nonce.
	_, err := launch.ValidateLaunch(context.Background(), f.cfg(), ltitest.MakeLaunchRequest(t, state, token))
	if err != nil {
		t.Fatalf("first launch should succeed, got %v", err)
	}

	// Second launch with the same token must be rejected.
	f.setStateCookie(state) // restore cookie for second attempt
	_, err = launch.ValidateLaunch(context.Background(), f.cfg(), ltitest.MakeLaunchRequest(t, state, token))
	if !errors.Is(err, lti.ErrInvalidNonce) {
		t.Errorf("expected ErrInvalidNonce on replay, got %v", err)
	}
}

// ── LTI spec §5.1.3 — Required LTI claims ────────────────────────────────────

// Spec: deployment_id must be present.
func TestLaunch_MissingDeploymentID_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-nodep"
	f.storeNonce(t, nonce)
	state := "state-nodep"
	f.setStateCookie(state)

	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		delete(c, "https://purl.imsglobal.org/spec/lti/claim/deployment_id")
	})

	_, err := f.validate(t, state, token)
	if !errors.Is(err, lti.ErrMissingClaim) {
		t.Errorf("expected ErrMissingClaim for missing deployment_id, got %v", err)
	}
}

// Spec: deployment_id must correspond to a registered deployment.
func TestLaunch_UnknownDeploymentID_Rejected(t *testing.T) {
	toolKey := ltitest.NewKey(t)
	platformKey := ltitest.NewKey(t)
	jwksSrv := ltitest.NewJWKSServer(t, "kid-1", platformKey)
	reg := ltitest.NewRegistration(toolKey, jwksSrv.URL)

	ds := &ltitest.StrictDatastore{Reg: reg, DeploymentID: "known-deploy"}
	nonces := lti.NewMemoryNonceStore()
	cookies := ltitest.NewCookieHandler()

	nonce := "nonce-baddep"
	nonces.StoreNonce(context.Background(), nonce) //nolint:errcheck
	state := "state-baddep"
	cookies.SetRaw("lti1p3_"+state, state)

	claims := ltitest.DefaultClaims(reg, nonce)
	claims["https://purl.imsglobal.org/spec/lti/claim/deployment_id"] = "unknown-deploy"
	token := ltitest.SignJWT(t, platformKey, "kid-1", claims)

	cfg := launch.Config{Datastore: ds, NonceStore: nonces, CookieHandler: cookies}
	_, err := launch.ValidateLaunch(context.Background(), cfg, ltitest.MakeLaunchRequest(t, state, token))
	if !errors.Is(err, lti.ErrDeploymentNotFound) {
		t.Errorf("expected ErrDeploymentNotFound, got %v", err)
	}
}

// Spec: message_type must be present.
func TestLaunch_MissingMessageType_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-nomsgtype"
	f.storeNonce(t, nonce)
	state := "state-nomsgtype"
	f.setStateCookie(state)

	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		delete(c, "https://purl.imsglobal.org/spec/lti/claim/message_type")
	})

	_, err := f.validate(t, state, token)
	if !errors.Is(err, lti.ErrMissingClaim) {
		t.Errorf("expected ErrMissingClaim for missing message_type, got %v", err)
	}
}

// Spec: version must be present.
func TestLaunch_MissingVersion_Rejected(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-nover"
	f.storeNonce(t, nonce)
	state := "state-nover"
	f.setStateCookie(state)

	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		delete(c, "https://purl.imsglobal.org/spec/lti/claim/version")
	})

	_, err := f.validate(t, state, token)
	if !errors.Is(err, lti.ErrMissingClaim) {
		t.Errorf("expected ErrMissingClaim for missing version, got %v", err)
	}
}

// ── Happy paths ───────────────────────────────────────────────────────────────

// A fully valid LtiResourceLinkRequest must succeed and produce correct LaunchData.
func TestLaunch_ValidResourceLinkRequest_Succeeds(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-valid"
	f.storeNonce(t, nonce)
	state := "state-valid"
	f.setStateCookie(state)

	token := f.validToken(t, nonce, nil)

	ld, err := f.validate(t, state, token)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if ld.LaunchID == "" {
		t.Error("LaunchID must be set")
	}
	if ld.Claims.Subject != "user-42" {
		t.Errorf("sub = %q, want user-42", ld.Claims.Subject)
	}
	if ld.Claims.MessageType != lti.MessageTypeResourceLink {
		t.Errorf("message_type = %q, want %q", ld.Claims.MessageType, lti.MessageTypeResourceLink)
	}
	if ld.Claims.Version != lti.LTIVersion {
		t.Errorf("version = %q, want %q", ld.Claims.Version, lti.LTIVersion)
	}
	if ld.Claims.DeploymentID != "deploy-1" {
		t.Errorf("deployment_id = %q, want deploy-1", ld.Claims.DeploymentID)
	}
	if ld.Claims.ResourceLink == nil || ld.Claims.ResourceLink.ID != "resource-link-1" {
		t.Error("resource_link.id must be resource-link-1")
	}
	if !ld.IsResourceLaunch() {
		t.Error("IsResourceLaunch() must be true")
	}
	if ld.IsDeepLinkLaunch() {
		t.Error("IsDeepLinkLaunch() must be false")
	}
	if ld.Registration == nil || ld.Registration.Issuer != f.reg.Issuer {
		t.Error("Registration must be populated")
	}
}

// A valid LtiDeepLinkingRequest must succeed.
func TestLaunch_ValidDeepLinkingRequest_Succeeds(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-dl"
	f.storeNonce(t, nonce)
	state := "state-dl"
	f.setStateCookie(state)

	token := ltitest.SignJWT(t, f.platformKey, "platform-kid-1", ltitest.DeepLinkClaims(f.reg, nonce))

	ld, err := f.validate(t, state, token)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !ld.IsDeepLinkLaunch() {
		t.Error("IsDeepLinkLaunch() must be true")
	}
	if !ld.HasDeepLinking() {
		t.Error("HasDeepLinking() must be true")
	}
	if ld.Claims.DeepLinkingSettings == nil {
		t.Error("DeepLinkingSettings must be populated")
	}
}

// ── LaunchData caching ────────────────────────────────────────────────────────

// The LaunchData must be persisted to the LaunchStore and retrievable via FromCache.
func TestLaunch_LaunchDataCachedAndRetrievable(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-cache"
	f.storeNonce(t, nonce)
	state := "state-cache"
	f.setStateCookie(state)
	token := f.validToken(t, nonce, nil)

	ld, err := f.validate(t, state, token)
	if err != nil {
		t.Fatalf("launch failed: %v", err)
	}

	cached, err := launch.FromCache(context.Background(), f.cfg(), ld.LaunchID)
	if err != nil {
		t.Fatalf("FromCache failed: %v", err)
	}
	if cached.LaunchID != ld.LaunchID {
		t.Errorf("cached launch ID = %q, want %q", cached.LaunchID, ld.LaunchID)
	}
}

// ── Handler middleware ────────────────────────────────────────────────────────

// Handler must inject LaunchData into the request context and call next.
func TestLaunch_Handler_InjectsContext(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-handler"
	f.storeNonce(t, nonce)
	state := "state-handler"
	f.setStateCookie(state)
	token := f.validToken(t, nonce, nil)

	var gotLD *lti.LaunchData
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ld, ok := launch.FromContext(r.Context())
		if !ok {
			t.Error("LaunchData missing from context in next handler")
			w.WriteHeader(500)
			return
		}
		gotLD = ld
		w.WriteHeader(200)
	})

	req := ltitest.MakeLaunchRequest(t, state, token)
	w := httptest.NewRecorder()
	launch.Handler(f.cfg(), next).ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if gotLD == nil {
		t.Error("LaunchData must be set in context")
	}
}

// Handler must return 400 and not call next on validation failure.
func TestLaunch_Handler_Returns400OnError(t *testing.T) {
	f := newFixture(t)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	})

	req := ltitest.MakeLaunchRequest(t, "no-state", "not.a.jwt")
	w := httptest.NewRecorder()
	launch.Handler(f.cfg(), next).ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if called {
		t.Error("next must not be called on validation failure")
	}
}

// ── Service endpoint detection ────────────────────────────────────────────────

// HasAGS must be true when the AGS endpoint claim is present with a lineitems URL.
func TestLaunch_HasAGS_WhenLineitemsPresent(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-ags"
	f.storeNonce(t, nonce)
	state := "state-ags"
	f.setStateCookie(state)

	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		c["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"] = map[string]any{
			"scope":     []string{lti.ScopeAGSScore, lti.ScopeAGSLineitem},
			"lineitems": "https://platform.example.com/lineitems",
		}
	})

	ld, err := f.validate(t, state, token)
	if err != nil {
		t.Fatalf("launch failed: %v", err)
	}
	if !ld.HasAGS() {
		t.Error("HasAGS() must be true when lineitems URL is present")
	}
}

// HasNRPS must be true when the NRPS endpoint claim is present.
func TestLaunch_HasNRPS_WhenMembershipsURLPresent(t *testing.T) {
	f := newFixture(t)
	nonce := "nonce-nrps"
	f.storeNonce(t, nonce)
	state := "state-nrps"
	f.setStateCookie(state)

	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		c["https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice"] = map[string]any{
			"context_memberships_url": "https://platform.example.com/memberships",
			"service_versions":        []string{"2.0"},
		}
	})

	ld, err := f.validate(t, state, token)
	if err != nil {
		t.Fatalf("launch failed: %v", err)
	}
	if !ld.HasNRPS() {
		t.Error("HasNRPS() must be true when context_memberships_url is present")
	}
}

// ── Key rotation ──────────────────────────────────────────────────────────────

// The SDK must handle JWKS with multiple keys and select the correct one by KID.
func TestLaunch_MultipleKeysInJWKS_SelectsByKID(t *testing.T) {
	toolKey := ltitest.NewKey(t)
	currentKey := ltitest.NewKey(t)
	oldKey := ltitest.NewKey(t)

	jwksSrv := ltitest.NewJWKSServerMulti(t, map[string]*rsa.PrivateKey{
		"current-key": currentKey,
		"old-key":     oldKey,
	})
	reg := ltitest.NewRegistration(toolKey, jwksSrv.URL)
	ds := &ltitest.SimpleDatastore{Reg: reg}
	nonces := lti.NewMemoryNonceStore()
	cookies := ltitest.NewCookieHandler()

	nonce := "nonce-multikey"
	nonces.StoreNonce(context.Background(), nonce) //nolint:errcheck
	state := "state-multikey"
	cookies.SetRaw("lti1p3_"+state, state)

	// JWT signed with the current key only.
	token := ltitest.SignJWT(t, currentKey, "current-key", ltitest.DefaultClaims(reg, nonce))

	cfg := launch.Config{Datastore: ds, NonceStore: nonces, CookieHandler: cookies}
	ld, err := launch.ValidateLaunch(context.Background(), cfg, ltitest.MakeLaunchRequest(t, state, token))
	if err != nil {
		t.Fatalf("expected success with multi-key JWKS, got %v", err)
	}
	if ld == nil {
		t.Error("expected non-nil launch data")
	}
}
