package lti_test

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
	"github.com/robertjndw/go-lti-tool/launch"
	"github.com/robertjndw/go-lti-tool/login"
)

// toolFixture wires a Registration + Datastore usable across the tests in
// this file; each test builds its own Tool with the ToolOptions it wants to
// exercise.
type toolFixture struct {
	platformKey *rsa.PrivateKey
	reg         *lti.Registration
	ds          *ltitest.SimpleDatastore
}

func newToolFixture(t *testing.T) *toolFixture {
	t.Helper()
	platformKey := ltitest.NewKey(t)
	toolKey := ltitest.NewKey(t)
	jwksSrv := ltitest.NewJWKSServer(t, "platform-kid-1", platformKey)
	reg := ltitest.NewRegistration(toolKey, jwksSrv.URL)
	ds := &ltitest.SimpleDatastore{}
	if err := ds.AddRegistration(context.Background(), *reg); err != nil {
		t.Fatalf("AddRegistration: %v", err)
	}
	return &toolFixture{platformKey: platformKey, reg: reg, ds: ds}
}

func (f *toolFixture) token(t *testing.T, nonce string, override func(jwt.MapClaims)) string {
	t.Helper()
	claims := ltitest.DefaultClaims(f.reg, nonce)
	if override != nil {
		override(claims)
	}
	return ltitest.SignJWT(t, f.platformKey, "platform-kid-1", claims)
}

func doLaunch(t *testing.T, tool *lti.Tool, state, idToken string) *httptest.ResponseRecorder {
	t.Helper()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := ltitest.MakeLaunchRequest(t, state, idToken)
	rec := httptest.NewRecorder()
	tool.HandleLaunch(next).ServeHTTP(rec, req)
	return rec
}

// A multi-audience token carrying an audience the tool does not trust must
// fail on a default Tool, and succeed once WithTrustedAudiences names it.
func TestTool_WithTrustedAudiences(t *testing.T) {
	f := newToolFixture(t)

	buildTool := func(opts ...lti.ToolOption) (*lti.Tool, *lti.MemoryNonceStore, *ltitest.SimpleCookieHandler) {
		nonces := lti.NewMemoryNonceStore()
		cookies := ltitest.NewCookieHandler()
		base := []lti.ToolOption{
			lti.WithDataStore(f.ds),
			lti.WithNonceStore(nonces),
			lti.WithLaunchDataStore(lti.NewMemoryLaunchDataStore()),
			lti.WithCookieHandler(cookies),
		}
		return lti.NewTool(append(base, opts...)...), nonces, cookies
	}

	overrideMultiAud := func(c jwt.MapClaims) {
		c["aud"] = []string{f.reg.ClientID, "other-app"}
		c["azp"] = f.reg.ClientID
	}

	t.Run("untrusted audience rejected by default", func(t *testing.T) {
		tool, nonces, cookies := buildTool()
		nonce := "nonce-untrusted"
		if err := nonces.StoreNonce(context.Background(), nonce); err != nil {
			t.Fatalf("StoreNonce: %v", err)
		}
		cookies.SetRaw("lti1p3_state-1", "state-1")
		rec := doLaunch(t, tool, "state-1", f.token(t, nonce, overrideMultiAud))
		if rec.Code == http.StatusOK {
			t.Fatalf("expected failure for untrusted extra audience on default Tool, got 200")
		}
	})

	t.Run("trusted audience accepted with WithTrustedAudiences", func(t *testing.T) {
		tool, nonces, cookies := buildTool(lti.WithTrustedAudiences("other-app"))
		nonce := "nonce-trusted"
		if err := nonces.StoreNonce(context.Background(), nonce); err != nil {
			t.Fatalf("StoreNonce: %v", err)
		}
		cookies.SetRaw("lti1p3_state-2", "state-2")
		rec := doLaunch(t, tool, "state-2", f.token(t, nonce, overrideMultiAud))
		if rec.Code != http.StatusOK {
			t.Errorf("expected success with WithTrustedAudiences, got %d", rec.Code)
		}
	})
}

// WithLaunchConfig must let a caller override a knob the dedicated With*
// options don't cover (MaxTokenAge), applied after the Tool's own wiring.
func TestTool_WithLaunchConfig_MaxTokenAge(t *testing.T) {
	f := newToolFixture(t)
	nonces := lti.NewMemoryNonceStore()
	cookies := ltitest.NewCookieHandler()
	tool := lti.NewTool(
		lti.WithDataStore(f.ds),
		lti.WithNonceStore(nonces),
		lti.WithLaunchDataStore(lti.NewMemoryLaunchDataStore()),
		lti.WithCookieHandler(cookies),
		lti.WithLaunchConfig(func(c *launch.Config) {
			c.MaxTokenAge = -1
		}),
	)

	nonce := "nonce-old-iat"
	if err := nonces.StoreNonce(context.Background(), nonce); err != nil {
		t.Fatalf("StoreNonce: %v", err)
	}
	cookies.SetRaw("lti1p3_state-old", "state-old")
	token := f.token(t, nonce, func(c jwt.MapClaims) {
		c["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	})

	rec := doLaunch(t, tool, "state-old", token)
	if rec.Code != http.StatusOK {
		t.Errorf("expected success with MaxTokenAge disabled, got %d", rec.Code)
	}
}

// WithLoginConfig must let a caller mutate the login.Config the Tool
// builds, applied after the Tool's own wiring. Exercised here via
// AllowedRedirectHosts (already available on login.Config) to prove fn
// actually runs against the real config, independent of the dedicated
// WithAllowedRedirectHosts option.
func TestTool_WithLoginConfig_Runs(t *testing.T) {
	ds := &ltitest.SimpleDatastore{}
	reg := &lti.Registration{
		Issuer:       "https://platform.example.com",
		ClientID:     "client-123",
		AuthLoginURL: "https://platform.example.com/auth",
	}
	if err := ds.AddRegistration(context.Background(), *reg); err != nil {
		t.Fatalf("AddRegistration: %v", err)
	}

	tool := lti.NewTool(
		lti.WithDataStore(ds),
		lti.WithNonceStore(lti.NewMemoryNonceStore()),
		lti.WithLoginConfig(func(c *login.Config) {
			c.AllowedRedirectHosts = []string{"allowed.example.com"}
		}),
	)

	req := ltitest.MakeLoginRequest(t, map[string]string{
		"iss":             reg.Issuer,
		"login_hint":      "user-1",
		"target_link_uri": "https://not-allowed.example.com/launch",
	})
	rec := httptest.NewRecorder()
	tool.HandleLogin().ServeHTTP(rec, req)

	if rec.Code == http.StatusFound {
		t.Errorf("expected rejection of disallowed redirect host via WithLoginConfig, got %d", rec.Code)
	}
}
