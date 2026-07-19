package login_test

import (
	"context"
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
	"github.com/robertjndw/go-lti-tool/login"
)

// IMS security guidance: the unsigned target_link_uri should be restricted to
// the tool's own hosts when AllowedRedirectHosts is configured.
func TestLogin_AllowedRedirectHosts_UnknownHost_Rejected(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	cfg.AllowedRedirectHosts = []string{"tool.example.com"}

	params := validParams(reg)
	params["target_link_uri"] = "https://evil.example.com/launch"
	_, _, err := doLogin(t, cfg, params)
	if err == nil {
		t.Error("expected error for target_link_uri host outside the allowlist")
	}
}

func TestLogin_AllowedRedirectHosts_KnownHost_Accepted(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	cfg.AllowedRedirectHosts = []string{"tool.example.com"}

	params := validParams(reg)
	params["target_link_uri"] = "https://tool.example.com/launch"
	if _, _, err := doLogin(t, cfg, params); err != nil {
		t.Errorf("expected success for allowlisted host, got %v", err)
	}
}

// target_link_uri must be an absolute http(s) URL.
func TestLogin_RelativeTargetLinkURI_Rejected(t *testing.T) {
	cfg, reg := newLoginConfig(t)

	params := validParams(reg)
	params["target_link_uri"] = "/launch"
	if _, _, err := doLogin(t, cfg, params); err == nil {
		t.Error("expected error for relative target_link_uri")
	}
}

// One issuer hosting two registrations: the login's client_id parameter must
// select the matching registration for the redirect.
func TestLogin_MultiRegistrationIssuer_ClientIDSelectsRegistration(t *testing.T) {
	iss := "https://canvas.instructure.com"
	store := lti.NewMemoryStore()
	for _, clientID := range []string{"client-a", "client-b"} {
		reg := lti.Registration{
			Issuer:       iss,
			ClientID:     clientID,
			AuthLoginURL: iss + "/api/lti/authorize_redirect",
			AuthTokenURL: iss + "/login/oauth2/token",
			KeySetURL:    iss + "/api/lti/security/jwks",
		}
		if err := store.AddRegistration(context.Background(), reg); err != nil {
			t.Fatal(err)
		}
	}
	cfg := login.Config{
		Datastore:     store,
		NonceStore:    lti.NewMemoryNonceStore(),
		CookieHandler: ltitest.NewCookieHandler(),
	}

	params := map[string]string{
		"iss":             iss,
		"login_hint":      "hint",
		"target_link_uri": "https://tool.example.com/launch",
		"client_id":       "client-b",
	}
	redirectURL, _, err := doLogin(t, cfg, params)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if got := parseRedirect(t, redirectURL).Query().Get("client_id"); got != "client-b" {
		t.Errorf("redirect client_id = %q, want client-b", got)
	}

	// Without a client_id the issuer is ambiguous and the login must fail.
	delete(params, "client_id")
	if _, _, err := doLogin(t, cfg, params); err == nil {
		t.Error("expected error for ambiguous issuer without client_id")
	}
}
