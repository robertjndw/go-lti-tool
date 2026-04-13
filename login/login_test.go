package login_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	lti "github.com/robertjndw/go-lti"
	"github.com/robertjndw/go-lti/internal/ltitest"
	"github.com/robertjndw/go-lti/login"
)

// newLoginConfig returns a ready-to-use login.Config backed by a simple in-memory store.
func newLoginConfig(t *testing.T) (login.Config, *lti.Registration) {
	t.Helper()
	key := ltitest.NewKey(t)
	reg := &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-abc",
		KeySetURL:      "https://platform.example.com/jwks",
		AuthLoginURL:   "https://platform.example.com/auth",
		AuthTokenURL:   "https://platform.example.com/token",
		ToolPrivateKey: key,
		KID:            "key-1",
	}
	store := ltitest.SimpleDatastore{}
	store.AddRegistration(context.TODO(), *reg)
	return login.Config{
		Datastore:     &store,
		NonceStore:    lti.NewMemoryNonceStore(),
		CookieHandler: ltitest.NewCookieHandler(),
	}, reg
}

// doLogin is a shorthand for calling HandleLogin with a flat parameter map.
func doLogin(t *testing.T, cfg login.Config, params map[string]string) (redirectURL string, cookies []*http.Cookie, err error) {
	t.Helper()
	req := ltitest.MakeLoginRequest(t, params)
	return login.HandleLogin(context.Background(), cfg, req)
}

// parseRedirect returns the parsed redirect URL for inspection.
func parseRedirect(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse redirect URL %q: %v", rawURL, err)
	}
	return u
}

// validParams returns the minimal required login initiation parameters.
func validParams(reg *lti.Registration) map[string]string {
	return map[string]string{
		"iss":             reg.Issuer,
		"login_hint":      "hint-xyz",
		"target_link_uri": "https://tool.example.com/launch",
	}
}

// ── Required parameters ───────────────────────────────────────────────────────

// Spec §4.1.1: iss is a required parameter.
func TestLogin_MissingIss_Rejected(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	params := validParams(reg)
	delete(params, "iss")

	_, _, err := doLogin(t, cfg, params)
	if err == nil {
		t.Error("expected error for missing iss, got nil")
	}
}

// Spec §4.1.1: login_hint is a required parameter.
func TestLogin_MissingLoginHint_Rejected(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	params := validParams(reg)
	delete(params, "login_hint")

	_, _, err := doLogin(t, cfg, params)
	if err == nil {
		t.Error("expected error for missing login_hint, got nil")
	}
}

// Spec §4.1.1: target_link_uri is a required parameter.
func TestLogin_MissingTargetLinkURI_Rejected(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	params := validParams(reg)
	delete(params, "target_link_uri")

	_, _, err := doLogin(t, cfg, params)
	if err == nil {
		t.Error("expected error for missing target_link_uri, got nil")
	}
}

// Spec: if client_id is supplied in the login request it must match the registration.
func TestLogin_ClientIDMismatch_Rejected(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	params := validParams(reg)
	params["client_id"] = "wrong-client"

	_, _, err := doLogin(t, cfg, params)
	if err == nil {
		t.Error("expected error for client_id mismatch, got nil")
	}
}

// Unknown issuer must return an error.
func TestLogin_UnknownIssuer_Rejected(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	params := validParams(reg)
	params["iss"] = "https://unknown-platform.example.com"

	_, _, err := doLogin(t, cfg, params)
	if err == nil {
		t.Error("expected error for unknown issuer, got nil")
	}
}

// ── OIDC authorization redirect parameters ────────────────────────────────────

// Spec §4.1.2: redirect must go to the platform's AuthLoginURL.
func TestLogin_RedirectsToAuthLoginURL(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	redirectURL, _, err := doLogin(t, cfg, validParams(reg))
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	if !strings.HasPrefix(redirectURL, reg.AuthLoginURL) {
		t.Errorf("redirect URL %q must start with AuthLoginURL %q", redirectURL, reg.AuthLoginURL)
	}
}

// Spec §4.1.2: scope must be "openid".
func TestLogin_RedirectHasOpenIDScope(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	rawURL, _, err := doLogin(t, cfg, validParams(reg))
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Get("scope") != "openid" {
		t.Errorf("scope = %q, want openid", u.Query().Get("scope"))
	}
}

// Spec §4.1.2: response_type must be "id_token".
func TestLogin_RedirectHasResponseTypeIDToken(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	rawURL, _, err := doLogin(t, cfg, validParams(reg))
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Get("response_type") != "id_token" {
		t.Errorf("response_type = %q, want id_token", u.Query().Get("response_type"))
	}
}

// Spec §4.1.2: response_mode must be "form_post".
func TestLogin_RedirectHasResponseModeFormPost(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	rawURL, _, err := doLogin(t, cfg, validParams(reg))
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Get("response_mode") != "form_post" {
		t.Errorf("response_mode = %q, want form_post", u.Query().Get("response_mode"))
	}
}

// Spec §4.1.2: prompt must be "none".
func TestLogin_RedirectHasPromptNone(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	rawURL, _, err := doLogin(t, cfg, validParams(reg))
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Get("prompt") != "none" {
		t.Errorf("prompt = %q, want none", u.Query().Get("prompt"))
	}
}

// Spec §4.1.2: client_id must match the registration's ClientID.
func TestLogin_RedirectHasClientID(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	rawURL, _, err := doLogin(t, cfg, validParams(reg))
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Get("client_id") != reg.ClientID {
		t.Errorf("client_id = %q, want %q", u.Query().Get("client_id"), reg.ClientID)
	}
}

// Spec §4.1.2: redirect_uri must equal the target_link_uri from the login request.
func TestLogin_RedirectURIEqualsTargetLinkURI(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	target := "https://tool.example.com/launch"
	params := validParams(reg)
	params["target_link_uri"] = target

	rawURL, _, err := doLogin(t, cfg, params)
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Get("redirect_uri") != target {
		t.Errorf("redirect_uri = %q, want %q", u.Query().Get("redirect_uri"), target)
	}
}

// Spec §4.1.2: login_hint must be forwarded unchanged.
func TestLogin_RedirectForwardsLoginHint(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	hint := "user-login-hint-abc"
	params := validParams(reg)
	params["login_hint"] = hint

	rawURL, _, err := doLogin(t, cfg, params)
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Get("login_hint") != hint {
		t.Errorf("login_hint = %q, want %q", u.Query().Get("login_hint"), hint)
	}
}

// Spec §4.1.2: state must be present and non-empty (randomly generated).
func TestLogin_RedirectHasState(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	rawURL, _, err := doLogin(t, cfg, validParams(reg))
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Get("state") == "" {
		t.Error("state must be present and non-empty")
	}
}

// Spec §4.1.2: nonce must be present and non-empty.
func TestLogin_RedirectHasNonce(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	rawURL, _, err := doLogin(t, cfg, validParams(reg))
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Get("nonce") == "" {
		t.Error("nonce must be present and non-empty")
	}
}

// State must be unique per request (two calls must produce different states).
func TestLogin_StateIsUniquePerRequest(t *testing.T) {
	cfg, reg := newLoginConfig(t)

	rawURL1, _, _ := doLogin(t, cfg, validParams(reg))
	rawURL2, _, _ := doLogin(t, cfg, validParams(reg))

	u1 := parseRedirect(t, rawURL1)
	u2 := parseRedirect(t, rawURL2)
	if u1.Query().Get("state") == u2.Query().Get("state") {
		t.Error("state values must differ across requests")
	}
}

// ── State cookie ─────────────────────────────────────────────────────────────

// Spec: A state cookie must be set so the launch handler can verify it.
// The cookie name encodes the state value (lti1p3_<state>).
func TestLogin_SetsCookieWithStateName(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	rawURL, cookies, err := doLogin(t, cfg, validParams(reg))
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}

	u := parseRedirect(t, rawURL)
	state := u.Query().Get("state")
	expectedCookieName := "lti1p3_" + state

	found := false
	for _, c := range cookies {
		if c.Name == expectedCookieName && c.Value == state {
			found = true
			break
		}
	}
	if !found {
		var names []string
		for _, c := range cookies {
			names = append(names, c.Name+"="+c.Value)
		}
		t.Errorf("expected cookie %q=%q; got cookies: %v", expectedCookieName, state, names)
	}
}

// ── Optional parameters ───────────────────────────────────────────────────────

// Spec §4.1.1: lti_message_hint, if provided, must be forwarded to the platform.
func TestLogin_ForwardsLTIMessageHint(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	params := validParams(reg)
	params["lti_message_hint"] = "dl-hint-123"

	rawURL, _, err := doLogin(t, cfg, params)
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Get("lti_message_hint") != "dl-hint-123" {
		t.Errorf("lti_message_hint not forwarded: got %q", u.Query().Get("lti_message_hint"))
	}
}

// When client_id is present and matches the registration it should be accepted.
func TestLogin_MatchingClientID_Accepted(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	params := validParams(reg)
	params["client_id"] = reg.ClientID

	_, _, err := doLogin(t, cfg, params)
	if err != nil {
		t.Errorf("expected success when client_id matches, got %v", err)
	}
}

// Spec §4.1.1: lti_deployment_id, if provided, must be forwarded to the platform.
func TestLogin_ForwardsLTIDeploymentID(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	params := validParams(reg)
	params["lti_deployment_id"] = "deploy-99"

	rawURL, _, err := doLogin(t, cfg, params)
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Get("lti_deployment_id") != "deploy-99" {
		t.Errorf("lti_deployment_id not forwarded: got %q", u.Query().Get("lti_deployment_id"))
	}
}

// lti_deployment_id must NOT appear in the redirect when absent from the login request.
func TestLogin_OmitsLTIDeploymentIDWhenNotProvided(t *testing.T) {
	cfg, reg := newLoginConfig(t)

	rawURL, _, err := doLogin(t, cfg, validParams(reg))
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u := parseRedirect(t, rawURL)
	if u.Query().Has("lti_deployment_id") {
		t.Errorf("lti_deployment_id must not appear when not provided, got %q", u.Query().Get("lti_deployment_id"))
	}
}

// ── login.Handler middleware ──────────────────────────────────────────────────

// Handler must redirect (302) and set the state cookie on a valid login request.
func TestLogin_Handler_ValidRequest_Redirects(t *testing.T) {
	cfg, reg := newLoginConfig(t)

	req := ltitest.MakeLoginRequest(t, validParams(reg))
	w := httptest.NewRecorder()
	login.Handler(cfg).ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("expected 302 Found, got %d: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected Location header in redirect response")
	}
	if !strings.HasPrefix(loc, reg.AuthLoginURL) {
		t.Errorf("Location %q must start with AuthLoginURL %q", loc, reg.AuthLoginURL)
	}
	// State cookie must be set.
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, "lti1p3_") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a lti1p3_<state> cookie to be set on the response")
	}
}

// Handler must return 400 Bad Request for an invalid login request (missing iss).
func TestLogin_Handler_InvalidRequest_Returns400(t *testing.T) {
	cfg, reg := newLoginConfig(t)

	params := validParams(reg)
	delete(params, "iss")
	req := ltitest.MakeLoginRequest(t, params)
	w := httptest.NewRecorder()
	login.Handler(cfg).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", w.Code)
	}
}
