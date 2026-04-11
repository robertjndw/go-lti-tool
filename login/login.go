// Package login handles LTI 1.3 OIDC third-party initiated login (step 1 of the launch flow).
//
// When a platform wants to launch a tool it sends the user to the tool's login
// initiation endpoint. This package validates that request, creates a state
// cookie and a nonce, and redirects the user to the platform's OIDC
// authorization endpoint so the platform can issue a signed id_token.
package login

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/robertjndw/go-lti"
)

// Config holds the dependencies for the OIDC login initiation handler.
type Config struct {
	// Datastore resolves the platform Registration from the issuer URL.
	Datastore lti.Datastore

	// NonceStore is used to store the generated nonce so it can be verified
	// later during launch validation.
	NonceStore lti.NonceStore

	// CookieHandler reads/writes state cookies. Defaults to lti.DefaultCookieHandler
	// if nil.
	CookieHandler lti.CookieHandler
}

func (c *Config) cookieHandler() lti.CookieHandler {
	if c.CookieHandler != nil {
		return c.CookieHandler
	}
	return lti.DefaultCookieHandler{}
}

// Handler returns an http.Handler that processes OIDC login initiation requests
// (GET or POST) and redirects to the platform's OIDC authorization endpoint.
func Handler(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL, cookies, err := HandleLogin(r.Context(), cfg, r)
		if err != nil {
			http.Error(w, fmt.Sprintf("LTI login error: %v", err), http.StatusBadRequest)
			return
		}
		for _, c := range cookies {
			http.SetCookie(w, c)
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})
}

// LoginResult contains the redirect URL and cookies produced by a login initiation.
type LoginResult struct {
	// RedirectURL is the platform OIDC authorization URL the user should be sent to.
	RedirectURL string

	// Cookies are the cookies that must be set on the response before redirecting.
	Cookies []*http.Cookie
}

// HandleLogin processes a login initiation request and returns the redirect URL
// and cookies to set. Use this when you need more control than Handler provides
// (e.g. integrating with a specific HTTP framework).
func HandleLogin(ctx context.Context, cfg Config, r *http.Request) (redirectURL string, cookies []*http.Cookie, err error) {
	if err := r.ParseForm(); err != nil {
		return "", nil, fmt.Errorf("lti/login: failed to parse request form: %w", err)
	}

	iss := r.FormValue("iss")
	if iss == "" {
		return "", nil, fmt.Errorf("lti/login: missing required parameter 'iss'")
	}
	loginHint := r.FormValue("login_hint")
	if loginHint == "" {
		return "", nil, fmt.Errorf("lti/login: missing required parameter 'login_hint'")
	}
	targetLinkURI := r.FormValue("target_link_uri")
	if targetLinkURI == "" {
		return "", nil, fmt.Errorf("lti/login: missing required parameter 'target_link_uri'")
	}
	ltiMessageHint := r.FormValue("lti_message_hint")
	clientID := r.FormValue("client_id")
	ltiDeploymentID := r.FormValue("lti_deployment_id")

	reg, err := cfg.Datastore.FindRegistrationByIssuer(ctx, iss)
	if err != nil {
		return "", nil, fmt.Errorf("lti/login: %w", err)
	}

	// If the request supplies a client_id, verify it matches the registration.
	if clientID != "" && clientID != reg.ClientID {
		return "", nil, fmt.Errorf("lti/login: client_id mismatch: got %q, want %q", clientID, reg.ClientID)
	}

	state, err := randomToken(32)
	if err != nil {
		return "", nil, fmt.Errorf("lti/login: failed to generate state: %w", err)
	}
	nonce, err := randomToken(32)
	if err != nil {
		return "", nil, fmt.Errorf("lti/login: failed to generate nonce: %w", err)
	}

	if err := cfg.NonceStore.StoreNonce(ctx, nonce); err != nil {
		return "", nil, fmt.Errorf("lti/login: failed to store nonce: %w", err)
	}

	// Build the state cookie. The cookie name encodes the state value so the
	// launch handler can look it up without a separate session store.
	cookieName := "lti1p3_" + state
	ch := cfg.cookieHandler()

	var cookieList []*http.Cookie
	// We collect cookies by using a temporary response writer that captures Set-Cookie headers.
	recorder := &cookieRecorder{}
	ch.SetCookie(recorder, cookieName, state, 600) // 10-minute TTL
	recorder.Flush()
	cookieList = append(cookieList, recorder.cookies...)

	// Build the OIDC authorization redirect URL.
	params := url.Values{}
	params.Set("scope", "openid")
	params.Set("response_type", "id_token")
	params.Set("response_mode", "form_post")
	params.Set("prompt", "none")
	params.Set("client_id", reg.ClientID)
	params.Set("redirect_uri", targetLinkURI)
	params.Set("login_hint", loginHint)
	params.Set("state", state)
	params.Set("nonce", nonce)
	if ltiMessageHint != "" {
		params.Set("lti_message_hint", ltiMessageHint)
	}
	if ltiDeploymentID != "" {
		params.Set("lti_deployment_id", ltiDeploymentID)
	}

	authURL, err := url.Parse(reg.AuthLoginURL)
	if err != nil {
		return "", nil, fmt.Errorf("lti/login: invalid auth login URL %q: %w", reg.AuthLoginURL, err)
	}
	authURL.RawQuery = params.Encode()

	return authURL.String(), cookieList, nil
}

// randomToken returns a URL-safe random string of n bytes encoded as base64.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// cookieRecorder is a minimal http.ResponseWriter that only captures Set-Cookie calls.
type cookieRecorder struct {
	cookies []*http.Cookie
	header  http.Header
}

func (cr *cookieRecorder) Header() http.Header {
	if cr.header == nil {
		cr.header = make(http.Header)
	}
	return cr.header
}
func (cr *cookieRecorder) Write([]byte) (int, error)      { return 0, nil }
func (cr *cookieRecorder) WriteHeader(int)                 {}
func (cr *cookieRecorder) Flush() {
	for _, line := range cr.header["Set-Cookie"] {
		if c, err := http.ParseSetCookie(line); err == nil {
			cr.cookies = append(cr.cookies, c)
		}
	}
}
