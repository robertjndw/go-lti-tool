// Package login handles LTI 1.3 OIDC third-party initiated login (step 1 of the launch flow).
//
// When a platform wants to launch a tool it sends the user to the tool's login
// initiation endpoint. This package validates that request, creates a state
// cookie and a nonce, and redirects the user to the platform's OIDC
// authorization endpoint so the platform can issue a signed id_token.
package login

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	lticore "github.com/robertjndw/go-lti-tool/internal/lticore"
	"github.com/robertjndw/go-lti-tool/internal/randutil"
)

// Config holds the dependencies for the OIDC login initiation handler.
type Config struct {
	// Datastore resolves the platform Registration from the issuer URL.
	Datastore lticore.Datastore

	// NonceStore is used to store the generated nonce so it can be verified
	// later during launch validation.
	NonceStore lticore.NonceStore

	// CookieHandler reads/writes state cookies. Defaults to lticore.DefaultCookieHandler
	// if nil.
	CookieHandler lticore.CookieHandler

	// AllowedRedirectHosts optionally restricts the host of the (unsigned)
	// target_link_uri login parameter, which is forwarded to the platform as the
	// OIDC redirect_uri. Platforms must reject unregistered redirect URIs, but
	// validating here follows the IMS security guidance of never trusting the
	// unsigned login request. Empty means no restriction.
	AllowedRedirectHosts []string

	// RequireHTTPSTargetLinkURI rejects a login initiation whose target_link_uri
	// is not https. The 1EdTech Security Framework requires TLS for LTI messages
	// and resource URLs; this defaults to false to keep local-development http
	// tools working, and should be enabled for spec-strict/production deployments.
	RequireHTTPSTargetLinkURI bool
}

func (c *Config) cookieHandler() lticore.CookieHandler {
	if c.CookieHandler != nil {
		return c.CookieHandler
	}
	return lticore.DefaultCookieHandler{}
}

// Handler returns an http.Handler that processes OIDC login initiation requests
// (GET or POST) and redirects to the platform's OIDC authorization endpoint.
func Handler(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL, cookies, err := HandleLogin(r.Context(), cfg, r)
		if err != nil {
			log.Printf("lti/login: %v", err)
			status := http.StatusBadRequest
			if errors.Is(err, lticore.ErrRegistrationNotFound) {
				status = http.StatusForbidden
			}
			http.Error(w, "login initiation failed", status)
			return
		}
		for _, c := range cookies {
			http.SetCookie(w, c)
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})
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

	if err := validateTargetLinkURI(targetLinkURI, cfg.AllowedRedirectHosts, cfg.RequireHTTPSTargetLinkURI); err != nil {
		return "", nil, err
	}

	// Resolve the registration by issuer and, when the platform supplied it,
	// client_id — issuers like cloud Canvas host many registrations.
	reg, err := lticore.FindRegistration(ctx, cfg.Datastore, iss, clientID)
	if err != nil {
		return "", nil, fmt.Errorf("lti/login: %w", err)
	}

	state, err := randutil.Token(32)
	if err != nil {
		return "", nil, fmt.Errorf("lti/login: failed to generate state: %w", err)
	}
	nonce, err := randutil.Token(32)
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

	cookieValue, err := lticore.EncodeStateCookie(lticore.StateCookieData{
		State:         state,
		Nonce:         nonce,
		TargetLinkURI: targetLinkURI,
	})
	if err != nil {
		return "", nil, fmt.Errorf("lti/login: failed to encode state cookie: %w", err)
	}

	var cookieList []*http.Cookie
	// We collect cookies by using a temporary response writer that captures Set-Cookie headers.
	recorder := &cookieRecorder{}
	if err := ch.SetCookie(recorder, cookieName, cookieValue, 600); err != nil { // 10-minute TTL
		return "", nil, fmt.Errorf("lti/login: failed to set state cookie: %w", err)
	}
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

// validateTargetLinkURI checks the unsigned target_link_uri parameter: it must
// parse as an absolute http(s) URL (or https-only when requireHTTPS is set)
// and, when allowedHosts is non-empty, its host must be in the list.
func validateTargetLinkURI(targetLinkURI string, allowedHosts []string, requireHTTPS bool) error {
	u, err := url.Parse(targetLinkURI)
	if err != nil {
		return fmt.Errorf("lti/login: invalid target_link_uri: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("lti/login: target_link_uri must be an absolute http(s) URL")
	}
	if requireHTTPS && u.Scheme != "https" {
		return fmt.Errorf("lti/login: target_link_uri must use https")
	}
	if u.Host == "" {
		return fmt.Errorf("lti/login: target_link_uri is missing a host")
	}
	if len(allowedHosts) == 0 {
		return nil
	}
	for _, h := range allowedHosts {
		if strings.EqualFold(u.Host, h) || strings.EqualFold(u.Hostname(), h) {
			return nil
		}
	}
	return fmt.Errorf("lti/login: target_link_uri host %q is not in the allowed redirect hosts", u.Host)
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
func (cr *cookieRecorder) Write([]byte) (int, error) { return 0, nil }
func (cr *cookieRecorder) WriteHeader(int)           {}
func (cr *cookieRecorder) Flush() {
	for _, line := range cr.header["Set-Cookie"] {
		if c, err := http.ParseSetCookie(line); err == nil {
			cr.cookies = append(cr.cookies, c)
		}
	}
}
