package lti

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/robertjndw/go-lti/dynreg"
	lticore "github.com/robertjndw/go-lti/internal/lticore"
	"github.com/robertjndw/go-lti/jwks"
	"github.com/robertjndw/go-lti/launch"
	"github.com/robertjndw/go-lti/login"
)

// Tool is the main entry point for an LTI 1.3 tool. It wires together a
// datastore, nonce store, launch data store and cookie handler into
// ready-to-use http.Handlers.
type Tool struct {
	dataStore       lticore.Datastore
	nonceStore      lticore.NonceStore
	launchDataStore lticore.LaunchDataStore
	cookieHandler   lticore.CookieHandler
	keySet          jwks.KeySetProvider
}

// NewTool creates a Tool pre-configured with in-memory stores and the default cookie handler.
// Override any component with the With* option functions.
func NewTool(opts ...ToolOption) *Tool {
	t := &Tool{
		dataStore:       NewMemoryStore(),
		nonceStore:      NewMemoryNonceStore(),
		launchDataStore: NewMemoryLaunchDataStore(),
		cookieHandler:   DefaultCookieHandler{},
		keySet:          nil, // Must be set with WithKeySet to serve JWKS.
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// LaunchFromContext extracts the *Launch stored by HandleLaunch from a request context.
// Returns false if the middleware was not applied or validation failed.
func LaunchFromContext(ctx context.Context) (*Launch, bool) {
	return launch.FromContext(ctx)
}

// GetLaunch retrieves previously cached launch data by launch ID.
// Useful for restoring launch context in subsequent requests (e.g. after deep-link content selection).
func (t *Tool) GetLaunch(ctx context.Context, launchID string) (*Launch, error) {
	return t.launchDataStore.GetLaunchData(ctx, launchID)
}

// HandleLogin returns an http.Handler for the OIDC login initiation endpoint.
// It validates the incoming request, sets the state cookie, and redirects to
// the platform's OIDC authorization endpoint.
func (t *Tool) HandleLogin() http.Handler {
	return login.Handler(login.Config{
		Datastore:     t.dataStore,
		NonceStore:    t.nonceStore,
		CookieHandler: t.cookieHandler,
	})
}

// HandleJWKS returns an http.Handler that serves the tool's public JWKS.
// Configure the key set with WithKeySet. If no key set was configured, responds with 501 Not Implemented.
// The JWKS document is serialized once at handler construction time, not on every request.
func (t *Tool) HandleJWKS() http.Handler {
	if t.keySet == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "JWKS not configured: use WithKeySet", http.StatusNotImplemented)
		})
	}
	data, err := t.keySet.PublicJWKS()
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, fmt.Sprintf("failed to build JWKS: %v", err), http.StatusInternalServerError)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data) //nolint:errcheck
	})
}

// HandleLaunch returns an http.Handler middleware that validates an LTI launch
// POST, caches the resulting LaunchData, and makes it available via FromContext
// before calling next.
func (t *Tool) HandleLaunch(next http.Handler) http.Handler {
	return launch.Handler(launch.Config{
		Datastore:     t.dataStore,
		NonceStore:    t.nonceStore,
		LaunchStore:   t.launchDataStore,
		CookieHandler: t.cookieHandler,
	}, next)
}

// ToolProfile describes the tool to a platform.
// Required for dynamic registration; optional but encouraged otherwise
// (it documents the tool's intended URIs in one place).
type ToolProfile struct {
	Name   string
	Domain string
	// JWKSBaseURL overrides Domain when building the JWKS URI advertised to the
	// platform. Set this when the platform's server must reach the tool via a
	// different hostname than the browser — for example, when Moodle runs in
	// Docker and must fetch JWKS via host.docker.internal while the browser uses
	// localhost. If empty, Domain is used.
	JWKSBaseURL string
	// AllowInsecureOpenIDConfigURL permits incoming openid_configuration URLs to
	// use http. This should stay false for production and only be enabled for
	// local development platforms that do not expose HTTPS.
	AllowInsecureOpenIDConfigURL bool
	KID                          string // Key ID for the tool's signing key, used in the JWT "kid" header and JWKS "kid" field.
	LoginPath                    string
	JWKSPath                     string
	RedirectPaths                []string
	TargetLinkPath               string

	// Optional placement/scope config
	Claims           []string
	Scopes           []string
	Messages         []ToolMessage
	CustomParameters map[string]string
	SecondaryDomains []string

	// Optional metadata (shown in platform admin UIs)
	Description string
	LogoURI     string
	Contacts    []string
	ClientURI   string
	TOSURI      string
	PolicyURI   string
}

// HandleDynamicRegistration returns an http.Handler for the LTI Dynamic
// Registration endpoint (spec: https://www.imsglobal.org/spec/lti-dr/v1p0).
//
// The platform opens this URL in an iframe or new tab with an
// openid_configuration query parameter (and an optional registration_token).
// The handler fetches the platform's OpenID Provider Configuration, POSTs a
// client registration request, persists the resulting Registration via
// cfg.RegistrationStore, and responds with an HTML page that sends the
// org.imsglobal.lti.close postMessage back to the platform.
//
// cfg carries the tool-specific information that cannot be derived from the
// shared Tool state (tool name, domain, JWKS URI, login URI, signing key, etc.).
// Set cfg.RegistrationStore to persist the incoming registration — typically
// the same store used with WithDataStore, which implements RegistrationStore
// when using MemoryStore or a compatible backend.
func (t *Tool) HandleDynamicRegistration(profile ToolProfile) http.Handler {
	if t.keySet == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "JWKS not configured: use WithKeySet", http.StatusInternalServerError)
		})
	}
	key, ok := t.keySet.GetPrivateKey(profile.KID)
	if !ok {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, fmt.Sprintf("key not found for KID %q: check tool configuration", profile.KID), http.StatusInternalServerError)
		})
	}

	redirectURIs := make([]string, len(profile.RedirectPaths))
	for i, p := range profile.RedirectPaths {
		redirectURIs[i], _ = url.JoinPath(profile.Domain, p)
	}

	jwksBase := profile.Domain
	if profile.JWKSBaseURL != "" {
		jwksBase = profile.JWKSBaseURL
	}

	// ToolDomain must be a bare hostname (no scheme/path) per the LTI DR spec.
	toolDomain := profile.Domain
	if u, err := url.Parse(profile.Domain); err == nil && u.Host != "" {
		toolDomain = u.Host
	}

	jwksURI, _ := url.JoinPath(jwksBase, profile.JWKSPath)
	loginURI, _ := url.JoinPath(profile.Domain, profile.LoginPath)
	targetURI, _ := url.JoinPath(profile.Domain, profile.TargetLinkPath)

	cfg := dynreg.DynRegConfig{
		ToolName:                     profile.Name,
		ToolDomain:                   toolDomain,
		RegistrationStore:            t.dataStore, // Must be set by caller to persist the registration
		InitiateLoginUri:             loginURI,
		JWKSUri:                      jwksURI,
		TargetLinkUri:                targetURI,
		RedirectURIs:                 redirectURIs,
		AllowInsecureOpenIDConfigURL: profile.AllowInsecureOpenIDConfigURL,

		KID:     profile.KID,
		ToolKey: key,

		// Optional placement/scope config
		Claims:           profile.Claims,
		Scopes:           profile.Scopes,
		Messages:         profile.Messages,
		CustomParameters: profile.CustomParameters,
		SecondaryDomains: profile.SecondaryDomains,

		// Metadata fields
		Description: profile.Description,
		LogoURI:     profile.LogoURI,
		Contacts:    profile.Contacts,
		ClientURI:   profile.ClientURI,
		TOSURI:      profile.TOSURI,
		PolicyURI:   profile.PolicyURI,
	}
	return dynreg.Handler(cfg)
}
