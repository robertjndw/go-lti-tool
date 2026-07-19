package dynreg_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/robertjndw/go-lti-tool/dynreg"
	lticore "github.com/robertjndw/go-lti-tool/internal/lticore"
)

// newPlatformWithConfig starts a TLS platform whose OpenID configuration is
// customised by the mutate function; the registration endpoint echoes back the
// requested scope.
func newPlatformWithConfig(t *testing.T, mutate func(*dynreg.OpenIDConfiguration), capturedScope *string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			cfg := dynreg.OpenIDConfiguration{
				Issuer:                            srv.URL,
				AuthorizationEndpoint:             srv.URL + "/auth",
				RegistrationEndpoint:              srv.URL + "/register",
				JWKSURL:                           srv.URL + "/jwks",
				TokenEndpoint:                     srv.URL + "/token",
				TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
			}
			if mutate != nil {
				mutate(&cfg)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(cfg) //nolint:errcheck

		case "/register":
			var req dynreg.ClientRegistrationRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if capturedScope != nil {
				*capturedScope = req.Scope
			}
			resp := dynreg.ClientRegistrationResponse{ClientID: "client-abc", Scope: req.Scope}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp) //nolint:errcheck

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A platform that does not support private_key_jwt cannot serve LTI Advantage
// calls from this tool; registration must fail up front.
func TestRegister_PlatformWithoutPrivateKeyJWT_Rejected(t *testing.T) {
	srv := newPlatformWithConfig(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.TokenEndpointAuthMethodsSupported = []string{"client_secret_basic"}
	}, nil)

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()

	_, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if err == nil {
		t.Fatal("expected error for platform without private_key_jwt support")
	}
	if !strings.Contains(err.Error(), "private_key_jwt") {
		t.Errorf("error should mention private_key_jwt, got %v", err)
	}
}

// OIDC Discovery: an omitted token_endpoint_auth_methods_supported defaults to
// client_secret_basic only, so it must also be rejected.
func TestRegister_PlatformOmitsAuthMethods_Rejected(t *testing.T) {
	srv := newPlatformWithConfig(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.TokenEndpointAuthMethodsSupported = nil
	}, nil)

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()

	_, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if err == nil {
		t.Fatal("expected error when token_endpoint_auth_methods_supported is omitted")
	}
	if !strings.Contains(err.Error(), "private_key_jwt") {
		t.Errorf("error should mention private_key_jwt, got %v", err)
	}
}

// LTI DR spec: requested scopes should be limited to those the platform
// advertises; openid is always kept.
func TestRegister_ScopesIntersectedWithPlatform(t *testing.T) {
	var capturedScope string
	srv := newPlatformWithConfig(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.ScopesSupported = []string{"openid", lticore.ScopeNRPS}
	}, &capturedScope)

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.Scopes = []string{lticore.ScopeNRPS, lticore.ScopeAGSScore}

	if _, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", ""); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if !strings.Contains(capturedScope, "openid") || !strings.Contains(capturedScope, lticore.ScopeNRPS) {
		t.Errorf("scope %q must keep openid and supported scopes", capturedScope)
	}
	if strings.Contains(capturedScope, lticore.ScopeAGSScore) {
		t.Errorf("scope %q must drop scopes the platform does not support", capturedScope)
	}
}

// When the platform advertises no scopes list, the tool's scopes pass through.
func TestRegister_NoPlatformScopes_AllRequested(t *testing.T) {
	var capturedScope string
	srv := newPlatformWithConfig(t, nil, &capturedScope)

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.Scopes = []string{lticore.ScopeAGSScore}

	if _, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", ""); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if !strings.Contains(capturedScope, lticore.ScopeAGSScore) {
		t.Errorf("scope %q must include requested scope when platform advertises none", capturedScope)
	}
}
