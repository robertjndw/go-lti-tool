package dynreg_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/robertjndw/go-lti-tool/dynreg"
)

// newCapturingPlatform starts a TLS platform whose OpenID configuration is
// customized by mutate, and which captures the decoded registration request
// into capturedReq (if non-nil) before responding.
func newCapturingPlatform(t *testing.T, mutate func(*dynreg.OpenIDConfiguration), capturedReq *dynreg.ClientRegistrationRequest) *httptest.Server {
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
			if capturedReq != nil {
				*capturedReq = req
			}
			resp := dynreg.ClientRegistrationResponse{ClientID: "client-abc"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ── Default-mode discovery compatibility checks ──────────────────────────────

func TestRegister_ResponseTypesSupported_IncompatibleRejected(t *testing.T) {
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.ResponseTypesSupported = []string{"code"}
	}, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	_, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if !errors.Is(err, dynreg.ErrIncompatibleDiscovery) {
		t.Errorf("want ErrIncompatibleDiscovery, got %v", err)
	}
}

func TestRegister_ResponseTypesSupported_OmittedAccepted(t *testing.T) {
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.ResponseTypesSupported = nil
	}, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	if _, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", ""); err != nil {
		t.Errorf("expected omitted response_types_supported to be accepted, got %v", err)
	}
}

func TestRegister_IDTokenSigningAlg_IncompatibleRejected(t *testing.T) {
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.IDTokenSigningAlgValuesSupported = []string{"ES256"}
	}, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	_, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if !errors.Is(err, dynreg.ErrIncompatibleDiscovery) {
		t.Errorf("want ErrIncompatibleDiscovery, got %v", err)
	}
}

func TestRegister_IDTokenSigningAlg_OmittedAccepted(t *testing.T) {
	srv := newCapturingPlatform(t, nil, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	if _, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", ""); err != nil {
		t.Errorf("expected omitted id_token_signing_alg_values_supported to be accepted, got %v", err)
	}
}

func TestRegister_TokenEndpointAuthSigningAlg_IncompatibleRejected(t *testing.T) {
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.TokenEndpointAuthSigningAlgValuesSupported = []string{"ES256"}
	}, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	_, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if !errors.Is(err, dynreg.ErrIncompatibleDiscovery) {
		t.Errorf("want ErrIncompatibleDiscovery, got %v", err)
	}
}

func TestRegister_TokenEndpointAuthSigningAlg_OmittedAccepted(t *testing.T) {
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.TokenEndpointAuthSigningAlgValuesSupported = nil
	}, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	if _, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", ""); err != nil {
		t.Errorf("expected omitted token_endpoint_auth_signing_alg_values_supported to be accepted, got %v", err)
	}
}

// ── StrictDiscovery ───────────────────────────────────────────────────────────

func TestRegister_StrictDiscovery_IncompleteRejected(t *testing.T) {
	srv := newCapturingPlatform(t, nil, nil) // base config omits response_types_supported etc.
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.StrictDiscovery = true
	_, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if !errors.Is(err, dynreg.ErrIncompleteDiscovery) {
		t.Errorf("want ErrIncompleteDiscovery, got %v", err)
	}
}

func TestRegister_StrictDiscovery_CompleteAccepted(t *testing.T) {
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.ResponseTypesSupported = []string{"id_token"}
		cfg.IDTokenSigningAlgValuesSupported = []string{"RS256"}
		cfg.TokenEndpointAuthSigningAlgValuesSupported = []string{"RS256"}
		cfg.ScopesSupported = []string{"openid"}
		cfg.SubjectTypesSupported = []string{"public"}
	}, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.StrictDiscovery = true
	if _, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", ""); err != nil {
		t.Errorf("expected complete discovery metadata to be accepted under StrictDiscovery, got %v", err)
	}
}

func TestRegister_StrictDiscovery_ScopesWithoutOpenID_Rejected(t *testing.T) {
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.ResponseTypesSupported = []string{"id_token"}
		cfg.IDTokenSigningAlgValuesSupported = []string{"RS256"}
		cfg.TokenEndpointAuthSigningAlgValuesSupported = []string{"RS256"}
		cfg.ScopesSupported = []string{"profile"} // missing "openid"
		cfg.SubjectTypesSupported = []string{"public"}
	}, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.StrictDiscovery = true
	_, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	// A non-empty scopes_supported missing "openid" is an affirmative
	// incompatibility, checked regardless of StrictDiscovery.
	if !errors.Is(err, dynreg.ErrIncompatibleDiscovery) {
		t.Errorf("want ErrIncompatibleDiscovery for scopes_supported missing openid, got %v", err)
	}
}

// Default mode: a non-empty scopes_supported omitting "openid" is rejected
// even without StrictDiscovery - a platform MUST support "openid" per OIDC
// Discovery §3 whenever it advertises the field at all.
func TestRegister_DefaultMode_ScopesSupportedWithoutOpenID_Rejected(t *testing.T) {
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.ScopesSupported = []string{"profile"}
	}, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	_, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if !errors.Is(err, dynreg.ErrIncompatibleDiscovery) {
		t.Errorf("want ErrIncompatibleDiscovery, got %v", err)
	}
}

// Default mode: an empty (omitted) scopes_supported is still tolerated.
func TestRegister_DefaultMode_EmptyScopesSupported_Accepted(t *testing.T) {
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.ScopesSupported = nil
	}, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	if _, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", ""); err != nil {
		t.Errorf("expected omitted scopes_supported to be accepted, got %v", err)
	}
}

// StrictDiscovery requires token_endpoint_auth_signing_alg_values_supported
// to be present (this tool needs to know the platform accepts RS256 for
// private_key_jwt client assertions).
func TestRegister_StrictDiscovery_MissingTokenEndpointAuthSigningAlg_Rejected(t *testing.T) {
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.ResponseTypesSupported = []string{"id_token"}
		cfg.IDTokenSigningAlgValuesSupported = []string{"RS256"}
		cfg.ScopesSupported = []string{"openid"}
		cfg.SubjectTypesSupported = []string{"public"}
		cfg.TokenEndpointAuthSigningAlgValuesSupported = nil
	}, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.StrictDiscovery = true
	_, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if !errors.Is(err, dynreg.ErrIncompleteDiscovery) {
		t.Errorf("want ErrIncompleteDiscovery for missing token_endpoint_auth_signing_alg_values_supported, got %v", err)
	}
}

// StrictDiscovery requires subject_types_supported to contain a recognized
// value ("public" or "pairwise" per OIDC Discovery); a list of only
// unrecognized values indicates a malformed discovery document.
func TestRegister_StrictDiscovery_UnrecognizedSubjectType_Rejected(t *testing.T) {
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.ResponseTypesSupported = []string{"id_token"}
		cfg.IDTokenSigningAlgValuesSupported = []string{"RS256"}
		cfg.TokenEndpointAuthSigningAlgValuesSupported = []string{"RS256"}
		cfg.ScopesSupported = []string{"openid"}
		cfg.SubjectTypesSupported = []string{"bogus"}
	}, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.StrictDiscovery = true
	_, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if !errors.Is(err, dynreg.ErrIncompleteDiscovery) {
		t.Errorf("want ErrIncompleteDiscovery for an unrecognized subject_types_supported value, got %v", err)
	}
}

func TestRegister_DefaultMode_AcceptsSameOmissionsStrictWouldReject(t *testing.T) {
	srv := newCapturingPlatform(t, nil, nil)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	// StrictDiscovery left at its default (false).
	if _, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", ""); err != nil {
		t.Errorf("expected default mode to tolerate omitted discovery fields, got %v", err)
	}
}

// ── messages_supported filtering ──────────────────────────────────────────────

func TestRegister_MessagesFilteredByPlatformSupport(t *testing.T) {
	var capturedReq dynreg.ClientRegistrationRequest
	srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
		cfg.LTIPlatformConfiguration = &dynreg.LTIPlatformConfig{
			MessagesSupported: []dynreg.PlatformMessage{{Type: "LtiResourceLinkRequest"}},
		}
	}, &capturedReq)

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.Messages = []dynreg.ToolMessage{
		{Type: "LtiResourceLinkRequest"},
		{Type: "LtiDeepLinkingRequest"},
	}

	if _, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", ""); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if capturedReq.LTIToolConfiguration == nil {
		t.Fatal("expected LTIToolConfiguration in captured request")
	}
	got := capturedReq.LTIToolConfiguration.Messages
	if len(got) != 1 || got[0].Type != "LtiResourceLinkRequest" {
		t.Errorf("messages = %v, want only LtiResourceLinkRequest", got)
	}
}

func TestRegister_MessagesUnfilteredWhenPlatformAdvertisesNone(t *testing.T) {
	var capturedReq dynreg.ClientRegistrationRequest
	srv := newCapturingPlatform(t, nil, &capturedReq)

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.Messages = []dynreg.ToolMessage{
		{Type: "LtiResourceLinkRequest"},
		{Type: "LtiDeepLinkingRequest"},
	}

	if _, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", ""); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if capturedReq.LTIToolConfiguration == nil {
		t.Fatal("expected LTIToolConfiguration in captured request")
	}
	got := capturedReq.LTIToolConfiguration.Messages
	if len(got) != 2 {
		t.Errorf("messages = %v, want both passed through when platform advertises none", got)
	}
}

// ── RegistrationResult exposes RFC 7592 credentials ──────────────────────────

func TestRegister_ExposesRFC7592Credentials(t *testing.T) {
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
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(cfg) //nolint:errcheck
		case "/register":
			resp := dynreg.ClientRegistrationResponse{ClientID: "client-abc"}
			resp.RegistrationClientURI = srv.URL + "/register/client-abc"
			resp.RegistrationAccessToken = "rat-secret"
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp) //nolint:errcheck
		}
	}))
	t.Cleanup(srv.Close)

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()

	result, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if result.RegistrationClientURI != srv.URL+"/register/client-abc" {
		t.Errorf("RegistrationClientURI = %q", result.RegistrationClientURI)
	}
	if result.RegistrationAccessToken != "rat-secret" {
		t.Errorf("RegistrationAccessToken = %q", result.RegistrationAccessToken)
	}
}

// ── RFC 7592 read/update ──────────────────────────────────────────────────────

func TestReadRegistration_RoundTrip(t *testing.T) {
	var gotAuth, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		resp := dynreg.ClientRegistrationResponse{ClientID: "client-abc"}
		resp.ClientName = "Test Tool"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer srv.Close()

	got, err := dynreg.ReadRegistration(context.Background(), srv.Client(), srv.URL, "secret-token")
	if err != nil {
		t.Fatalf("ReadRegistration failed: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %s, want GET", gotMethod)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization header = %q, want Bearer secret-token", gotAuth)
	}
	if got.ClientID != "client-abc" || got.ClientName != "Test Tool" {
		t.Errorf("got %+v", got)
	}
}

func TestReadRegistration_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := dynreg.ReadRegistration(context.Background(), srv.Client(), srv.URL, "bad-token")
	if !errors.Is(err, dynreg.ErrRegistrationFailed) {
		t.Errorf("want ErrRegistrationFailed, got %v", err)
	}
}

func TestUpdateRegistration_RoundTrip(t *testing.T) {
	var gotAuth, gotMethod string
	var gotBody dynreg.ClientRegistrationUpdate
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		resp := dynreg.ClientRegistrationResponse{ClientID: gotBody.ClientID}
		resp.ClientName = gotBody.ClientName
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer srv.Close()

	upd := &dynreg.ClientRegistrationUpdate{ClientID: "client-abc"}
	upd.ClientName = "Updated Name"

	got, err := dynreg.UpdateRegistration(context.Background(), srv.Client(), srv.URL, "secret-token", upd)
	if err != nil {
		t.Fatalf("UpdateRegistration failed: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", gotMethod)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization header = %q, want Bearer secret-token", gotAuth)
	}
	if gotBody.ClientID != "client-abc" {
		t.Errorf("captured update client_id = %q, want client-abc", gotBody.ClientID)
	}
	// registration_access_token/registration_client_uri must not appear in the
	// PUT body (RFC 7592 §2.2).
	if got.ClientName != "Updated Name" {
		t.Errorf("ClientName = %q, want Updated Name", got.ClientName)
	}
}

func TestUpdateRegistration_ExcludesRegistrationCredentialsFromBody(t *testing.T) {
	var rawBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&rawBody)
		resp := dynreg.ClientRegistrationResponse{ClientID: "client-abc"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer srv.Close()

	upd := &dynreg.ClientRegistrationUpdate{ClientID: "client-abc"}
	if _, err := dynreg.UpdateRegistration(context.Background(), srv.Client(), srv.URL, "secret-token", upd); err != nil {
		t.Fatalf("UpdateRegistration failed: %v", err)
	}
	if _, ok := rawBody["registration_access_token"]; ok {
		t.Error("update body must not include registration_access_token")
	}
	if _, ok := rawBody["registration_client_uri"]; ok {
		t.Error("update body must not include registration_client_uri")
	}
}
