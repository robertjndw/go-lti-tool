package dynreg_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/robertjndw/go-lti-tool/dynreg"
	lticore "github.com/robertjndw/go-lti-tool/internal/lticore"
)

// minimalConfig returns a Config with the required fields populated.
func minimalConfig(t *testing.T) dynreg.DynRegConfig {
	t.Helper()
	return dynreg.DynRegConfig{
		ToolName:         "Test Tool",
		ToolDomain:       "tool.example.com",
		JWKSURL:          "https://tool.example.com/jwks",
		InitiateLoginURL: "https://tool.example.com/login",
		RedirectURIs:     []string{"https://tool.example.com/launch"},
		TargetLinkURL:    "https://tool.example.com/launch",
		Claims:           []string{"sub", "email"},
	}
}

// newPlatform starts a TLS test server acting as a platform.
func newPlatform(t *testing.T, registrationStatus int) *httptest.Server {
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
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(cfg); err != nil {
				t.Errorf("encode OpenID config: %v", err)
			}

		case "/register":
			if registrationStatus != http.StatusOK {
				w.WriteHeader(registrationStatus)
				_, _ = w.Write([]byte(`{"error":"unauthorized_client"}`))
				return
			}
			var req dynreg.ClientRegistrationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode registration request: %v", err)
			}
			resp := dynreg.ClientRegistrationResponse{ClientID: "client-abc"}
			resp.ApplicationType = req.ApplicationType
			resp.GrantTypes = req.GrantTypes
			resp.ResponseTypes = req.ResponseTypes
			resp.RedirectURIs = req.RedirectURIs
			resp.InitiateLoginURI = req.InitiateLoginURI
			resp.ClientName = req.ClientName
			resp.JWKSURL = req.JWKSURL
			resp.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
			resp.Scope = req.Scope
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Errorf("encode registration response: %v", err)
			}

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// stubStore is a minimal RegistrationStore for tests.
type stubStore struct {
	savedReg *lticore.Registration
	savedDep *lticore.Deployment
	err      error
}

func (s *stubStore) AddRegistration(_ context.Context, reg lticore.Registration) error {
	if s.err != nil {
		return s.err
	}
	s.savedReg = &reg
	return nil
}

func (s *stubStore) AddDeployment(_ context.Context, _ string, dep lticore.Deployment) error {
	if s.err != nil {
		return s.err
	}
	s.savedDep = &dep
	return nil
}

func (s *stubStore) FindRegistrationByIssuer(_ context.Context, _ string) (*lticore.Registration, error) {
	return nil, lticore.ErrRegistrationNotFound
}

func (s *stubStore) FindDeployment(_ context.Context, _, _ string) (*lticore.Deployment, error) {
	return nil, lticore.ErrDeploymentNotFound
}

// --- Handler tests ---

func TestHandler_MissingOpenIDConfigParam(t *testing.T) {
	h := dynreg.Handler(minimalConfig(t))
	req := httptest.NewRequest(http.MethodGet, "/dynreg", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), dynreg.ErrMissingOpenIDConfigURL.Error()) {
		t.Errorf("body missing expected error: %s", rec.Body.String())
	}
}

func TestHandler_NonHTTPSOpenIDConfigURL(t *testing.T) {
	h := dynreg.Handler(minimalConfig(t))
	req := httptest.NewRequest(http.MethodGet,
		"/dynreg?openid_configuration=http://platform.example.com/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), dynreg.ErrInvalidOpenIDConfigURL.Error()) {
		t.Errorf("body missing expected error: %s", rec.Body.String())
	}
}

func TestHandler_NonHTTPSOpenIDConfigURL_AllowedByConfig(t *testing.T) {
	cfg := minimalConfig(t)
	cfg.AllowInsecureOpenIDConfigURL = true
	cfg.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case "http://platform.example.com/.well-known/openid-configuration":
				body := `{"issuer":"http://platform.example.com","registration_endpoint":"http://platform.example.com/register","jwks_uri":"http://platform.example.com/jwks","token_endpoint":"http://platform.example.com/token","authorization_endpoint":"http://platform.example.com/auth","token_endpoint_auth_methods_supported":["private_key_jwt"]}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    req,
				}, nil
			case "http://platform.example.com/register":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"client_id":"client-abc"}`)),
					Request:    req,
				}, nil
			default:
				t.Fatalf("unexpected URL: %s", req.URL.String())
				return nil, nil
			}
		}),
	}

	h := dynreg.Handler(cfg)
	req := httptest.NewRequest(http.MethodGet,
		"/dynreg?openid_configuration=http://platform.example.com/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "org.imsglobal.lti.close") {
		t.Errorf("response body missing close message: %s", rec.Body.String())
	}
}

func TestHandler_DomainMismatch(t *testing.T) {
	// The attacker serves an openid-config whose Issuer claims a completely
	// different hostname, so validateDomain must reject it.
	attacker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := dynreg.OpenIDConfiguration{
			Issuer:                "https://legit-platform.example.com",
			RegistrationEndpoint:  "https://legit-platform.example.com/register",
			JWKSURL:               "https://legit-platform.example.com/jwks",
			TokenEndpoint:         "https://legit-platform.example.com/token",
			AuthorizationEndpoint: "https://legit-platform.example.com/auth",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	}))
	t.Cleanup(attacker.Close)

	cfg := minimalConfig(t)
	cfg.HTTPClient = attacker.Client()

	h := dynreg.Handler(cfg)
	req := httptest.NewRequest(http.MethodGet,
		"/dynreg?openid_configuration="+attacker.URL+"/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), dynreg.ErrDomainMismatch.Error()) {
		t.Errorf("body missing domain mismatch error: %s", rec.Body.String())
	}
}

func TestHandler_Success(t *testing.T) {
	srv := newPlatform(t, http.StatusOK)
	store := &stubStore{}

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.RegistrationStore = store
	cfg.Scopes = []string{"https://purl.imsglobal.org/spec/lti-ags/scope/lineitem"}

	h := dynreg.Handler(cfg)
	req := httptest.NewRequest(http.MethodGet,
		"/dynreg?openid_configuration="+srv.URL+"/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "org.imsglobal.lti.close") {
		t.Error("response body missing postMessage close call")
	}
	if store.savedReg == nil {
		t.Fatal("RegistrationStore.AddRegistration was not called")
	}
	if store.savedReg.ClientID != "client-abc" {
		t.Errorf("want ClientID client-abc, got %q", store.savedReg.ClientID)
	}
	if store.savedReg.Issuer != srv.URL {
		t.Errorf("want Issuer %s, got %q", srv.URL, store.savedReg.Issuer)
	}
}

func TestHandler_WithRegistrationToken(t *testing.T) {
	var receivedToken string

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			cfg := dynreg.OpenIDConfiguration{
				Issuer:                            "https://" + r.Host,
				RegistrationEndpoint:              "https://" + r.Host + "/register",
				JWKSURL:                           "https://" + r.Host + "/jwks",
				TokenEndpoint:                     "https://" + r.Host + "/token",
				AuthorizationEndpoint:             "https://" + r.Host + "/auth",
				TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg)
		case "/register":
			receivedToken = r.Header.Get("Authorization")
			resp := dynreg.ClientRegistrationResponse{ClientID: "tok-client"}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	t.Cleanup(srv.Close)

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()

	h := dynreg.Handler(cfg)
	req := httptest.NewRequest(http.MethodGet,
		"/dynreg?openid_configuration="+srv.URL+"/.well-known/openid-configuration&registration_token=supersecret", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if receivedToken != "Bearer supersecret" {
		t.Errorf("want 'Bearer supersecret', got %q", receivedToken)
	}
}

func TestHandler_StoreError(t *testing.T) {
	srv := newPlatform(t, http.StatusOK)

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.RegistrationStore = &stubStore{err: errors.New("db unavailable")}

	h := dynreg.Handler(cfg)
	req := httptest.NewRequest(http.MethodGet,
		"/dynreg?openid_configuration="+srv.URL+"/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("want 502, got %d", rec.Code)
	}
}

func TestHandler_PlatformRegistrationError(t *testing.T) {
	srv := newPlatform(t, http.StatusUnauthorized)

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()

	h := dynreg.Handler(cfg)
	req := httptest.NewRequest(http.MethodGet,
		"/dynreg?openid_configuration="+srv.URL+"/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("want 502, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), dynreg.ErrRegistrationFailed.Error()) {
		t.Errorf("body missing expected error: %s", rec.Body.String())
	}
}

// --- Register (programmatic) tests ---

func TestRegister_Success(t *testing.T) {
	srv := newPlatform(t, http.StatusOK)
	store := &stubStore{}

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.RegistrationStore = store

	result, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Registration.ClientID != "client-abc" {
		t.Errorf("want client-abc, got %q", result.Registration.ClientID)
	}
	if result.Registration.Issuer != srv.URL {
		t.Errorf("want issuer %s, got %s", srv.URL, result.Registration.Issuer)
	}
	if result.Deployment != nil {
		t.Error("expected nil Deployment when platform did not return deployment_id")
	}
	if store.savedReg == nil {
		t.Error("RegistrationStore.AddRegistration was not called")
	}
}

func TestRegister_WithDeploymentID(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			cfg := dynreg.OpenIDConfiguration{
				Issuer:                            "https://" + r.Host,
				RegistrationEndpoint:              "https://" + r.Host + "/register",
				JWKSURL:                           "https://" + r.Host + "/jwks",
				TokenEndpoint:                     "https://" + r.Host + "/token",
				AuthorizationEndpoint:             "https://" + r.Host + "/auth",
				TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg)
		case "/register":
			resp := dynreg.ClientRegistrationResponse{ClientID: "dep-client"}
			resp.LTIToolConfiguration = &dynreg.LTIToolConfig{
				Domain:        "tool.example.com",
				TargetLinkURI: "https://tool.example.com/launch",
				Claims:        []string{"sub"},
				DeploymentID:  "deploy-123",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	t.Cleanup(srv.Close)

	store := &stubStore{}
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.RegistrationStore = store

	result, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Deployment == nil {
		t.Fatal("expected non-nil Deployment")
	}
	if result.Deployment.DeploymentID != "deploy-123" {
		t.Errorf("want deploy-123, got %q", result.Deployment.DeploymentID)
	}
	if store.savedDep == nil {
		t.Error("RegistrationStore.AddDeployment was not called")
	}
}

func TestRegister_NonHTTPS(t *testing.T) {
	cfg := minimalConfig(t)
	_, err := dynreg.Register(context.Background(), cfg,
		"http://platform.example.com/.well-known/openid-configuration", "")
	if !errors.Is(err, dynreg.ErrInvalidOpenIDConfigURL) {
		t.Errorf("want ErrInvalidOpenIDConfigURL, got %v", err)
	}
}

func TestRegister_NonHTTPS_AllowedByConfig(t *testing.T) {
	cfg := minimalConfig(t)
	cfg.AllowInsecureOpenIDConfigURL = true
	cfg.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case "http://platform.example.com/.well-known/openid-configuration":
				body := `{"issuer":"http://platform.example.com","registration_endpoint":"http://platform.example.com/register","jwks_uri":"http://platform.example.com/jwks","token_endpoint":"http://platform.example.com/token","authorization_endpoint":"http://platform.example.com/auth","token_endpoint_auth_methods_supported":["private_key_jwt"]}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    req,
				}, nil
			case "http://platform.example.com/register":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"client_id":"client-abc"}`)),
					Request:    req,
				}, nil
			default:
				t.Fatalf("unexpected URL: %s", req.URL.String())
				return nil, nil
			}
		}),
	}

	result, err := dynreg.Register(context.Background(), cfg,
		"http://platform.example.com/.well-known/openid-configuration", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Registration.ClientID != "client-abc" {
		t.Errorf("want client-abc, got %q", result.Registration.ClientID)
	}
	if result.Registration.Issuer != "http://platform.example.com" {
		t.Errorf("want http://platform.example.com, got %q", result.Registration.Issuer)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestRegister_DomainMismatch(t *testing.T) {
	// The attacker serves an openid-config whose Issuer claims a different hostname.
	attacker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := dynreg.OpenIDConfiguration{
			Issuer:                "https://legit-platform.example.com",
			RegistrationEndpoint:  "https://legit-platform.example.com/register",
			JWKSURL:               "https://legit-platform.example.com/jwks",
			TokenEndpoint:         "https://legit-platform.example.com/token",
			AuthorizationEndpoint: "https://legit-platform.example.com/auth",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	}))
	t.Cleanup(attacker.Close)

	cfg := minimalConfig(t)
	cfg.HTTPClient = attacker.Client()

	_, err := dynreg.Register(context.Background(), cfg,
		attacker.URL+"/.well-known/openid-configuration", "")
	if !errors.Is(err, dynreg.ErrDomainMismatch) {
		t.Errorf("want ErrDomainMismatch, got %v", err)
	}
}

// --- Registration request structure ---

func TestRequestFields(t *testing.T) {
	var received dynreg.ClientRegistrationRequest

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			cfg := dynreg.OpenIDConfiguration{
				Issuer:                            "https://" + r.Host,
				RegistrationEndpoint:              "https://" + r.Host + "/register",
				JWKSURL:                           "https://" + r.Host + "/jwks",
				TokenEndpoint:                     "https://" + r.Host + "/token",
				AuthorizationEndpoint:             "https://" + r.Host + "/auth",
				TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg)
		case "/register":
			_ = json.NewDecoder(r.Body).Decode(&received)
			resp := dynreg.ClientRegistrationResponse{ClientID: "x"}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	t.Cleanup(srv.Close)

	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()
	cfg.Messages = []dynreg.ToolMessage{
		{Type: "LtiDeepLinkingRequest", Placements: []string{"course_navigation"}},
	}
	cfg.Scopes = []string{"https://purl.imsglobal.org/spec/lti-ags/scope/lineitem"}

	_, err := dynreg.Register(context.Background(), cfg, srv.URL+"/.well-known/openid-configuration", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if received.ApplicationType != "web" {
		t.Errorf("application_type: want web, got %q", received.ApplicationType)
	}
	if received.TokenEndpointAuthMethod != "private_key_jwt" {
		t.Errorf("token_endpoint_auth_method: want private_key_jwt, got %q", received.TokenEndpointAuthMethod)
	}

	wantGrants := map[string]bool{"client_credentials": true, "implicit": true}
	for _, g := range received.GrantTypes {
		delete(wantGrants, g)
	}
	if len(wantGrants) > 0 {
		t.Errorf("grant_types missing: %v", wantGrants)
	}

	if !strings.Contains(received.Scope, "openid") {
		t.Errorf("scope missing openid: %q", received.Scope)
	}
	if !strings.Contains(received.Scope, "lti-ags") {
		t.Errorf("scope missing ags scope: %q", received.Scope)
	}

	if received.LTIToolConfiguration == nil {
		t.Fatal("lti tool configuration is nil")
	}
	if received.LTIToolConfiguration.Domain != cfg.ToolDomain {
		t.Errorf("domain: want %q, got %q", cfg.ToolDomain, received.LTIToolConfiguration.Domain)
	}
	if len(received.LTIToolConfiguration.Messages) != 1 {
		t.Errorf("messages: want 1, got %d", len(received.LTIToolConfiguration.Messages))
	}
}
