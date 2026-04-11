package connector_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	lti "github.com/robertjndw/go-lti"
	"github.com/robertjndw/go-lti/connector"
	"github.com/robertjndw/go-lti/internal/ltitest"
)

// tokenServerConfig controls what the mock token endpoint returns.
type tokenServerConfig struct {
	status      int
	accessToken string
	expiresIn   int
	// capturedRequests holds the raw request bodies for inspection.
	capturedRequests []string
}

// newTokenServer starts a mock OAuth2 token endpoint.
func newTokenServer(t *testing.T, cfg *tokenServerConfig) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cfg.capturedRequests = append(cfg.capturedRequests, string(body))

		if cfg.status != 0 && cfg.status != http.StatusOK {
			w.WriteHeader(cfg.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"access_token": cfg.accessToken,
			"token_type":   "Bearer",
			"expires_in":   cfg.expiresIn,
		}
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newReg creates a registration pointing at the given token server.
func newReg(t *testing.T, tokenServerURL string) *lti.Registration {
	t.Helper()
	key := ltitest.NewKey(t)
	return &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-xyz",
		KeySetURL:      "https://platform.example.com/jwks",
		AuthLoginURL:   "https://platform.example.com/auth",
		AuthTokenURL:   tokenServerURL,
		AuthServer:     tokenServerURL,
		ToolPrivateKey: key,
		KID:            "tool-key-1",
	}
}

// ── RFC 7523 §2.1 — Client assertion JWT structure ────────────────────────────

// Spec: The client assertion JWT must use grant_type=client_credentials.
// Spec: client_assertion_type must be the JWT bearer URN.
func TestConnector_TokenRequest_HasCorrectGrantType(t *testing.T) {
	cfg := &tokenServerConfig{accessToken: "tok-abc", expiresIn: 3600}
	srv := newTokenServer(t, cfg)

	reg := newReg(t, srv.URL)
	conn := connector.New(reg, connector.WithHTTPClient(srv.Client()))

	_, err := conn.GetAccessToken(context.Background(), []string{lti.ScopeAGSScore})
	if err != nil {
		t.Fatalf("GetAccessToken failed: %v", err)
	}

	if len(cfg.capturedRequests) == 0 {
		t.Fatal("no request captured")
	}
	body := cfg.capturedRequests[0]
	if !strings.Contains(body, "grant_type=client_credentials") {
		t.Errorf("grant_type=client_credentials not found in request body: %s", body)
	}
	const expectedType = "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
	if !strings.Contains(body, expectedType) {
		t.Errorf("client_assertion_type not found in request body: %s", body)
	}
}

// Spec: The scope must be passed as a space-separated list.
func TestConnector_TokenRequest_IncludesRequestedScopes(t *testing.T) {
	cfg := &tokenServerConfig{accessToken: "tok-scopes", expiresIn: 3600}
	srv := newTokenServer(t, cfg)

	reg := newReg(t, srv.URL)
	conn := connector.New(reg, connector.WithHTTPClient(srv.Client()))

	scopes := []string{lti.ScopeAGSScore, lti.ScopeAGSLineitem}
	_, err := conn.GetAccessToken(context.Background(), scopes)
	if err != nil {
		t.Fatalf("GetAccessToken failed: %v", err)
	}

	vals, err := url.ParseQuery(cfg.capturedRequests[0])
	if err != nil {
		t.Fatalf("failed to parse request body: %v", err)
	}
	scopeParam := vals.Get("scope")
	for _, scope := range scopes {
		if !strings.Contains(scopeParam, scope) {
			t.Errorf("scope %q not found in scope param %q", scope, scopeParam)
		}
	}
}

// Spec RFC 7523 §3: The client_assertion JWT must have iss=client_id and sub=client_id.
func TestConnector_ClientAssertion_IssAndSubAreClientID(t *testing.T) {
	cfg := &tokenServerConfig{accessToken: "tok-claims", expiresIn: 3600}
	srv := newTokenServer(t, cfg)

	reg := newReg(t, srv.URL)
	conn := connector.New(reg, connector.WithHTTPClient(srv.Client()))

	_, err := conn.GetAccessToken(context.Background(), []string{lti.ScopeAGSScore})
	if err != nil {
		t.Fatalf("GetAccessToken failed: %v", err)
	}

	assertion := extractAssertion(t, cfg.capturedRequests[0])
	claims := parseAssertionClaims(t, assertion)

	if claims["iss"] != reg.ClientID {
		t.Errorf("iss = %v, want %q", claims["iss"], reg.ClientID)
	}
	if claims["sub"] != reg.ClientID {
		t.Errorf("sub = %v, want %q", claims["sub"], reg.ClientID)
	}
}

// Spec RFC 7523 §3: The aud claim must be the token endpoint URL.
func TestConnector_ClientAssertion_AudIsAuthServer(t *testing.T) {
	cfg := &tokenServerConfig{accessToken: "tok-aud", expiresIn: 3600}
	srv := newTokenServer(t, cfg)

	reg := newReg(t, srv.URL)
	conn := connector.New(reg, connector.WithHTTPClient(srv.Client()))

	_, err := conn.GetAccessToken(context.Background(), []string{lti.ScopeAGSScore})
	if err != nil {
		t.Fatalf("GetAccessToken failed: %v", err)
	}

	assertion := extractAssertion(t, cfg.capturedRequests[0])
	claims := parseAssertionClaims(t, assertion)

	aud, _ := claims["aud"].(string)
	if aud != reg.EffectiveAuthServer() {
		t.Errorf("aud = %q, want %q", aud, reg.EffectiveAuthServer())
	}
}

// Spec: The client_assertion must be signed with RS256 (the tool's private key).
func TestConnector_ClientAssertion_SignedWithRS256(t *testing.T) {
	cfg := &tokenServerConfig{accessToken: "tok-sig", expiresIn: 3600}
	srv := newTokenServer(t, cfg)

	reg := newReg(t, srv.URL)
	conn := connector.New(reg, connector.WithHTTPClient(srv.Client()))

	_, err := conn.GetAccessToken(context.Background(), []string{lti.ScopeAGSScore})
	if err != nil {
		t.Fatalf("GetAccessToken failed: %v", err)
	}

	assertion := extractAssertion(t, cfg.capturedRequests[0])
	alg := parseAssertionAlg(t, assertion)
	if alg != "RS256" {
		t.Errorf("alg = %q, want RS256", alg)
	}
}

// ── Token caching ─────────────────────────────────────────────────────────────

// Tokens must be cached and reused until expiry.
// A second call with the same scopes must NOT hit the token endpoint.
func TestConnector_TokenCached_ReusedUntilExpiry(t *testing.T) {
	cfg := &tokenServerConfig{accessToken: "cached-token", expiresIn: 3600}
	srv := newTokenServer(t, cfg)

	reg := newReg(t, srv.URL)
	conn := connector.New(reg, connector.WithHTTPClient(srv.Client()))

	scopes := []string{lti.ScopeNRPS}

	tok1, err := conn.GetAccessToken(context.Background(), scopes)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	tok2, err := conn.GetAccessToken(context.Background(), scopes)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if tok1 != tok2 {
		t.Error("second call must return the cached token")
	}
	if len(cfg.capturedRequests) != 1 {
		t.Errorf("expected 1 token endpoint call, got %d", len(cfg.capturedRequests))
	}
}

// Different scope sets must use separate cache entries.
func TestConnector_DifferentScopes_SeparateCacheEntries(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"access_token": "tok-" + string(rune('a'+callCount)),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(srv.Close)

	reg := newReg(t, srv.URL)
	conn := connector.New(reg, connector.WithHTTPClient(srv.Client()))
	ctx := context.Background()

	_, _ = conn.GetAccessToken(ctx, []string{lti.ScopeAGSScore})
	_, _ = conn.GetAccessToken(ctx, []string{lti.ScopeNRPS})

	if callCount != 2 {
		t.Errorf("expected 2 token endpoint calls for different scopes, got %d", callCount)
	}
}

// ── Bearer token on service requests ─────────────────────────────────────────

// Service requests must carry an Authorization: Bearer <token> header.
func TestConnector_Request_AttachesBearerToken(t *testing.T) {
	const accessToken = "service-bearer-token"
	tokenSrv := newTokenServer(t, &tokenServerConfig{accessToken: accessToken, expiresIn: 3600})

	var capturedAuth string
	serviceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(serviceSrv.Close)

	reg := newReg(t, tokenSrv.URL)
	conn := connector.New(reg, connector.WithHTTPClient(tokenSrv.Client()))

	resp, err := conn.Request(context.Background(), http.MethodGet, serviceSrv.URL, nil,
		[]string{lti.ScopeAGSScore})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	want := "Bearer " + accessToken
	if capturedAuth != want {
		t.Errorf("Authorization = %q, want %q", capturedAuth, want)
	}
}

// ── Link header pagination ─────────────────────────────────────────────────────

// NextPageURL must extract the URL from a Link: <url>; rel="next" header.
func TestServiceResponse_NextPageURL_ExtractsLink(t *testing.T) {
	resp := &connector.ServiceResponse{
		StatusCode: 200,
		Headers: http.Header{
			"Link": {`<https://platform.example.com/page2>; rel="next", <https://platform.example.com/page1>; rel="prev"`},
		},
		Body: []byte("[]"),
	}
	got := resp.NextPageURL()
	if got != "https://platform.example.com/page2" {
		t.Errorf("NextPageURL = %q, want https://platform.example.com/page2", got)
	}
}

// NextPageURL must return empty string when no rel="next" link is present.
func TestServiceResponse_NextPageURL_EmptyWhenNoNext(t *testing.T) {
	resp := &connector.ServiceResponse{
		StatusCode: 200,
		Headers:    http.Header{"Link": {`<https://platform.example.com/page1>; rel="prev"`}},
		Body:       []byte("[]"),
	}
	if got := resp.NextPageURL(); got != "" {
		t.Errorf("NextPageURL = %q, want empty string", got)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// extractAssertion parses a URL-encoded form body and returns the client_assertion value.
func extractAssertion(t *testing.T, body string) string {
	t.Helper()
	vals, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("failed to parse form body: %v", err)
	}
	a := vals.Get("client_assertion")
	if a == "" {
		t.Fatalf("client_assertion not found in body: %s", body)
	}
	return a
}

// parseAssertionClaims decodes the payload of a JWT without verifying the signature.
func parseAssertionClaims(t *testing.T, tokenStr string) jwt.MapClaims {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format in assertion")
	}
	import_encoding_base64_rawurl := func(s string) []byte {
		b, err := base64DecodeRawURL(s)
		if err != nil {
			t.Fatalf("failed to base64-decode payload: %v", err)
		}
		return b
	}
	var claims jwt.MapClaims
	if err := json.Unmarshal(import_encoding_base64_rawurl(parts[1]), &claims); err != nil {
		t.Fatalf("failed to unmarshal claims: %v", err)
	}
	return claims
}

// parseAssertionAlg returns the alg field from a JWT header.
func parseAssertionAlg(t *testing.T, tokenStr string) string {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT")
	}
	b, err := base64DecodeRawURL(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	json.Unmarshal(b, &header) //nolint:errcheck
	return header.Alg
}

func base64DecodeRawURL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
