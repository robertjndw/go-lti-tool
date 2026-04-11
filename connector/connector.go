// Package connector provides an OAuth2 client_credentials service connector for
// LTI Advantage service calls (AGS, NRPS, etc.).
//
// The connector authenticates to the platform's token endpoint using a signed JWT
// assertion (iss=sub=client_id), exchanges it for a bearer token, and attaches
// that token to HTTP requests. Tokens are cached per scope set and reused until
// close to their expiry.
package connector

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/robertjndw/go-lti"
)

// Connector holds a platform Registration and manages OAuth2 access tokens for
// LTI Advantage service calls.
type Connector struct {
	reg        *lti.Registration
	httpClient *http.Client
	mu         sync.Mutex
	tokens     map[string]*tokenEntry // keyed by sorted scope string
}

type tokenEntry struct {
	accessToken string
	expiresAt   time.Time
}

// Option configures a Connector.
type Option func(*Connector)

// WithHTTPClient overrides the HTTP client used for token exchange and service calls.
func WithHTTPClient(c *http.Client) Option {
	return func(conn *Connector) {
		conn.httpClient = c
	}
}

// New creates a Connector for the given Registration.
func New(reg *lti.Registration, opts ...Option) *Connector {
	c := &Connector{
		reg:        reg,
		httpClient: http.DefaultClient,
		tokens:     make(map[string]*tokenEntry),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// tokenResponse is the JSON body returned by the platform's token endpoint.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// GetAccessToken returns a valid bearer token for the given scopes, obtaining a
// new one from the platform if no cached token is available.
func (c *Connector) GetAccessToken(ctx context.Context, scopes []string) (string, error) {
	key := scopeKey(scopes)

	c.mu.Lock()
	entry, ok := c.tokens[key]
	c.mu.Unlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.accessToken, nil
	}

	// Build the client assertion JWT.
	jti, err := randomToken(16)
	if err != nil {
		return "", fmt.Errorf("connector: failed to generate jti: %w", err)
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": c.reg.ClientID,
		"sub": c.reg.ClientID,
		"aud": c.reg.EffectiveAuthServer(),
		"iat": now.Unix(),
		"exp": now.Add(60 * time.Second).Unix(),
		"jti": jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = c.reg.KID
	assertion, err := token.SignedString(c.reg.ToolPrivateKey)
	if err != nil {
		return "", fmt.Errorf("connector: failed to sign client assertion: %w", err)
	}

	// Exchange the assertion for a bearer token.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	form.Set("scope", strings.Join(scopes, " "))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.reg.AuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("connector: failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("connector: token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("connector: failed to read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("connector: token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("connector: failed to parse token response: %w", err)
	}

	expiresIn := tr.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	// Subtract 30 seconds to avoid using a token that is about to expire.
	expiresAt := time.Now().Add(time.Duration(expiresIn-30) * time.Second)

	c.mu.Lock()
	c.tokens[key] = &tokenEntry{accessToken: tr.AccessToken, expiresAt: expiresAt}
	c.mu.Unlock()

	return tr.AccessToken, nil
}

// ServiceResponse wraps an HTTP response from a platform service endpoint.
type ServiceResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// NextPageURL extracts the URL from a rel="next" Link header, returning an empty
// string if no next page exists.
func (sr *ServiceResponse) NextPageURL() string {
	return parseLinkNext(sr.Headers.Get("Link"))
}

// linkNextRe extracts the URL from a Link header with rel="next".
var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func parseLinkNext(header string) string {
	if m := linkNextRe.FindStringSubmatch(header); len(m) == 2 {
		return m[1]
	}
	return ""
}

// RequestOption configures a single service HTTP request.
type RequestOption func(*http.Request)

// WithContentType sets the Content-Type header.
func WithContentType(ct string) RequestOption {
	return func(r *http.Request) {
		r.Header.Set("Content-Type", ct)
	}
}

// WithAccept sets the Accept header.
func WithAccept(accept string) RequestOption {
	return func(r *http.Request) {
		r.Header.Set("Accept", accept)
	}
}

// Request makes an authenticated HTTP request to a platform service endpoint.
// It obtains a bearer token for the given scopes, adds it as a Bearer Authorization
// header, and returns the raw response.
func (c *Connector) Request(ctx context.Context, method, serviceURL string, body io.Reader, scopes []string, opts ...RequestOption) (*ServiceResponse, error) {
	token, err := c.GetAccessToken(ctx, scopes)
	if err != nil {
		return nil, fmt.Errorf("connector: failed to get access token: %w", err)
	}

	var bodyBytes []byte
	if body != nil {
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("connector: failed to read request body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, serviceURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("connector: failed to build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	for _, opt := range opts {
		opt(req)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connector: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("connector: failed to read response body: %w", err)
	}

	return &ServiceResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
	}, nil
}

// scopeKey returns a stable cache key for a set of scopes.
func scopeKey(scopes []string) string {
	sorted := make([]string, len(scopes))
	copy(sorted, scopes)
	sort.Strings(sorted)
	return strings.Join(sorted, " ")
}

// randomToken generates a URL-safe random string of n bytes.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
