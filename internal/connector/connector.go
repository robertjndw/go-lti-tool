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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/internal/randutil"
)

// maxResponseBodyBytes limits the size of HTTP response bodies read from the platform.
const maxResponseBodyBytes = 1 << 20 // 1 MiB

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
	Scope       string `json:"scope"`
}

// isLoopbackHost reports whether hostport (a URL host, optionally with a
// port) refers to a loopback address (127.0.0.1, ::1, localhost). The
// Security Framework's TLS requirement targets real network traffic; a
// same-machine test/dev endpoint is exempted for LTI service calls.
func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// requireSecureServiceURL enforces the Security Framework §3 TLS requirement
// on an LTI service call, exempting loopback hosts for local testing.
func requireSecureServiceURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("connector: invalid service URL %q: %w", rawURL, err)
	}
	if u.Scheme == "https" || isLoopbackHost(u.Host) {
		return nil
	}
	return fmt.Errorf("connector: insecure service URL %q: the 1EdTech Security Framework §3 requires TLS (loopback hosts are exempt for local testing)", rawURL)
}

// scopeSetEqual reports whether granted (a space-separated OAuth2 scope
// list, RFC 6749 §3.3) contains exactly the requested scopes, regardless of
// order. An empty/omitted granted scope never matches a non-empty request.
func scopeSetEqual(granted string, requested []string) bool {
	grantedScopes := strings.Fields(granted)
	if len(grantedScopes) != len(requested) {
		return false
	}
	for _, s := range requested {
		if !slices.Contains(grantedScopes, s) {
			return false
		}
	}
	return true
}

// GetAccessToken returns a valid bearer token for the given scopes, obtaining a
// new one from the platform if no cached token is available.
func (c *Connector) GetAccessToken(ctx context.Context, scopes []string) (string, error) {
	// The Security Framework §3 requires TLS for the token endpoint, with the
	// same loopback exemption as service calls (local testing).
	if u, err := url.Parse(c.reg.AuthTokenURL); err != nil || (u.Scheme != "https" && !isLoopbackHost(u.Host)) {
		return "", fmt.Errorf("connector: insecure OAuth token endpoint %q: the 1EdTech Security Framework §3 requires TLS (loopback hosts are exempt for local testing)", c.reg.AuthTokenURL)
	}

	key := scopeKey(scopes)

	// Hold the lock for the entire check-and-fetch to prevent concurrent goroutines
	// from issuing redundant token requests for the same scope set.
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.tokens[key]; ok && time.Now().Before(entry.expiresAt) {
		return entry.accessToken, nil
	}

	if c.reg.ToolPrivateKey == nil {
		return "", fmt.Errorf("connector: registration has no private key")
	}

	jti, err := randutil.Token(16)
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return "", fmt.Errorf("connector: failed to read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Truncate to avoid leaking large or sensitive platform error bodies.
		excerpt := body
		if len(excerpt) > 200 {
			excerpt = excerpt[:200]
		}
		return "", fmt.Errorf("connector: token endpoint returned %d: %s", resp.StatusCode, excerpt)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("connector: failed to parse token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("connector: token response missing access_token")
	}
	if !strings.EqualFold(tr.TokenType, "bearer") {
		return "", fmt.Errorf("connector: token response has unsupported token_type %q, want Bearer", tr.TokenType)
	}
	if !scopeSetEqual(tr.Scope, scopes) {
		return "", fmt.Errorf("connector: token endpoint granted scope %q does not match requested scopes %v", tr.Scope, scopes)
	}

	expiresIn := tr.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	// Subtract 30 seconds to avoid using a token that is about to expire.
	// Clamp so that short-lived tokens (expires_in ≤ 30) still produce a positive duration.
	safeExpiry := max(expiresIn-30, 1)
	expiresAt := time.Now().Add(time.Duration(safeExpiry) * time.Second)

	c.tokens[key] = &tokenEntry{accessToken: tr.AccessToken, expiresAt: expiresAt}
	return tr.AccessToken, nil
}

// ServiceResponse wraps an HTTP response from a platform service endpoint.
type ServiceResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte

	// RequestURL is the URL the request was sent to, used to resolve relative
	// URLs in Link headers.
	RequestURL *url.URL
}

// NextPageURL extracts the URL from a rel="next" Link header, returning an empty
// string if no next page exists.
func (sr *ServiceResponse) NextPageURL() string {
	return sr.LinkURL("next")
}

// LinkURL extracts the URL for the given rel value from the response's Link
// headers (e.g. "next", "differences"). All Link header values are scanned and
// relative URLs are resolved against the request URL. Returns "" if absent.
func (sr *ServiceResponse) LinkURL(rel string) string {
	for _, header := range sr.Headers.Values("Link") {
		if raw := parseLinkRel(header, rel); raw != "" {
			return sr.resolveURL(raw)
		}
	}
	return ""
}

func (sr *ServiceResponse) resolveURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.IsAbs() || sr.RequestURL == nil {
		return raw
	}
	return sr.RequestURL.ResolveReference(u).String()
}

// linkRe matches one Link header entry: a <URL> followed by its parameters.
var linkRe = regexp.MustCompile(`<([^>]*)>([^,]*)`)

// parseLinkRel extracts the URL whose parameters include rel="<rel>" (with or
// without quotes) from a single Link header value.
func parseLinkRel(header, rel string) string {
	for _, m := range linkRe.FindAllStringSubmatch(header, -1) {
		for _, param := range strings.Split(m[2], ";") {
			key, value, ok := strings.Cut(strings.TrimSpace(param), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "rel") {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), `"`)
			if strings.EqualFold(value, rel) {
				return m[1]
			}
		}
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
	if err := requireSecureServiceURL(serviceURL); err != nil {
		return nil, err
	}

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

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("connector: failed to read response body: %w", err)
	}

	return &ServiceResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		RequestURL: resp.Request.URL,
	}, nil
}

// scopeKey returns a stable cache key for a set of scopes.
func scopeKey(scopes []string) string {
	sorted := make([]string, len(scopes))
	copy(sorted, scopes)
	sort.Strings(sorted)
	return strings.Join(sorted, " ")
}
