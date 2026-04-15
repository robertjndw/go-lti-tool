package dynreg

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	lticore "github.com/robertjndw/go-lti/internal/lticore"
)

// Sentinel errors.
var (
	// ErrMissingOpenIDConfigURL is returned when the openid_configuration query
	// parameter is absent from the initiation request.
	ErrMissingOpenIDConfigURL = errors.New("lti/dynreg: missing openid_configuration parameter")

	// ErrInvalidOpenIDConfigURL is returned when the openid_configuration URL
	// is not a valid HTTPS URL.
	ErrInvalidOpenIDConfigURL = errors.New("lti/dynreg: invalid openid_configuration URL")

	// ErrDomainMismatch is returned when the host of the openid_configuration
	// URL does not match the host of the issuer declared in the fetched OpenID
	// Provider Configuration, indicating a potential impersonation attack.
	ErrDomainMismatch = errors.New("lti/dynreg: openid_configuration URL host does not match issuer host")

	// ErrOpenIDConfigFetch is returned when the platform's OpenID Provider
	// Configuration cannot be retrieved or decoded.
	ErrOpenIDConfigFetch = errors.New("lti/dynreg: failed to fetch OpenID configuration")

	// ErrRegistrationFailed is returned when the platform's registration
	// endpoint responds with a non-success status or an invalid body.
	ErrRegistrationFailed = errors.New("lti/dynreg: platform registration failed")
)

// DynRegConfig holds all dependencies and tool-identity information needed for the
// dynamic registration flow.
//
// The dependency fields (RegistrationStore, ToolKey, KID, HTTPClient) parallel
// those in login.DynRegConfig and launch.DynRegConfig. The remaining fields describe the
// tool to the platform and are embedded in the registration request.
type DynRegConfig struct {
	// RegistrationStore persists the platform Registration (and optional
	// Deployment) produced by a successful registration. If nil, the result is
	// discarded — useful only in tests.
	RegistrationStore lticore.Datastore

	// ToolKey is the RSA private key the tool uses to sign service-call JWTs
	// (AGS, NRPS). It is stored in the Registration so that subsequent
	// launches can use it via the Connector. If nil the Registration is saved
	// without a private key.
	ToolKey *rsa.PrivateKey

	// KID identifies ToolKey in the tool's JWKS. Must match a key served at
	// JWKSUri. Ignored when ToolKey is nil.
	KID string

	// HTTPClient is used for outbound requests to the platform.
	// Defaults to http.DefaultClient when nil.
	HTTPClient *http.Client

	// AllowInsecureOpenIDConfigURL permits the incoming openid_configuration URL
	// to use http instead of https. Leave this disabled in production; it exists
	// only for local development flows where the platform exposes insecure URLs.
	AllowInsecureOpenIDConfigURL bool

	// --- Tool identity fields (sent in the registration request) ---

	// ToolName is the human-readable display name sent to the platform.
	ToolName string

	// ToolDomain is the primary domain of the tool (e.g. "tool.example.com"),
	// without scheme or path.
	ToolDomain string

	// JWKSUri is the URL where the tool serves its public JWKS.
	JWKSUri string

	// InitiateLoginUri is the URL the platform calls to begin an OIDC launch.
	InitiateLoginUri string

	// RedirectURIs lists the post-launch callback URLs accepted by the tool.
	RedirectURIs []string

	// TargetLinkUri is the default launch URL when no message-specific URI is set.
	TargetLinkUri string

	// Claims lists the OIDC / LTI claims the tool requires
	// (e.g. "sub", "email", "name").
	Claims []string

	// Scopes lists the OAuth2 scopes the tool requests (e.g. AGS, NRPS scopes).
	// "openid" is always included even if omitted here.
	Scopes []string

	// Messages configures placement-specific message types.
	Messages []ToolMessage

	// CustomParameters are global custom parameter substitutions.
	CustomParameters map[string]string

	// SecondaryDomains lists additional domains served by this tool.
	SecondaryDomains []string

	// --- Optional metadata ---

	// LogoURI is the URL of the tool's logo image.
	LogoURI string

	// Contacts is a list of contact email addresses for the tool.
	Contacts []string

	// ClientURI is the tool's homepage URL.
	ClientURI string

	// TOSURI is the tool's terms-of-service URL.
	TOSURI string

	// PolicyURI is the tool's privacy-policy URL.
	PolicyURI string

	// Description is a human-readable description of the tool.
	Description string
}

func (c *DynRegConfig) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

// RegistrationResult holds the domain objects produced by a successful
// dynamic registration.
type RegistrationResult struct {
	// Registration is the platform Registration ready to be used by the
	// login and launch handlers. It has been persisted via RegistrationStore
	// when one was configured.
	Registration *lticore.Registration

	// Deployment is non-nil when the platform assigned a deployment_id as part
	// of the registration response.
	Deployment *lticore.Deployment
}

// Handler returns an http.Handler for the tool's dynamic registration endpoint.
//
// The platform opens this URL (typically in an iframe or new tab) with the
// following query parameters:
//
//   - openid_configuration – URL of the platform's OpenID Provider Configuration
//   - registration_token   – (optional) short-lived Bearer token
//
// On success the handler writes an HTML page that sends the
// org.imsglobal.lti.close postMessage to the opener/parent frame so the
// platform knows registration is complete.
func Handler(cfg DynRegConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		openidConfigURL := q.Get("openid_configuration")
		registrationToken := q.Get("registration_token")

		if openidConfigURL == "" {
			http.Error(w, ErrMissingOpenIDConfigURL.Error(), http.StatusBadRequest)
			return
		}

		_, err := Register(r.Context(), cfg, openidConfigURL, registrationToken)
		if err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, ErrMissingOpenIDConfigURL) || errors.Is(err, ErrInvalidOpenIDConfigURL) || errors.Is(err, ErrDomainMismatch) {
				status = http.StatusBadRequest
			}
			http.Error(w, err.Error(), status)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, closePage)
	})
}

// Register performs the full dynamic registration flow and returns the resulting
// domain objects. It is the lower-level counterpart to Handler, useful when
// you need more control than the http.Handler provides (e.g. a CLI tool or a
// custom HTTP framework).
//
// On success the Registration (and Deployment, if present) are persisted via
// cfg.RegistrationStore before being returned.
func Register(ctx context.Context, cfg DynRegConfig, openidConfigURL, registrationToken string) (*RegistrationResult, error) {
	if openidConfigURL == "" {
		return nil, ErrMissingOpenIDConfigURL
	}
	if err := validateOpenIDConfigURL(openidConfigURL, cfg.AllowInsecureOpenIDConfigURL); err != nil {
		return nil, err
	}

	client := cfg.httpClient()

	openidConfig, err := fetchOpenIDConfig(ctx, client, openidConfigURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOpenIDConfigFetch, err)
	}

	// Guard against impersonation: the URL we fetched must be on the same host
	// as the issuer declared inside the document.
	if err := validateDomain(openidConfigURL, openidConfig.Issuer); err != nil {
		return nil, err
	}

	regReq := cfg.buildRequest()
	regResp, err := postRegistration(ctx, client, openidConfig.RegistrationEndpoint, registrationToken, regReq)
	if err != nil {
		return nil, err
	}

	result := buildResult(openidConfig, regResp, cfg.ToolKey, cfg.KID)

	if cfg.RegistrationStore != nil {
		if err := cfg.RegistrationStore.AddRegistration(ctx, *result.Registration); err != nil {
			return nil, fmt.Errorf("lti/dynreg: save registration: %w", err)
		}
		if result.Deployment != nil {
			if err := cfg.RegistrationStore.AddDeployment(ctx, result.Registration.Issuer, *result.Deployment); err != nil {
				return nil, fmt.Errorf("lti/dynreg: save deployment: %w", err)
			}
		}
	}

	return result, nil
}

// buildResult maps the raw HTTP response types to the domain Registration and
// optional Deployment.
func buildResult(openidConfig *OpenIDConfiguration, resp *ClientRegistrationResponse, key *rsa.PrivateKey, kid string) *RegistrationResult {
	reg := &lticore.Registration{
		Issuer:         openidConfig.Issuer,
		ClientID:       resp.ClientID,
		KeySetURL:      openidConfig.JWKSUri,
		AuthTokenURL:   openidConfig.TokenEndpoint,
		AuthLoginURL:   openidConfig.AuthorizationEndpoint,
		AuthServer:     openidConfig.AuthorizationServer,
		ToolPrivateKey: key,
		KID:            kid,
	}

	var dep *lticore.Deployment
	if resp.LTIToolConfiguration != nil && resp.LTIToolConfiguration.DeploymentID != "" {
		dep = &lticore.Deployment{DeploymentID: resp.LTIToolConfiguration.DeploymentID}
	}

	return &RegistrationResult{Registration: reg, Deployment: dep}
}

// buildRequest assembles a ClientRegistrationRequest from the Config.
func (cfg *DynRegConfig) buildRequest() *ClientRegistrationRequest {
	return &ClientRegistrationRequest{
		ApplicationType:         "web",
		GrantTypes:              []string{"client_credentials", "implicit"},
		ResponseTypes:           []string{"id_token"},
		RedirectURIs:            cfg.RedirectURIs,
		InitiateLoginURI:        cfg.InitiateLoginUri,
		ClientName:              cfg.ToolName,
		JWKSUri:                 cfg.JWKSUri,
		TokenEndpointAuthMethod: "private_key_jwt",
		Scope:                   strings.Join(cfg.scopes(), " "),
		LogoURI:                 cfg.LogoURI,
		Contacts:                cfg.Contacts,
		ClientURI:               cfg.ClientURI,
		TOSURI:                  cfg.TOSURI,
		PolicyURI:               cfg.PolicyURI,
		LTIToolConfiguration: &LTIToolConfig{
			Domain:           cfg.ToolDomain,
			SecondaryDomains: cfg.SecondaryDomains,
			TargetLinkURI:    cfg.TargetLinkUri,
			CustomParameters: cfg.CustomParameters,
			Description:      cfg.Description,
			Claims:           cfg.Claims,
			Messages:         cfg.Messages,
		},
	}
}

// scopes returns the configured scopes, always prepending "openid".
func (cfg *DynRegConfig) scopes() []string {
	seen := make(map[string]bool, len(cfg.Scopes)+1)
	out := []string{"openid"}
	seen["openid"] = true
	for _, s := range cfg.Scopes {
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	return out
}

// validateOpenIDConfigURL returns an error when rawURL is not a valid OpenID
// configuration URL for the current security mode.
func validateOpenIDConfigURL(rawURL string, allowInsecure bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidOpenIDConfigURL, err)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidOpenIDConfigURL)
	}
	if allowInsecure {
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%w: URL must use http or https scheme", ErrInvalidOpenIDConfigURL)
		}
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: URL must use https scheme", ErrInvalidOpenIDConfigURL)
	}
	return nil
}

// validateDomain checks that the host of configURL exactly matches the host of
// the issuer URL. Subdomain and TLD differences are both rejected.
func validateDomain(configURL, issuer string) error {
	cfgU, err := url.Parse(configURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidOpenIDConfigURL, err)
	}
	issuerU, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("%w: malformed issuer %q: %v", ErrDomainMismatch, issuer, err)
	}
	if cfgU.Host != issuerU.Host {
		return fmt.Errorf("%w: config host %q != issuer host %q", ErrDomainMismatch, cfgU.Host, issuerU.Host)
	}
	return nil
}

// fetchOpenIDConfig fetches and decodes the platform's OpenID Provider
// Configuration from rawURL.
func fetchOpenIDConfig(ctx context.Context, client *http.Client, rawURL string) (*OpenIDConfiguration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("platform returned HTTP %d", resp.StatusCode)
	}

	var cfg OpenIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode OpenID configuration: %w", err)
	}
	if cfg.Issuer == "" {
		return nil, errors.New("OpenID configuration missing issuer")
	}
	if cfg.RegistrationEndpoint == "" {
		return nil, errors.New("OpenID configuration missing registration_endpoint")
	}
	return &cfg, nil
}

// postRegistration POSTs regReq to endpoint and decodes the response.
// token is sent as a Bearer Authorization header when non-empty.
func postRegistration(ctx context.Context, client *http.Client, endpoint, token string, regReq *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	body, err := json.Marshal(regReq)
	if err != nil {
		return nil, fmt.Errorf("marshal registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Platforms may return 200 (LTI DR spec) or 201 (RFC 7591).
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrRegistrationFailed, resp.StatusCode, string(raw))
	}

	var regResp ClientRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("decode registration response: %w", err)
	}
	if regResp.ClientID == "" {
		return nil, fmt.Errorf("%w: response missing client_id", ErrRegistrationFailed)
	}
	return &regResp, nil
}

// closePage is returned to the browser after a successful registration.
// The postMessage tells the platform's frame/opener that the flow is complete.
const closePage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Registration complete</title></head>
<body>
<p>Registration complete. This window will close automatically.</p>
<script>
(window.opener || window.parent).postMessage({subject: 'org.imsglobal.lti.close'}, '*');
</script>
</body>
</html>
`
