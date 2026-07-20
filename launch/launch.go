// Package launch handles LTI 1.3 message launch validation (step 2 of the launch flow).
//
// After the platform redirects the user back to the tool with a signed id_token,
// this package validates the JWT, checks all LTI claims, resolves the deployment,
// and makes the resulting *Launch available via the request context.
package launch

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	lticore "github.com/robertjndw/go-lti-tool/internal/lticore"
	"github.com/robertjndw/go-lti-tool/internal/randutil"
)

// contextKey is an unexported type for context keys in this package.
type contextKey struct{}

// Config holds the dependencies for launch validation.
type Config struct {
	// Datastore resolves registrations and deployments.
	Datastore lticore.Datastore

	// NonceStore verifies (and invalidates) nonces.
	NonceStore lticore.NonceStore

	// LaunchStore caches validated launch data.
	LaunchStore lticore.LaunchDataStore

	// CookieHandler reads/writes cookies. Defaults to lticore.DefaultCookieHandler.
	CookieHandler lticore.CookieHandler

	// Validators is the set of MessageValidators to run. Defaults to DefaultValidators().
	Validators []MessageValidator

	// JWKSFetchOptions are optional options passed to jwk.Fetch.
	JWKSFetchOptions []jwk.FetchOption

	// Leeway is the clock-skew tolerance applied when validating exp/iat.
	// Defaults to 60 seconds; platform clocks are rarely perfectly in sync.
	Leeway time.Duration

	// MaxTokenAge is the maximum accepted age of the id_token (now minus iat).
	// The IMS Security Framework requires rejecting tokens issued too far in
	// the past. Defaults to 10 minutes (matching the state/nonce TTL); set a
	// negative value to disable the check.
	MaxTokenAge time.Duration

	// JWKSCacheTTL controls how long fetched platform JWKS documents are
	// reused before being re-fetched. A cache miss on an unknown kid always
	// triggers a refresh, so key rotation is picked up immediately.
	// Defaults to 1 hour; set a negative value to disable caching.
	JWKSCacheTTL time.Duration

	// TrustedAudiences lists additional aud values the tool accepts besides its
	// own client_id. The 1EdTech Security Framework requires rejecting tokens
	// carrying audiences the tool does not trust, so by default any aud entry
	// other than the client_id causes the launch to fail.
	TrustedAudiences []string
}

func (c *Config) cookieHandler() lticore.CookieHandler {
	if c.CookieHandler != nil {
		return c.CookieHandler
	}
	return lticore.DefaultCookieHandler{}
}

func (c *Config) validators() []MessageValidator {
	if len(c.Validators) > 0 {
		return c.Validators
	}
	return DefaultValidators()
}

func (c *Config) leeway() time.Duration {
	if c.Leeway > 0 {
		return c.Leeway
	}
	return 60 * time.Second
}

func (c *Config) maxTokenAge() time.Duration {
	if c.MaxTokenAge != 0 {
		return c.MaxTokenAge
	}
	return 10 * time.Minute
}

func (c *Config) jwksCacheTTL() time.Duration {
	if c.JWKSCacheTTL != 0 {
		return c.JWKSCacheTTL
	}
	return time.Hour
}

// Handler returns an http.Handler middleware that validates the LTI launch POST
// request and stores the *Launch in the request context. On success it calls
// next; on failure it responds with an appropriate HTTP error.
func Handler(cfg Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ld, err := ValidateLaunch(r.Context(), cfg, r)
		if err != nil {
			log.Printf("lti/launch: %v", err)
			http.Error(w, "launch failed", statusForError(err))
			return
		}
		// Delete the state cookie — it is one-time use. The nonce prevents JWT
		// replay, but explicit deletion provides defence-in-depth against state reuse.
		if state := r.FormValue("state"); state != "" {
			cfg.cookieHandler().DeleteCookie(w, "lti1p3_"+state)
		}
		ctx := context.WithValue(r.Context(), contextKey{}, ld)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// statusForError maps a ValidateLaunch error to an HTTP status code. The
// 1EdTech Security Framework distinguishes authentication failures (invalid
// state/signature/nonce/expired token, untrusted audience, a platform-reported
// OIDC error) from authorization failures against a known platform (unknown
// registration/deployment); everything else is a malformed request.
func statusForError(err error) int {
	var platformErr *lticore.PlatformError
	switch {
	case errors.As(err, &platformErr):
		return http.StatusUnauthorized
	case errors.Is(err, lticore.ErrRegistrationNotFound), errors.Is(err, lticore.ErrDeploymentNotFound):
		return http.StatusForbidden
	case errors.Is(err, lticore.ErrInvalidState),
		errors.Is(err, lticore.ErrInvalidSignature),
		errors.Is(err, lticore.ErrExpiredJWT),
		errors.Is(err, lticore.ErrInvalidNonce),
		errors.Is(err, lticore.ErrInvalidClaims),
		errors.Is(err, lticore.ErrMissingClaim):
		return http.StatusUnauthorized
	default:
		return http.StatusBadRequest
	}
}

// FromContext extracts the *Launch stored by Handler from a request context.
// Returns false if no launch data is present (e.g. the middleware was not applied).
func FromContext(ctx context.Context) (*lticore.Launch, bool) {
	ld, ok := ctx.Value(contextKey{}).(*lticore.Launch)
	return ld, ok
}

// FromCache reconstructs a *Launch from the launch store using a launch ID.
// Useful for restoring launch context in subsequent requests (e.g. AJAX calls).
func FromCache(ctx context.Context, cfg Config, launchID string) (*lticore.Launch, error) {
	if cfg.LaunchStore == nil {
		return nil, fmt.Errorf("lti/launch: LaunchStore not configured")
	}
	return cfg.LaunchStore.GetLaunchData(ctx, launchID)
}

// ValidateLaunch processes a launch POST request and returns the validated *Launch.
// Use this when you prefer not to use the middleware pattern.
func ValidateLaunch(ctx context.Context, cfg Config, r *http.Request) (*lticore.Launch, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("lti/launch: failed to parse form: %w", err)
	}

	state := r.FormValue("state")
	idToken := r.FormValue("id_token")

	// OIDC Core §3.1.2.6: the platform may POST an error response instead of
	// an id_token (e.g. the user declined consent, or login_required could
	// not be satisfied silently). Surface it as a typed error rather than
	// falling through to the generic "missing id_token" message.
	if errCode := r.FormValue("error"); errCode != "" {
		return nil, &lticore.PlatformError{Code: errCode, Description: r.FormValue("error_description")}
	}

	if idToken == "" {
		return nil, fmt.Errorf("lti/launch: missing id_token in request")
	}

	// Step 1: Validate the state cookie.
	stateData, err := validateState(r, state, cfg.cookieHandler())
	if err != nil {
		return nil, err
	}

	// Step 2: Decode JWT header + body (unverified) to extract iss and kid.
	rawClaims, kid, err := decodeJWTUnverified(idToken)
	if err != nil {
		return nil, fmt.Errorf("lti/launch: %w", err)
	}

	// Step 3: Look up the registration by issuer + client_id (azp/aud).
	reg, err := findRegistration(ctx, cfg.Datastore, rawClaims)
	if err != nil {
		return nil, fmt.Errorf("lti/launch: %w", err)
	}

	// Step 4: Fetch the platform's JWKS and verify the JWT signature.
	claims, err := verifyJWT(ctx, idToken, reg, kid, cfg)
	if err != nil {
		return nil, fmt.Errorf("lti/launch: %w", err)
	}

	// Step 5: Validate standard OIDC claims.
	if err := validateOIDCClaims(claims, reg, cfg); err != nil {
		return nil, err
	}

	// Step 5b: bind the launch to its login-initiation transaction. A state
	// cookie written by login.HandleLogin carries the nonce and
	// target_link_uri issued alongside that state; require them to match so a
	// nonce or target_link_uri from a different login cannot be combined with
	// this state (1EdTech Security Framework transaction binding). Cookies
	// that predate this binding (no bound nonce/target_link_uri) skip the
	// corresponding check.
	if stateData.Nonce != "" && subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(stateData.Nonce)) != 1 {
		return nil, lticore.ErrInvalidNonce
	}
	if stateData.TargetLinkURI != "" && claims.TargetLinkURI != stateData.TargetLinkURI {
		return nil, fmt.Errorf("%w: target_link_uri does not match the login initiation request", lticore.ErrInvalidClaims)
	}

	// Step 6: Validate the nonce.
	ok, err := cfg.NonceStore.CheckNonce(ctx, claims.Nonce)
	if err != nil {
		return nil, fmt.Errorf("lti/launch: nonce check failed: %w", err)
	}
	if !ok {
		return nil, lticore.ErrInvalidNonce
	}

	// Step 7: Look up the deployment.
	dep, err := cfg.Datastore.FindDeployment(ctx, claims.Issuer, claims.DeploymentID)
	if err != nil {
		return nil, fmt.Errorf("lti/launch: %w", err)
	}

	// Step 8: Run message validators.
	if err := runMessageValidators(cfg.validators(), claims); err != nil {
		return nil, err
	}

	// Step 9: Assemble the LaunchData.
	launchID, err := generateLaunchID()
	if err != nil {
		return nil, fmt.Errorf("lti/launch: failed to generate launch ID: %w", err)
	}
	ld := &lticore.Launch{
		LaunchID:     launchID,
		Claims:       claims,
		Registration: reg,
		Deployment:   dep,
	}

	// Step 10: Cache the launch data.
	if cfg.LaunchStore != nil {
		if err := cfg.LaunchStore.CacheLaunchData(ctx, launchID, ld); err != nil {
			return nil, fmt.Errorf("lti/launch: failed to cache launch data: %w", err)
		}
	}

	return ld, nil
}

// validateState checks that the state parameter matches the state cookie using
// a constant-time comparison to prevent timing side-channel attacks. It
// returns the cookie's bound data (nonce/target_link_uri) for transaction
// binding checks against the verified claims.
func validateState(r *http.Request, state string, ch lticore.CookieHandler) (lticore.StateCookieData, error) {
	if state == "" {
		return lticore.StateCookieData{}, lticore.ErrInvalidState
	}
	cookieName := "lti1p3_" + state
	cookieValue, err := ch.GetCookie(r, cookieName)
	if err != nil {
		return lticore.StateCookieData{}, fmt.Errorf("lti/launch: %w: %w", lticore.ErrInvalidState, err)
	}
	data := lticore.DecodeStateCookie(cookieValue)
	if subtle.ConstantTimeCompare([]byte(data.State), []byte(state)) != 1 {
		return lticore.StateCookieData{}, lticore.ErrInvalidState
	}
	return data, nil
}

// rawJWTHeader holds the minimal fields we need from the JWT header.
type rawJWTHeader struct {
	KID string `json:"kid"`
	ALG string `json:"alg"`
}

// decodeJWTUnverified decodes the header and payload of a JWT without verifying
// the signature. Used to extract the issuer and KID before fetching the right key.
func decodeJWTUnverified(tokenStr string) (*lticore.LTIClaims, string, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, "", lticore.ErrInvalidJWT
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("%w: bad header encoding", lticore.ErrInvalidJWT)
	}
	var header rawJWTHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, "", fmt.Errorf("%w: bad header JSON", lticore.ErrInvalidJWT)
	}

	// Decode payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("%w: bad payload encoding", lticore.ErrInvalidJWT)
	}
	var claims lticore.LTIClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, "", fmt.Errorf("%w: bad payload JSON: %v", lticore.ErrInvalidJWT, err)
	}

	return &claims, header.KID, nil
}

// findRegistration resolves the registration for the token's issuer, using the
// client_id hints available in the unverified claims (azp, then aud values) to
// disambiguate issuers that host multiple registrations. The claims are only
// hints at this point — the id_token signature and audience are verified
// against the resolved registration afterwards.
func findRegistration(ctx context.Context, ds lticore.Datastore, claims *lticore.LTIClaims) (*lticore.Registration, error) {
	var candidates []string
	if claims.Azp != "" {
		candidates = append(candidates, claims.Azp)
	}
	for _, aud := range claims.Audience {
		if aud != claims.Azp {
			candidates = append(candidates, aud)
		}
	}
	if len(candidates) == 0 {
		return lticore.FindRegistration(ctx, ds, claims.Issuer, "")
	}
	var lastErr error
	for _, clientID := range candidates {
		reg, err := lticore.FindRegistration(ctx, ds, claims.Issuer, clientID)
		if err == nil {
			return reg, nil
		}
		lastErr = err
	}
	// No candidate matched. Fall back to the issuer's (unambiguous) registration
	// so that a bad aud fails later with a clear "aud does not contain client_id"
	// error instead of a registration-not-found error.
	if reg, err := lticore.FindRegistration(ctx, ds, claims.Issuer, ""); err == nil {
		return reg, nil
	}
	return nil, lastErr
}

// jwksCacheEntry is a cached platform JWKS document.
type jwksCacheEntry struct {
	set       jwk.Set
	fetchedAt time.Time
}

// jwksCache caches platform key sets by URL across launches so that each launch
// does not depend on (and wait for) the platform's JWKS endpoint.
var jwksCache sync.Map // KeySetURL → *jwksCacheEntry

// fetchKeySet returns the platform JWKS, from cache when fresh unless
// forceRefresh is set. fromCache reports whether the returned set was served
// from the cache. ttl <= 0 disables caching entirely.
func fetchKeySet(ctx context.Context, url string, ttl time.Duration, fetchOpts []jwk.FetchOption, forceRefresh bool) (set jwk.Set, fromCache bool, err error) {
	if ttl > 0 && !forceRefresh {
		if v, ok := jwksCache.Load(url); ok {
			entry := v.(*jwksCacheEntry)
			if time.Since(entry.fetchedAt) < ttl {
				return entry.set, true, nil
			}
		}
	}
	set, err = jwk.Fetch(ctx, url, fetchOpts...)
	if err != nil {
		return nil, false, fmt.Errorf("failed to fetch platform JWKS: %w", err)
	}
	if ttl > 0 {
		jwksCache.Store(url, &jwksCacheEntry{set: set, fetchedAt: time.Now()})
	}
	return set, false, nil
}

// candidateKeys returns the verification keys to try: the key matching kid when
// one is present, or every key in the set when the JWT header omits kid.
func candidateKeys(keySet jwk.Set, kid string) []jwk.Key {
	if kid != "" {
		if k, found := keySet.LookupKeyID(kid); found {
			return []jwk.Key{k}
		}
		return nil
	}
	keys := make([]jwk.Key, 0, keySet.Len())
	for i := 0; i < keySet.Len(); i++ {
		if k, ok := keySet.Key(i); ok {
			keys = append(keys, k)
		}
	}
	return keys
}

// tryVerify attempts signature verification with each candidate key, returning
// the verified raw claims from the first key that succeeds.
func tryVerify(parser *jwt.Parser, tokenStr string, keys []jwk.Key) (jwt.MapClaims, error) {
	var lastErr error
	for _, key := range keys {
		var pubKey rsa.PublicKey
		if err := jwk.Export(key, &pubKey); err != nil {
			lastErr = fmt.Errorf("failed to export RSA public key: %w", err)
			continue
		}
		rawClaims := jwt.MapClaims{}
		_, err := parser.ParseWithClaims(tokenStr, &rawClaims, func(t *jwt.Token) (any, error) {
			return &pubKey, nil
		})
		if err == nil {
			return rawClaims, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no verification keys available")
	}
	return nil, lastErr
}

// verifyJWT fetches the platform's JWKS and verifies the JWT signature, returning
// the validated claims. When verification fails against a cached key set the
// JWKS is re-fetched once and verification retried, so platform key rotation is
// picked up immediately.
func verifyJWT(ctx context.Context, tokenStr string, reg *lticore.Registration, kid string, cfg Config) (*lticore.LTIClaims, error) {
	ttl := cfg.jwksCacheTTL()
	keySet, fromCache, err := fetchKeySet(ctx, reg.KeySetURL, ttl, cfg.JWKSFetchOptions, false)
	if err != nil {
		return nil, err
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(cfg.leeway()),
	)

	keys := candidateKeys(keySet, kid)
	rawClaims, verifyErr := tryVerify(parser, tokenStr, keys)
	if verifyErr != nil && fromCache {
		// The cached key set may be stale (rotated keys): refresh once and retry.
		keySet, _, err = fetchKeySet(ctx, reg.KeySetURL, ttl, cfg.JWKSFetchOptions, true)
		if err != nil {
			return nil, err
		}
		keys = candidateKeys(keySet, kid)
		rawClaims, verifyErr = tryVerify(parser, tokenStr, keys)
	}
	if verifyErr != nil {
		if len(keys) == 0 && kid != "" {
			return nil, fmt.Errorf("%w: no key with kid=%q in platform JWKS", lticore.ErrInvalidSignature, kid)
		}
		return nil, fmt.Errorf("%w: %v", lticore.ErrInvalidSignature, verifyErr)
	}

	// Re-marshal the verified payload into our typed claims struct.
	rawPayload, err := json.Marshal(rawClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal claims: %w", err)
	}
	var claims lticore.LTIClaims
	if err := json.Unmarshal(rawPayload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse verified claims: %w", err)
	}
	return &claims, nil
}

// validateOIDCClaims checks the standard OIDC claims against the registration.
func validateOIDCClaims(claims *lticore.LTIClaims, reg *lticore.Registration, cfg Config) error {
	if claims.Issuer != reg.Issuer {
		return fmt.Errorf("%w: iss does not match registration", lticore.ErrInvalidClaims)
	}
	if !claims.Audience.Contains(reg.ClientID) {
		return fmt.Errorf("%w: aud does not contain client_id", lticore.ErrInvalidClaims)
	}
	// 1EdTech Security Framework: reject tokens carrying audiences the tool
	// does not trust (client_id plus any configured TrustedAudiences).
	for _, aud := range claims.Audience {
		if aud != reg.ClientID && !slices.Contains(cfg.TrustedAudiences, aud) {
			return fmt.Errorf("%w: aud contains untrusted audience %q", lticore.ErrInvalidClaims, aud)
		}
	}
	// OIDC Core §3.1.3.7: with multiple audiences azp must be present, and when
	// present it must equal the client_id.
	if claims.Azp != "" && claims.Azp != reg.ClientID {
		return fmt.Errorf("%w: azp does not match client_id", lticore.ErrInvalidClaims)
	}
	if len(claims.Audience) > 1 && claims.Azp == "" {
		return fmt.Errorf("%w: azp is required when aud has multiple values", lticore.ErrMissingClaim)
	}
	if claims.IssuedAt == 0 {
		return fmt.Errorf("%w: iat claim is missing", lticore.ErrMissingClaim)
	}
	// IMS Security Framework: reject tokens issued too far in the past even if
	// they have not yet expired.
	if maxTokenAge := cfg.maxTokenAge(); maxTokenAge > 0 {
		age := time.Since(time.Unix(claims.IssuedAt, 0))
		if age > maxTokenAge+cfg.leeway() {
			return fmt.Errorf("%w: token issued too long ago (iat age %s exceeds %s)", lticore.ErrExpiredJWT, age.Round(time.Second), maxTokenAge)
		}
	}
	if claims.Nonce == "" {
		return fmt.Errorf("%w: nonce is missing", lticore.ErrMissingClaim)
	}
	if claims.DeploymentID == "" {
		return fmt.Errorf("%w: deployment_id is missing", lticore.ErrMissingClaim)
	}
	if claims.MessageType == "" {
		return fmt.Errorf("%w: message_type is missing", lticore.ErrMissingClaim)
	}
	if claims.Version == "" {
		return fmt.Errorf("%w: version is missing", lticore.ErrMissingClaim)
	}
	// Spec §4.3.2: target_link_uri is required and must be read from the signed JWT,
	// never from the unsigned login initiation request.
	if claims.TargetLinkURI == "" {
		return fmt.Errorf("%w: target_link_uri is missing", lticore.ErrMissingClaim)
	}
	return validateCoreClaimSchema(claims)
}

// maxIdentifierLength is the Core spec's bound on sub, deployment_id,
// resource_link.id, context.id, and tool_platform.guid: at most 255 ASCII characters.
const maxIdentifierLength = 255

// membershipSubRolePattern matches the Core Appendix A sub-role construction
// documented under the membership namespace: a principal role segment
// followed by a specific sub-role fragment (e.g.
// ".../membership/Instructor#TeachingAssistant"). This is an open-ended,
// documented pattern distinct from the closed base-role vocabulary
// (lticore.StandardRoles), so it is recognized structurally instead of via
// exhaustive enumeration. A bare "membership#SomeFragment" does NOT match:
// that form belongs to the closed vocabulary and must be an exact match.
var membershipSubRolePattern = regexp.MustCompile(`^` + regexp.QuoteMeta(lticore.MembershipSubRolePrefix) + `[^/#]+#[^/#]+$`)

// isStandardRole reports whether role is drawn from the Core Appendix A role
// vocabularies (system, institution, and membership/context roles) or the
// documented sub-role construction. A namespace prefix alone with a made-up
// fragment (e.g. ".../membership#NotARealRole") is not sufficient.
func isStandardRole(role string) bool {
	return slices.Contains(lticore.StandardRoles, role) || membershipSubRolePattern.MatchString(role)
}

// isStandardContextType reports whether t is one of the Core Appendix A.1
// context type vocabulary's exact values.
func isStandardContextType(t string) bool {
	return slices.Contains(lticore.StandardContextTypes, t)
}

// validateCoreClaimSchema enforces Core 1.3 schema constraints on claims that
// are only meaningful once the token is otherwise trusted: identifier length
// bounds, required members of optional claim objects, and closed vocabularies.
func validateCoreClaimSchema(claims *lticore.LTIClaims) error {
	if len(claims.Subject) > maxIdentifierLength {
		return fmt.Errorf("%w: sub exceeds %d characters", lticore.ErrInvalidClaims, maxIdentifierLength)
	}
	if len(claims.DeploymentID) > maxIdentifierLength {
		return fmt.Errorf("%w: deployment_id exceeds %d characters", lticore.ErrInvalidClaims, maxIdentifierLength)
	}
	if claims.ResourceLink != nil && len(claims.ResourceLink.ID) > maxIdentifierLength {
		return fmt.Errorf("%w: resource_link.id exceeds %d characters", lticore.ErrInvalidClaims, maxIdentifierLength)
	}
	if claims.Context != nil {
		if claims.Context.ID == "" {
			return fmt.Errorf("%w: context.id is required when context is present", lticore.ErrInvalidClaims)
		}
		if len(claims.Context.ID) > maxIdentifierLength {
			return fmt.Errorf("%w: context.id exceeds %d characters", lticore.ErrInvalidClaims, maxIdentifierLength)
		}
		if len(claims.Context.Type) > 0 && !slices.ContainsFunc(claims.Context.Type, isStandardContextType) {
			return fmt.Errorf("%w: context.type does not include a recognized context type", lticore.ErrInvalidClaims)
		}
	}
	if claims.ToolPlatform != nil {
		if claims.ToolPlatform.GUID == "" {
			return fmt.Errorf("%w: tool_platform.guid is required when tool_platform is present", lticore.ErrInvalidClaims)
		}
		if len(claims.ToolPlatform.GUID) > maxIdentifierLength {
			return fmt.Errorf("%w: tool_platform.guid exceeds %d characters", lticore.ErrInvalidClaims, maxIdentifierLength)
		}
	}
	if len(claims.Roles) > 0 && !slices.ContainsFunc(claims.Roles, isStandardRole) {
		return fmt.Errorf("%w: roles does not include a role from the standard vocabularies", lticore.ErrInvalidClaims)
	}
	if len(claims.RoleScopeMentor) > 0 && !slices.Contains(claims.Roles, lticore.RoleMentor) {
		return fmt.Errorf("%w: role_scope_mentor requires the Mentor role in roles", lticore.ErrInvalidClaims)
	}
	if claims.LaunchPresentation != nil && claims.LaunchPresentation.DocumentTarget != "" {
		switch claims.LaunchPresentation.DocumentTarget {
		case lticore.DocumentTargetFrame, lticore.DocumentTargetIframe, lticore.DocumentTargetWindow:
		default:
			return fmt.Errorf("%w: launch_presentation.document_target must be frame, iframe, or window", lticore.ErrInvalidClaims)
		}
	}
	// 1EdTech Security Framework §3 requires TLS for LTI message URLs;
	// return_url is where the tool redirects the user back to the platform.
	if claims.LaunchPresentation != nil && claims.LaunchPresentation.ReturnURL != "" && !isFullyQualifiedHTTPSURL(claims.LaunchPresentation.ReturnURL) {
		return fmt.Errorf("%w: launch_presentation.return_url must be a fully-qualified https URL", lticore.ErrInvalidClaims)
	}
	return nil
}

// isFullyQualifiedHTTPSURL reports whether s is an absolute https URL with a host.
func isFullyQualifiedHTTPSURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// runMessageValidators finds the appropriate validator for the message type and runs it.
func runMessageValidators(validators []MessageValidator, claims *lticore.LTIClaims) error {
	for _, v := range validators {
		if v.CanValidate(claims) {
			return v.Validate(claims)
		}
	}
	return fmt.Errorf("%w: no validator found for message_type %q", lticore.ErrInvalidClaims, claims.MessageType)
}

func generateLaunchID() (string, error) {
	return randutil.Token(24)
}
