// Package launch handles LTI 1.3 message launch validation (step 2 of the launch flow).
//
// After the platform redirects the user back to the tool with a signed id_token,
// this package validates the JWT, checks all LTI claims, resolves the deployment,
// and makes the resulting LaunchData available via the request context.
package launch

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/robertjndw/go-lti"
)

// contextKey is an unexported type for context keys in this package.
type contextKey struct{}

// Config holds the dependencies for launch validation.
type Config struct {
	// Datastore resolves registrations and deployments.
	Datastore lti.Datastore

	// NonceStore verifies (and invalidates) nonces.
	NonceStore lti.NonceStore

	// LaunchStore caches validated launch data.
	LaunchStore lti.LaunchDataStore

	// CookieHandler reads/writes cookies. Defaults to lti.DefaultCookieHandler.
	CookieHandler lti.CookieHandler

	// Validators is the set of MessageValidators to run. Defaults to DefaultValidators().
	Validators []MessageValidator

	// JWKSFetchOptions are optional options passed to jwk.Fetch.
	JWKSFetchOptions []jwk.FetchOption

	// SkipNonceCheck disables nonce verification. Only use this in tests.
	SkipNonceCheck bool
}

func (c *Config) cookieHandler() lti.CookieHandler {
	if c.CookieHandler != nil {
		return c.CookieHandler
	}
	return lti.DefaultCookieHandler{}
}

func (c *Config) validators() []MessageValidator {
	if len(c.Validators) > 0 {
		return c.Validators
	}
	return DefaultValidators()
}

// Handler returns an http.Handler middleware that validates the LTI launch POST
// request and stores the LaunchData in the request context. On success it calls
// next; on failure it responds with an appropriate HTTP error.
func Handler(cfg Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ld, err := ValidateLaunch(r.Context(), cfg, r)
		if err != nil {
			http.Error(w, fmt.Sprintf("LTI launch error: %v", err), http.StatusBadRequest)
			return
		}
		ctx := context.WithValue(r.Context(), contextKey{}, ld)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FromContext extracts the LaunchData stored by Handler from a request context.
// Returns false if no launch data is present (e.g. the middleware was not applied).
func FromContext(ctx context.Context) (*lti.LaunchData, bool) {
	ld, ok := ctx.Value(contextKey{}).(*lti.LaunchData)
	return ld, ok
}

// FromCache reconstructs a LaunchData from the launch store using a launch ID.
// Useful for restoring launch context in subsequent requests (e.g. AJAX calls).
func FromCache(ctx context.Context, cfg Config, launchID string) (*lti.LaunchData, error) {
	return cfg.LaunchStore.GetLaunchData(ctx, launchID)
}

// ValidateLaunch processes a launch POST request and returns the validated LaunchData.
// Use this when you prefer not to use the middleware pattern.
func ValidateLaunch(ctx context.Context, cfg Config, r *http.Request) (*lti.LaunchData, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("lti/launch: failed to parse form: %w", err)
	}

	state := r.FormValue("state")
	idToken := r.FormValue("id_token")

	if idToken == "" {
		return nil, fmt.Errorf("lti/launch: missing id_token in request")
	}

	// Step 1: Validate the state cookie.
	if err := validateState(r, state, cfg.cookieHandler()); err != nil {
		return nil, err
	}

	// Step 2: Decode JWT header + body (unverified) to extract iss and kid.
	rawClaims, kid, err := decodeJWTUnverified(idToken)
	if err != nil {
		return nil, fmt.Errorf("lti/launch: %w", err)
	}

	// Step 3: Look up the registration by issuer.
	reg, err := cfg.Datastore.FindRegistrationByIssuer(ctx, rawClaims.Issuer)
	if err != nil {
		return nil, fmt.Errorf("lti/launch: %w", err)
	}

	// Step 4: Fetch the platform's JWKS and verify the JWT signature.
	claims, err := verifyJWT(ctx, idToken, reg, kid, cfg.JWKSFetchOptions)
	if err != nil {
		return nil, fmt.Errorf("lti/launch: %w", err)
	}

	// Step 5: Validate standard OIDC claims.
	if err := validateOIDCClaims(claims, reg); err != nil {
		return nil, err
	}

	// Step 6: Validate the nonce.
	if !cfg.SkipNonceCheck {
		ok, err := cfg.NonceStore.CheckNonce(ctx, claims.Nonce)
		if err != nil {
			return nil, fmt.Errorf("lti/launch: nonce check failed: %w", err)
		}
		if !ok {
			return nil, lti.ErrInvalidNonce
		}
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
	ld := &lti.LaunchData{
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

// validateState checks that the state parameter matches the state cookie.
func validateState(r *http.Request, state string, ch lti.CookieHandler) error {
	if state == "" {
		return lti.ErrInvalidState
	}
	cookieName := "lti1p3_" + state
	cookieValue, err := ch.GetCookie(r, cookieName)
	if err != nil {
		return fmt.Errorf("lti/launch: %w: %v", lti.ErrInvalidState, err)
	}
	if cookieValue != state {
		return lti.ErrInvalidState
	}
	return nil
}

// rawJWTHeader holds the minimal fields we need from the JWT header.
type rawJWTHeader struct {
	KID string `json:"kid"`
	ALG string `json:"alg"`
}

// decodeJWTUnverified decodes the header and payload of a JWT without verifying
// the signature. Used to extract the issuer and KID before fetching the right key.
func decodeJWTUnverified(tokenStr string) (*lti.LTIClaims, string, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, "", lti.ErrInvalidJWT
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("%w: bad header encoding", lti.ErrInvalidJWT)
	}
	var header rawJWTHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, "", fmt.Errorf("%w: bad header JSON", lti.ErrInvalidJWT)
	}

	// Decode payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("%w: bad payload encoding", lti.ErrInvalidJWT)
	}
	var claims lti.LTIClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, "", fmt.Errorf("%w: bad payload JSON: %v", lti.ErrInvalidJWT, err)
	}

	return &claims, header.KID, nil
}

// verifyJWT fetches the platform's JWKS and verifies the JWT signature, returning
// the validated claims.
func verifyJWT(ctx context.Context, tokenStr string, reg *lti.Registration, kid string, fetchOpts []jwk.FetchOption) (*lti.LTIClaims, error) {
	// Fetch the platform's JWKS.
	keySet, err := jwk.Fetch(ctx, reg.KeySetURL, fetchOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch platform JWKS from %q: %w", reg.KeySetURL, err)
	}

	// Find the key that matches the JWT's KID.
	var matchKey jwk.Key
	if kid != "" {
		k, found := keySet.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("%w: no key with kid=%q in platform JWKS", lti.ErrInvalidSignature, kid)
		}
		matchKey = k
	} else {
		// No KID in JWT header — use the first key in the set.
		if keySet.Len() == 0 {
			return nil, fmt.Errorf("%w: platform JWKS is empty", lti.ErrInvalidSignature)
		}
		k, ok := keySet.Key(0)
		if !ok {
			return nil, fmt.Errorf("%w: failed to access key at index 0", lti.ErrInvalidSignature)
		}
		matchKey = k
	}

	// Extract the raw RSA public key.
	var pubKey rsa.PublicKey
	if err := jwk.Export(matchKey, &pubKey); err != nil {
		return nil, fmt.Errorf("%w: failed to export RSA public key: %v", lti.ErrInvalidSignature, err)
	}

	// Verify the JWT signature using golang-jwt.
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	var rawClaims jwt.MapClaims
	_, err = parser.ParseWithClaims(tokenStr, &rawClaims, func(t *jwt.Token) (any, error) {
		return &pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", lti.ErrInvalidSignature, err)
	}

	// Re-marshal the verified payload into our typed claims struct.
	rawPayload, err := json.Marshal(rawClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal claims: %w", err)
	}
	var claims lti.LTIClaims
	if err := json.Unmarshal(rawPayload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse verified claims: %w", err)
	}
	return &claims, nil
}

// validateOIDCClaims checks the standard OIDC claims against the registration.
func validateOIDCClaims(claims *lti.LTIClaims, reg *lti.Registration) error {
	if claims.Issuer != reg.Issuer {
		return fmt.Errorf("%w: iss %q does not match registration issuer %q", lti.ErrInvalidClaims, claims.Issuer, reg.Issuer)
	}
	if !claims.Audience.Contains(reg.ClientID) {
		return fmt.Errorf("%w: aud does not contain client_id %q", lti.ErrInvalidClaims, reg.ClientID)
	}
	if claims.IssuedAt == 0 {
		return fmt.Errorf("%w: iat claim is missing", lti.ErrMissingClaim)
	}
	if claims.Nonce == "" {
		return fmt.Errorf("%w: nonce is missing", lti.ErrMissingClaim)
	}
	if claims.DeploymentID == "" {
		return fmt.Errorf("%w: deployment_id is missing", lti.ErrMissingClaim)
	}
	if claims.MessageType == "" {
		return fmt.Errorf("%w: message_type is missing", lti.ErrMissingClaim)
	}
	if claims.Version == "" {
		return fmt.Errorf("%w: version is missing", lti.ErrMissingClaim)
	}
	// Spec §4.3.2: target_link_uri is required and must be read from the signed JWT,
	// never from the unsigned login initiation request.
	if claims.TargetLinkURI == "" {
		return fmt.Errorf("%w: target_link_uri is missing", lti.ErrMissingClaim)
	}
	return nil
}

// runMessageValidators finds the appropriate validator for the message type and runs it.
func runMessageValidators(validators []MessageValidator, claims *lti.LTIClaims) error {
	for _, v := range validators {
		if v.CanValidate(claims) {
			return v.Validate(claims)
		}
	}
	return fmt.Errorf("%w: no validator found for message_type %q", lti.ErrInvalidClaims, claims.MessageType)
}

// generateLaunchID returns a random base64url-encoded 24-byte token.
func generateLaunchID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
