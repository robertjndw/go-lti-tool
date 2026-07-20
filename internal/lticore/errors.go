package lticore

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by the SDK.
var (
	ErrRegistrationNotFound    = errors.New("lti: registration not found for issuer")
	ErrDeploymentNotFound      = errors.New("lti: deployment not found")
	ErrInvalidState            = errors.New("lti: invalid or missing state parameter")
	ErrInvalidNonce            = errors.New("lti: invalid or expired nonce")
	ErrInvalidJWT              = errors.New("lti: invalid JWT format")
	ErrInvalidSignature        = errors.New("lti: JWT signature verification failed")
	ErrInvalidClaims           = errors.New("lti: invalid LTI claims")
	ErrExpiredJWT              = errors.New("lti: JWT has expired")
	ErrMissingClaim            = errors.New("lti: required claim is missing")
	ErrLaunchNotFound          = errors.New("lti: launch data not found in store")
	ErrNoCookieHandler         = errors.New("lti: no cookie handler configured")
	ErrAGSNotAvailable         = errors.New("lti: AGS endpoint not available in this launch")
	ErrNRPSNotAvailable        = errors.New("lti: NRPS endpoint not available in this launch")
	ErrDeepLinkingNotAvailable = errors.New("lti: deep linking settings not available in this launch")

	// ErrLTI11ClaimMissing is returned by VerifyLTI11ConsumerKeySign when the
	// launch has no lti1p1 claim, or the claim lacks oauth_consumer_key or
	// oauth_consumer_key_sign.
	ErrLTI11ClaimMissing = errors.New("lti: lti1p1 migration claim missing or incomplete")

	// ErrLTI11SignInvalid is returned by VerifyLTI11ConsumerKeySign when the
	// oauth_consumer_key_sign does not verify against the given secret, or
	// clientID is not an audience of the token.
	ErrLTI11SignInvalid = errors.New("lti: lti1p1 oauth_consumer_key_sign is invalid")
)

// PlatformError is an OIDC/OAuth error response the platform POSTed to the
// launch endpoint instead of an id_token (OIDC Core §3.1.2.6).
type PlatformError struct {
	Code        string // the "error" parameter, e.g. "login_required"
	Description string // the optional "error_description" parameter
}

func (e *PlatformError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("lti: platform returned error %q: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("lti: platform returned error %q", e.Code)
}
