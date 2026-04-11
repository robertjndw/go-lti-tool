package lti

import "errors"

// Sentinel errors returned by the SDK.
var (
	ErrRegistrationNotFound = errors.New("lti: registration not found for issuer")
	ErrDeploymentNotFound   = errors.New("lti: deployment not found")
	ErrInvalidState         = errors.New("lti: invalid or missing state parameter")
	ErrInvalidNonce         = errors.New("lti: invalid or expired nonce")
	ErrInvalidJWT           = errors.New("lti: invalid JWT format")
	ErrInvalidSignature     = errors.New("lti: JWT signature verification failed")
	ErrInvalidClaims        = errors.New("lti: invalid LTI claims")
	ErrExpiredJWT           = errors.New("lti: JWT has expired")
	ErrMissingClaim         = errors.New("lti: required claim is missing")
	ErrLaunchNotFound       = errors.New("lti: launch data not found in store")
	ErrNoCookieHandler      = errors.New("lti: no cookie handler configured")
	ErrAGSNotAvailable      = errors.New("lti: AGS endpoint not available in this launch")
	ErrNRPSNotAvailable     = errors.New("lti: NRPS endpoint not available in this launch")
	ErrDeepLinkingNotAvailable = errors.New("lti: deep linking settings not available in this launch")
)
