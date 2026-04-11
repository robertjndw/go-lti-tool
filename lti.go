// Package lti provides a Go SDK for LTI 1.3 (Learning Tools Interoperability).
//
// The SDK targets tool implementations (not platforms) and covers the full LTI
// Advantage surface: OIDC launch flow, Assignment & Grade Services (AGS),
// Names & Role Provisioning Services (NRPS), and Deep Linking.
//
// # Architecture
//
// The SDK is split into a core layer and a service layer:
//
//   - Core (this package + login/, launch/, jwks/): OIDC login initiation,
//     JWT validation, and serving the tool's JWKS endpoint.
//   - Services (connector/, advantage/ags/, advantage/nrps/, advantage/deeplink/):
//     LTI Advantage service calls. Import only what you need.
//
// # Quickstart
//
//	store := &MyDatastore{}              // implements lti.Datastore
//	nonces := lti.NewMemoryNonceStore()
//	launches := lti.NewMemoryLaunchDataStore()
//
//	mux := http.NewServeMux()
//	mux.Handle("/oidc/login", login.Handler(login.Config{
//	    Datastore: store, NonceStore: nonces,
//	}))
//	mux.Handle("/lti/launch", launch.Handler(
//	    launch.Config{Datastore: store, NonceStore: nonces, LaunchStore: launches},
//	    http.HandlerFunc(myLaunchHandler),
//	))
//	mux.Handle("/.well-known/jwks.json", jwks.FromRegistration(reg).Handler())
//	http.ListenAndServe(":8080", mux)
package lti

import (
	"context"
	"net/http"
)

// Datastore resolves platform registrations and deployments.
// Callers must implement this interface backed by their own storage.
type Datastore interface {
	// FindRegistrationByIssuer returns the Registration for the given platform issuer URL.
	// Return ErrRegistrationNotFound if no registration exists.
	FindRegistrationByIssuer(ctx context.Context, issuer string) (*Registration, error)

	// FindDeployment returns the Deployment for the given issuer + deployment ID pair.
	// Return ErrDeploymentNotFound if no deployment exists.
	FindDeployment(ctx context.Context, issuer, deploymentID string) (*Deployment, error)
}

// NonceStore tracks OIDC nonces to prevent replay attacks.
// Implementations should auto-expire entries (recommended TTL: 5–10 minutes).
type NonceStore interface {
	// StoreNonce stores a nonce. Return an error if storing fails.
	StoreNonce(ctx context.Context, nonce string) error

	// CheckNonce verifies and invalidates a nonce. Returns true if the nonce
	// was previously stored and has not yet been used. Must consume the nonce
	// (mark it used) so the same nonce cannot be validated twice.
	CheckNonce(ctx context.Context, nonce string) (bool, error)
}

// LaunchDataStore caches validated launch payloads so they can be retrieved
// by later requests (e.g. service calls triggered after the initial render).
type LaunchDataStore interface {
	// CacheLaunchData stores the launch data under the given launch ID.
	CacheLaunchData(ctx context.Context, launchID string, data *LaunchData) error

	// GetLaunchData retrieves previously cached launch data by launch ID.
	// Return ErrLaunchNotFound if the ID is unknown or expired.
	GetLaunchData(ctx context.Context, launchID string) (*LaunchData, error)
}

// CookieHandler abstracts reading and writing HTTP cookies.
// This allows callers to plug in custom cookie behaviour (e.g. encrypted cookies,
// SameSite=None for iframes, legacy fallbacks) without framework coupling.
type CookieHandler interface {
	// GetCookie reads a named cookie from the request.
	// Return an error (e.g. http.ErrNoCookie) if not found.
	GetCookie(r *http.Request, name string) (string, error)

	// SetCookie writes a cookie to the response.
	// maxAge is in seconds; 0 means session cookie.
	SetCookie(w http.ResponseWriter, name, value string, maxAge int)
}

// LaunchData is the validated, trusted payload produced after a successful launch.
type LaunchData struct {
	// LaunchID is a unique identifier for this launch, used to retrieve it from the store.
	LaunchID string

	// Claims contains the fully parsed and validated JWT body.
	Claims *LTIClaims

	// Registration is the platform registration resolved during validation.
	Registration *Registration

	// Deployment is the deployment resolved during validation.
	Deployment *Deployment
}

// HasAGS reports whether the launch includes an AGS endpoint.
func (ld *LaunchData) HasAGS() bool {
	return ld.Claims.AGS != nil && (ld.Claims.AGS.Lineitems != "" || ld.Claims.AGS.Lineitem != "")
}

// HasNRPS reports whether the launch includes an NRPS endpoint.
func (ld *LaunchData) HasNRPS() bool {
	return ld.Claims.NRPS != nil && ld.Claims.NRPS.ContextMembershipsURL != ""
}

// HasDeepLinking reports whether the launch is a deep linking request.
func (ld *LaunchData) HasDeepLinking() bool {
	return ld.Claims.DeepLinkingSettings != nil && ld.Claims.DeepLinkingSettings.DeepLinkReturnURL != ""
}

// IsResourceLaunch reports whether this is an LtiResourceLinkRequest.
func (ld *LaunchData) IsResourceLaunch() bool {
	return ld.Claims.MessageType == MessageTypeResourceLink
}

// IsDeepLinkLaunch reports whether this is an LtiDeepLinkingRequest.
func (ld *LaunchData) IsDeepLinkLaunch() bool {
	return ld.Claims.MessageType == MessageTypeDeepLinking
}
