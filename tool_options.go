package lti

import (
	"github.com/robertjndw/go-lti-tool/jwks"
	"github.com/robertjndw/go-lti-tool/launch"
	"github.com/robertjndw/go-lti-tool/login"
)

// ToolOption is a functional option for configuring a Tool.
type ToolOption func(*Tool)

// WithDataStore sets the Datastore for the Tool.
func WithDataStore(ds Datastore) ToolOption {
	return func(t *Tool) {
		t.dataStore = ds
	}
}

// WithNonceStore sets the NonceStore for the Tool.
func WithNonceStore(ns NonceStore) ToolOption {
	return func(t *Tool) {
		t.nonceStore = ns
	}
}

// WithLaunchDataStore sets the LaunchDataStore for the Tool.
func WithLaunchDataStore(lds LaunchDataStore) ToolOption {
	return func(t *Tool) {
		t.launchDataStore = lds
	}
}

// WithCookieHandler sets the CookieHandler for the Tool.
func WithCookieHandler(ch CookieHandler) ToolOption {
	return func(t *Tool) {
		t.cookieHandler = ch
	}
}

// WithKeySet sets the KeySetProvider used by HandleJWKS.
// Pass a *jwks.KeySet (from the jwks sub-package) here.
func WithKeySet(ks jwks.KeySetProvider) ToolOption {
	return func(t *Tool) {
		t.keySet = ks
	}
}

// WithAllowedRedirectHosts restricts the host of the target_link_uri login
// parameter (which becomes the OIDC redirect_uri) to the given hosts.
// Recommended in production: the login request is unsigned, so this prevents
// the tool from forwarding attacker-chosen redirect targets to the platform.
func WithAllowedRedirectHosts(hosts ...string) ToolOption {
	return func(t *Tool) {
		t.allowedRedirectHosts = hosts
	}
}

// WithTrustedAudiences sets launch.Config.TrustedAudiences: additional aud
// values the tool accepts besides its own client_id. Convenience wrapper
// around WithLaunchConfig for this security-relevant knob.
func WithTrustedAudiences(auds ...string) ToolOption {
	return WithLaunchConfig(func(c *launch.Config) {
		c.TrustedAudiences = auds
	})
}

// WithLaunchConfig runs fn against the launch.Config built by HandleLaunch,
// after the Tool's own wiring (Datastore, NonceStore, LaunchStore,
// CookieHandler). Use this to set launch-side knobs the dedicated With*
// options don't cover (TrustedAudiences, Leeway, MaxTokenAge, JWKSCacheTTL,
// Validators, JWKSFetchOptions, ...). Set stores via their dedicated With*
// options instead of through fn — fn runs after those are applied and can
// override them, which is usually not what you want.
func WithLaunchConfig(fn func(*launch.Config)) ToolOption {
	return func(t *Tool) {
		t.launchConfigFns = append(t.launchConfigFns, fn)
	}
}

// WithLoginConfig runs fn against the login.Config built by HandleLogin,
// after the Tool's own wiring (Datastore, NonceStore, CookieHandler,
// AllowedRedirectHosts). Use this to set login-side knobs the dedicated
// With* options don't cover. Set stores via their dedicated With* options
// instead of through fn — fn runs after those are applied and can override
// them, which is usually not what you want.
func WithLoginConfig(fn func(*login.Config)) ToolOption {
	return func(t *Tool) {
		t.loginConfigFns = append(t.loginConfigFns, fn)
	}
}
