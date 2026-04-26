package lti

import "github.com/robertjndw/go-lti/jwks"

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
