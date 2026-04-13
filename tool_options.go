package lti

type ToolOptions func(*Tool)

// WithDataStore sets the Datastore for the Tool.
func WithDataStore(ds Datastore) ToolOptions {
	return func(t *Tool) {
		t.dataStore = ds
	}
}

// WithNonceStore sets the NonceStore for the Tool.
func WithNonceStore(ns NonceStore) ToolOptions {
	return func(t *Tool) {
		t.nonceStore = ns
	}
}

// WithLaunchDataStore sets the LaunchDataStore for the Tool.
func WithLaunchDataStore(lds LaunchDataStore) ToolOptions {
	return func(t *Tool) {
		t.launchDataStore = lds
	}
}

// WithCookieHandler sets the CookieHandler for the Tool.
func WithCookieHandler(ch CookieHandler) ToolOptions {
	return func(t *Tool) {
		t.cookieHandler = ch
	}
}
