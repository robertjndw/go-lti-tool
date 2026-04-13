package lti

import (
	"context"
	"net/http"

	lticore "github.com/robertjndw/go-lti/internal/lticore"
	"github.com/robertjndw/go-lti/launch"
	"github.com/robertjndw/go-lti/login"
)

// Tool is the main entry point for an LTI 1.3 tool. It wires together a
// datastore, nonce store, launch data store and cookie handler into
// ready-to-use http.Handlers.
type Tool struct {
	dataStore       lticore.Datastore
	nonceStore      lticore.NonceStore
	launchDataStore lticore.LaunchDataStore
	cookieHandler   lticore.CookieHandler
}

// NewTool creates a Tool with in-memory stores and the default cookie handler.
// Override any component with the With* option functions.
func NewTool(opts ...ToolOptions) *Tool {
	t := &Tool{
		dataStore:       lticore.NewMemoryStore(),
		nonceStore:      lticore.NewMemoryNonceStore(),
		launchDataStore: lticore.NewMemoryLaunchDataStore(),
		cookieHandler:   lticore.DefaultCookieHandler{},
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// FromContext extracts the LaunchData stored by HandleLaunch from a request context.
// Returns false if the middleware was not applied or validation failed.
func FromContext(ctx context.Context) (*LaunchData, bool) {
	return launch.FromContext(ctx)
}

// GetLaunchData retrieves previously cached launch data by launch ID.
// Useful for restoring launch context in subsequent requests (e.g. after deep-link content selection).
func (t *Tool) GetLaunchData(ctx context.Context, launchID string) (*LaunchData, error) {
	return t.launchDataStore.GetLaunchData(ctx, launchID)
}

// HandleLogin returns an http.Handler for the OIDC login initiation endpoint.
// It validates the incoming request, sets the state cookie, and redirects to
// the platform's OIDC authorization endpoint.
func (t *Tool) HandleLogin() http.Handler {
	return login.Handler(login.Config{
		Datastore:     t.dataStore,
		NonceStore:    t.nonceStore,
		CookieHandler: t.cookieHandler,
	})
}

// HandleLaunch returns an http.Handler middleware that validates an LTI launch
// POST, caches the resulting LaunchData, and makes it available via FromContext
// before calling next.
func (t *Tool) HandleLaunch(next http.Handler) http.Handler {
	return launch.Handler(launch.Config{
		Datastore:   t.dataStore,
		NonceStore:  t.nonceStore,
		LaunchStore: t.launchDataStore,
		CookieHandler: t.cookieHandler,
	}, next)
}
