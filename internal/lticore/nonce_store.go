package lticore

import (
	"context"
)

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
