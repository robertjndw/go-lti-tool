package lticore

import (
	"context"
	"sync"
	"time"
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

// nonceEntry holds a nonce and the time it expires.
type nonceEntry struct {
	expiresAt time.Time
}

// MemoryNonceStore is an in-memory NonceStore suitable for development and testing.
// It is NOT suitable for production use: nonces are not persisted across restarts
// and will not work correctly in multi-instance deployments.
type MemoryNonceStore struct {
	mu     sync.Mutex
	nonces map[string]nonceEntry
	ttl    time.Duration
}

// NewMemoryNonceStore creates a MemoryNonceStore with a 10-minute nonce TTL.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{
		nonces: make(map[string]nonceEntry),
		ttl:    10 * time.Minute,
	}
}

// StoreNonce stores the nonce with a TTL expiry.
func (s *MemoryNonceStore) StoreNonce(_ context.Context, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[nonce] = nonceEntry{expiresAt: time.Now().Add(s.ttl)}
	return nil
}

// CheckNonce verifies the nonce is present and unexpired, then deletes it (one-time use).
func (s *MemoryNonceStore) CheckNonce(_ context.Context, nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.nonces[nonce]
	if !ok {
		return false, nil
	}
	delete(s.nonces, nonce)
	if time.Now().After(entry.expiresAt) {
		return false, nil
	}
	return true, nil
}
