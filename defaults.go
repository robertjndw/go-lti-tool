package lti

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// DefaultCookieHandler writes SameSite=None; Secure cookies and a LEGACY_ prefixed
// fallback for browsers that strip SameSite=None cookies (mirrors the PHP reference
// implementation's iframe compatibility behaviour).
type DefaultCookieHandler struct{}

// GetCookie reads the named cookie. It prefers the SameSite=None version but falls
// back to the LEGACY_ prefixed cookie if the main one is absent.
func (h DefaultCookieHandler) GetCookie(r *http.Request, name string) (string, error) {
	if c, err := r.Cookie(name); err == nil {
		return c.Value, nil
	}
	if c, err := r.Cookie("LEGACY_" + name); err == nil {
		return c.Value, nil
	}
	return "", http.ErrNoCookie
}

// SetCookie writes both a SameSite=None; Secure cookie and a LEGACY_ version without
// SameSite, ensuring compatibility with browsers that block third-party SameSite=None
// cookies while embedded in iframes.
func (h DefaultCookieHandler) SetCookie(w http.ResponseWriter, name, value string, maxAge int) {
	base := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   maxAge,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(w, base)

	legacy := &http.Cookie{
		Name:     "LEGACY_" + name,
		Value:    value,
		MaxAge:   maxAge,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, legacy)
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

// MemoryLaunchDataStore is an in-memory LaunchDataStore suitable for development
// and testing. NOT suitable for production: data is lost on restart and not
// shared across instances.
type MemoryLaunchDataStore struct {
	mu      sync.RWMutex
	entries map[string]*LaunchData
}

// NewMemoryLaunchDataStore creates an empty MemoryLaunchDataStore.
func NewMemoryLaunchDataStore() *MemoryLaunchDataStore {
	return &MemoryLaunchDataStore{
		entries: make(map[string]*LaunchData),
	}
}

// CacheLaunchData stores the launch data under the given launch ID.
func (s *MemoryLaunchDataStore) CacheLaunchData(_ context.Context, launchID string, data *LaunchData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[launchID] = data
	return nil
}

// GetLaunchData retrieves launch data by launch ID.
func (s *MemoryLaunchDataStore) GetLaunchData(_ context.Context, launchID string) (*LaunchData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.entries[launchID]
	if !ok {
		return nil, ErrLaunchNotFound
	}
	return data, nil
}
