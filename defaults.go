package lti

import (
	"context"
	"sync"
	"time"
)

type deploymentKey struct{ issuer, deploymentID string }

// MemoryStore is an in-memory Datastore suitable for development and testing.
// NOT suitable for production: data is lost on restart and not shared across instances.
type MemoryStore struct {
	muReg         sync.RWMutex
	registrations map[string]Registration

	muDeployment sync.RWMutex
	deployments  map[deploymentKey]Deployment
}

// NewMemoryStore creates an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		registrations: make(map[string]Registration),
		deployments:   make(map[deploymentKey]Deployment),
	}
}

func (s *MemoryStore) AddRegistration(_ context.Context, reg Registration) error {
	s.muReg.Lock()
	defer s.muReg.Unlock()
	s.registrations[reg.Issuer] = reg
	return nil
}

func (s *MemoryStore) FindRegistrationByIssuer(_ context.Context, issuer string) (*Registration, error) {
	s.muReg.RLock()
	defer s.muReg.RUnlock()
	reg, ok := s.registrations[issuer]
	if !ok {
		return nil, ErrRegistrationNotFound
	}
	return &reg, nil
}

func (s *MemoryStore) AddDeployment(_ context.Context, issuer string, dep Deployment) error {
	s.muDeployment.Lock()
	defer s.muDeployment.Unlock()
	s.deployments[deploymentKey{issuer, dep.DeploymentID}] = dep
	return nil
}

func (s *MemoryStore) FindDeployment(_ context.Context, issuer, deploymentID string) (*Deployment, error) {
	s.muDeployment.RLock()
	defer s.muDeployment.RUnlock()
	dep, ok := s.deployments[deploymentKey{issuer, deploymentID}]
	if !ok {
		return nil, ErrDeploymentNotFound
	}
	return &dep, nil
}

// MemoryLaunchDataStore is an in-memory LaunchDataStore suitable for development
// and testing. NOT suitable for production: data is lost on restart and not
// shared across instances.
type MemoryLaunchDataStore struct {
	mu      sync.RWMutex
	entries map[string]*Launch
}

// NewMemoryLaunchDataStore creates an empty MemoryLaunchDataStore.
func NewMemoryLaunchDataStore() *MemoryLaunchDataStore {
	return &MemoryLaunchDataStore{
		entries: make(map[string]*Launch),
	}
}

// CacheLaunchData stores the launch data under the given launch ID.
func (s *MemoryLaunchDataStore) CacheLaunchData(_ context.Context, launchID string, data *Launch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[launchID] = data
	return nil
}

// GetLaunchData retrieves launch data by launch ID.
func (s *MemoryLaunchDataStore) GetLaunchData(_ context.Context, launchID string) (*Launch, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.entries[launchID]
	if !ok {
		return nil, ErrLaunchNotFound
	}
	return data, nil
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
