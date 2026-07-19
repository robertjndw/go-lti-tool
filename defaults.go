package lti

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type deploymentKey struct{ issuer, deploymentID string }
type registrationKey struct{ issuer, clientID string }

// MemoryStore is an in-memory Datastore suitable for development and testing.
// NOT suitable for production: data is lost on restart and not shared across instances.
// It supports multiple registrations per issuer, keyed by (issuer, client_id).
type MemoryStore struct {
	muReg         sync.RWMutex
	registrations map[registrationKey]Registration

	muDeployment sync.RWMutex
	deployments  map[deploymentKey]Deployment
}

// NewMemoryStore creates an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		registrations: make(map[registrationKey]Registration),
		deployments:   make(map[deploymentKey]Deployment),
	}
}

func (s *MemoryStore) AddRegistration(_ context.Context, reg Registration) error {
	s.muReg.Lock()
	defer s.muReg.Unlock()
	s.registrations[registrationKey{reg.Issuer, reg.ClientID}] = reg
	return nil
}

// FindRegistration returns the registration for the (issuer, client_id) pair.
// With an empty clientID it returns the issuer's registration only when exactly
// one exists; multiple matches are ambiguous and produce an error.
func (s *MemoryStore) FindRegistration(_ context.Context, issuer, clientID string) (*Registration, error) {
	s.muReg.RLock()
	defer s.muReg.RUnlock()
	if clientID != "" {
		reg, ok := s.registrations[registrationKey{issuer, clientID}]
		if !ok {
			return nil, ErrRegistrationNotFound
		}
		return &reg, nil
	}
	var found *Registration
	for key, reg := range s.registrations {
		if key.issuer != issuer {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: multiple registrations for issuer %q, client_id required", ErrRegistrationNotFound, issuer)
		}
		reg := reg
		found = &reg
	}
	if found == nil {
		return nil, ErrRegistrationNotFound
	}
	return found, nil
}

func (s *MemoryStore) FindRegistrationByIssuer(ctx context.Context, issuer string) (*Registration, error) {
	return s.FindRegistration(ctx, issuer, "")
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

// StoreNonce stores the nonce with a TTL expiry. It also evicts any expired
// entries to prevent unbounded growth under high load or adversarial input.
func (s *MemoryNonceStore) StoreNonce(_ context.Context, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, e := range s.nonces {
		if now.After(e.expiresAt) {
			delete(s.nonces, k)
		}
	}
	s.nonces[nonce] = nonceEntry{expiresAt: now.Add(s.ttl)}
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
