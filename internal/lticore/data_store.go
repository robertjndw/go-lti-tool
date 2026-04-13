package lticore

import (
	"context"
	"sync"
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

// --- In-memory datastore for the example ---
type MemoryStore struct {
	muReg         sync.RWMutex
	registrations map[string]Registration

	muDeployment sync.RWMutex
	deployments  map[string]Deployment
}

// NewMemoryNonceStore creates a MemoryNonceStore with a 10-minute nonce TTL.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		registrations: make(map[string]Registration),
		deployments:   make(map[string]Deployment),
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
	s.deployments[issuer+dep.DeploymentID] = dep
	return nil
}

func (s *MemoryStore) FindDeployment(_ context.Context, issuer, deploymentID string) (*Deployment, error) {
	s.muDeployment.RLock()
	defer s.muDeployment.RUnlock()
	dep, ok := s.deployments[issuer+deploymentID]
	if !ok {
		return nil, ErrDeploymentNotFound
	}
	return &dep, nil
}
