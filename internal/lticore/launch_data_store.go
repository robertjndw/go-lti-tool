package lticore

import (
	"context"
	"sync"
)

// LaunchDataStore caches validated launch payloads so they can be retrieved
// by later requests (e.g. service calls triggered after the initial render).
type LaunchDataStore interface {
	// CacheLaunchData stores the launch data under the given launch ID.
	CacheLaunchData(ctx context.Context, launchID string, data *LaunchData) error

	// GetLaunchData retrieves previously cached launch data by launch ID.
	// Return ErrLaunchNotFound if the ID is unknown or expired.
	GetLaunchData(ctx context.Context, launchID string) (*LaunchData, error)
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
