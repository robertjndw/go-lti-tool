package lticore

import (
	"context"
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
