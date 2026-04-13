package lticore

import (
	"context"
)

// Datastore resolves platform registrations and deployments.
// Callers must implement this interface backed by their own storage.
type Datastore interface {
	// AddRegistration persists a platform Registration keyed by its issuer URL.
	// Calling it again with the same issuer replaces the existing entry.
	AddRegistration(ctx context.Context, reg Registration) error
	// FindRegistrationByIssuer returns the Registration for the given platform issuer URL.
	// Return ErrRegistrationNotFound if no registration exists.
	FindRegistrationByIssuer(ctx context.Context, issuer string) (*Registration, error)

	// AddDeployment persists a Deployment for the given platform issuer.
	AddDeployment(ctx context.Context, issuer string, dep Deployment) error
	// FindDeployment returns the Deployment for the given issuer + deployment ID pair.
	// Return ErrDeploymentNotFound if no deployment exists.
	FindDeployment(ctx context.Context, issuer, deploymentID string) (*Deployment, error)
}
