package lticore

import (
	"context"
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
