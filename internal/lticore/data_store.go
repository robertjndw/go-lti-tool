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

// RegistrationFinder is an optional extension of Datastore for deployments
// where one issuer hosts multiple registrations (e.g. cloud Canvas, where every
// school shares the issuer https://canvas.instructure.com). LTI 1.3 identifies
// a registration by the (issuer, client_id) pair; implement this interface to
// disambiguate.
type RegistrationFinder interface {
	// FindRegistration returns the Registration for the given issuer and
	// client_id. When clientID is empty the implementation should return the
	// registration for the issuer if it is unambiguous, and an error otherwise.
	// Return ErrRegistrationNotFound if no matching registration exists.
	FindRegistration(ctx context.Context, issuer, clientID string) (*Registration, error)
}

// FindRegistration resolves a registration by issuer and (optionally) client_id.
// It uses the RegistrationFinder interface when the datastore implements it and
// falls back to FindRegistrationByIssuer otherwise, verifying the client_id on
// the returned registration when one was supplied.
func FindRegistration(ctx context.Context, ds Datastore, issuer, clientID string) (*Registration, error) {
	if rf, ok := ds.(RegistrationFinder); ok {
		return rf.FindRegistration(ctx, issuer, clientID)
	}
	reg, err := ds.FindRegistrationByIssuer(ctx, issuer)
	if err != nil {
		return nil, err
	}
	if clientID != "" && reg.ClientID != clientID {
		return nil, ErrRegistrationNotFound
	}
	return reg, nil
}

// RegistrationWriter persists platform registrations and deployments.
// Datastores that support dynamic registration must implement this in addition to Datastore.
type RegistrationWriter interface {
	// AddRegistration persists a platform Registration keyed by its issuer URL.
	// Calling it again with the same issuer replaces the existing entry.
	AddRegistration(ctx context.Context, reg Registration) error
	// AddDeployment persists a Deployment for the given platform issuer.
	AddDeployment(ctx context.Context, issuer string, dep Deployment) error
}
