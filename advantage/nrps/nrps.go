// Package nrps implements the LTI Advantage Names & Role Provisioning Services (NRPS) v2.0.
//
// NRPS allows a tool to retrieve the course roster with roles from the platform.
// Pagination is handled automatically.
//
// Usage:
//
//	svc, err := nrps.NewFromLaunch(launchData)
//	members, err := svc.GetMembers(ctx)
//	for _, m := range members {
//	    fmt.Printf("%s <%s>\n", m.Name, m.Email)
//	}
package nrps

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/internal/connector"
)

// membershipsResponse is the NRPS API response envelope.
type membershipsResponse struct {
	ID      string   `json:"id"`
	Context struct { //nolint:govet
		ID    string `json:"id"`
		Label string `json:"label,omitempty"`
		Title string `json:"title,omitempty"`
	} `json:"context"`
	Members []Member `json:"members"`
}

// Service provides NRPS roster operations for a specific launch context.
type Service struct {
	conn     *connector.Connector
	endpoint *lti.NRPSClaim
}

// New creates an NRPS Service using the given Connector and endpoint claim.
func New(conn *connector.Connector, endpoint *lti.NRPSClaim) *Service {
	return &Service{conn: conn, endpoint: endpoint}
}

// NewFromLaunch creates an NRPS Service from a validated *lti.Launch.
// Returns ErrNRPSNotAvailable if the launch does not include NRPS claims.
func NewFromLaunch(ld *lti.Launch) (*Service, error) {
	if !ld.HasNRPS() {
		return nil, lti.ErrNRPSNotAvailable
	}
	conn := connector.New(ld.Registration)
	return New(conn, ld.Claims.NRPS), nil
}

// GetMembers fetches the full course roster, following pagination automatically.
func (s *Service) GetMembers(ctx context.Context) ([]Member, error) {
	var all []Member
	pageURL := s.endpoint.ContextMembershipsURL

	for pageURL != "" {
		resp, err := s.conn.Request(ctx, http.MethodGet, pageURL, nil,
			[]string{lti.ScopeNRPS},
			connector.WithAccept("application/vnd.ims.lti-nrps.v2.membershipcontainer+json"),
		)
		if err != nil {
			return nil, fmt.Errorf("nrps: GetMembers request failed: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("nrps: GetMembers returned %d: %s", resp.StatusCode, resp.Body)
		}
		var page membershipsResponse
		if err := json.Unmarshal(resp.Body, &page); err != nil {
			return nil, fmt.Errorf("nrps: failed to parse memberships response: %w", err)
		}
		all = append(all, page.Members...)
		pageURL = resp.NextPageURL()
	}
	return all, nil
}
