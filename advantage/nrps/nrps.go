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
	"net/url"
	"strconv"

	"github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/internal/connector"
)

// Context identifies the course context a membership list belongs to.
type Context struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	Title string `json:"title,omitempty"`
}

// Memberships is the full NRPS response: the roster plus the context it
// belongs to and, when the platform supports incremental sync, the URL to
// fetch membership differences later.
type Memberships struct {
	// ID is the membership container URL reported by the platform.
	ID string
	// Context is the course context of the roster.
	Context Context
	// Members is the aggregated roster across all pages.
	Members []Member
	// DifferencesURL, when non-empty, can be requested later to receive only
	// membership changes since this snapshot (rel="differences" Link header).
	DifferencesURL string
}

// membershipsResponse is the NRPS API response envelope.
type membershipsResponse struct {
	ID      string   `json:"id"`
	Context Context  `json:"context"`
	Members []Member `json:"members"`
}

// MembersQuery holds the filter parameters defined by the NRPS spec.
// Zero-value fields are omitted.
type MembersQuery struct {
	// Role restricts results to members with the given role (full URI or
	// simple name, e.g. lti.RoleLearner).
	Role string
	// Limit restricts the page size (the platform may return fewer; pagination
	// is still followed to fetch all matching members).
	Limit int
	// ResourceLinkID restricts results to members with access to that resource
	// link (the "rlid" query parameter). Combine with AGS to know who can be graded.
	ResourceLinkID string
}

// apply appends the query parameters to rawURL.
func (q MembersQuery) apply(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	params := u.Query()
	if q.Role != "" {
		params.Set("role", q.Role)
	}
	if q.Limit > 0 {
		params.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.ResourceLinkID != "" {
		params.Set("rlid", q.ResourceLinkID)
	}
	u.RawQuery = params.Encode()
	return u.String(), nil
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
	m, err := s.GetMemberships(ctx)
	if err != nil {
		return nil, err
	}
	return m.Members, nil
}

// GetMemberships fetches the roster with its context, following pagination
// automatically. An optional MembersQuery filters server-side by role, limit
// and resource link (NRPS spec query parameters). To fetch incremental changes
// later, request the returned DifferencesURL with GetMembershipsFrom.
func (s *Service) GetMemberships(ctx context.Context, query ...MembersQuery) (*Memberships, error) {
	startURL := s.endpoint.ContextMembershipsURL
	if len(query) > 0 {
		var err error
		startURL, err = query[0].apply(startURL)
		if err != nil {
			return nil, fmt.Errorf("nrps: invalid memberships URL: %w", err)
		}
	}
	return s.GetMembershipsFrom(ctx, startURL)
}

// validateMembershipsPage checks a decoded membership container page against
// the NRPS 2.0 response schema's required properties, so a malformed
// container is never exposed to callers as a valid (if sparse) roster.
// A nil Members/Roles slice means the JSON key was absent (a schema
// violation); an empty-but-present array is a valid value.
func validateMembershipsPage(page membershipsResponse) error {
	if page.ID == "" {
		return fmt.Errorf("nrps: membership container missing 'id'")
	}
	if page.Context.ID == "" {
		return fmt.Errorf("nrps: membership container missing 'context.id'")
	}
	if page.Members == nil {
		return fmt.Errorf("nrps: membership container missing 'members'")
	}
	for i, m := range page.Members {
		if m.UserID == "" {
			return fmt.Errorf("nrps: member %d missing 'user_id'", i)
		}
		if m.Roles == nil {
			return fmt.Errorf("nrps: member %d missing 'roles'", i)
		}
		switch m.Status {
		case "", MemberStatusActive, MemberStatusInactive, MemberStatusDeleted:
		default:
			return fmt.Errorf("nrps: member %d has invalid status %q", i, m.Status)
		}
	}
	return nil
}

// GetMembershipsFrom fetches memberships starting at the given URL — either a
// (possibly filtered) container URL or a DifferencesURL from an earlier call.
func (s *Service) GetMembershipsFrom(ctx context.Context, startURL string) (*Memberships, error) {
	result := &Memberships{}
	pageURL := startURL

	for pageURL != "" {
		resp, err := s.conn.Request(ctx, http.MethodGet, pageURL, nil,
			[]string{lti.ScopeNRPS},
			connector.WithAccept("application/vnd.ims.lti-nrps.v2.membershipcontainer+json"),
		)
		if err != nil {
			return nil, fmt.Errorf("nrps: GetMemberships request failed: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("nrps: GetMemberships returned %d: %s", resp.StatusCode, resp.Body)
		}
		var page membershipsResponse
		if err := json.Unmarshal(resp.Body, &page); err != nil {
			return nil, fmt.Errorf("nrps: failed to parse memberships response: %w", err)
		}
		if err := validateMembershipsPage(page); err != nil {
			return nil, err
		}
		if result.ID == "" {
			result.ID = page.ID
			result.Context = page.Context
		}
		for i := range page.Members {
			// NRPS 2.0: an absent status means Active.
			if page.Members[i].Status == "" {
				page.Members[i].Status = MemberStatusActive
			}
		}
		result.Members = append(result.Members, page.Members...)
		if diff := resp.LinkURL("differences"); diff != "" {
			result.DifferencesURL = diff
		}
		pageURL = resp.NextPageURL()
	}
	return result, nil
}
