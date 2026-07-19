// Package ags implements the LTI Advantage Assignment & Grade Services (AGS) v2.0.
//
// AGS allows tools to read and write grade line items and post learner scores
// back to the platform's gradebook.
//
// Usage:
//
//	svc, err := ags.NewFromLaunch(launchData)
//	li, err := svc.FindOrCreateLineitem(ctx, ags.Lineitem{Label: "Quiz 1", ScoreMaximum: 100})
//	err = svc.SubmitScore(ctx, li.ID, ags.Score{
//	    UserID:           launchData.Claims.Subject,
//	    ScoreGiven:       85,
//	    ScoreMaximum:     100,
//	    ActivityProgress: ags.ActivityProgressCompleted,
//	    GradingProgress:  ags.GradingProgressFullyGraded,
//	    Timestamp:        time.Now().UTC().Format(time.RFC3339),
//	})
package ags

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/internal/connector"
)

// appendPathSegment appends segment to the path component of rawURL,
// preserving any existing query string. This is necessary because LMS
// platforms (e.g. Moodle) include query parameters in lineitem URLs, so
// simple string concatenation would place the segment inside the query string.
func appendPathSegment(rawURL, segment string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.JoinPath(segment).String(), nil
}

const (
	contentTypeLineitem  = "application/vnd.ims.lis.v2.lineitem+json"
	contentTypeLineitems = "application/vnd.ims.lis.v2.lineitemcontainer+json"
	contentTypeScore     = "application/vnd.ims.lis.v1.score+json"
	contentTypeResults   = "application/vnd.ims.lis.v2.resultcontainer+json"
)

// Service provides LTI AGS operations for a specific launch context.
type Service struct {
	conn     *connector.Connector
	endpoint *lti.AGSClaim
	// resourceLinkID scopes FindOrCreateLineitem to the launching resource link
	// when the service was built from a launch.
	resourceLinkID string
}

// New creates an AGS Service using the given Connector and endpoint claim.
func New(conn *connector.Connector, endpoint *lti.AGSClaim) *Service {
	return &Service{conn: conn, endpoint: endpoint}
}

// NewFromLaunch creates an AGS Service from a validated *lti.Launch.
// Returns ErrAGSNotAvailable if the launch does not include AGS claims.
func NewFromLaunch(ld *lti.Launch) (*Service, error) {
	if !ld.HasAGS() {
		return nil, lti.ErrAGSNotAvailable
	}
	conn := connector.New(ld.Registration)
	svc := New(conn, ld.Claims.AGS)
	if ld.Claims.ResourceLink != nil {
		svc.resourceLinkID = ld.Claims.ResourceLink.ID
	}
	return svc, nil
}

// LineitemQuery holds the filter parameters defined by the AGS spec for the
// line item container endpoint. Zero-value fields are omitted.
type LineitemQuery struct {
	// ResourceLinkID restricts results to line items bound to that resource link.
	ResourceLinkID string
	// ResourceID restricts results to line items with that tool-defined resourceId.
	ResourceID string
	// Tag restricts results to line items with that tag.
	Tag string
	// Limit restricts the page size (the platform may return fewer; pagination
	// is still followed to fetch all matching items).
	Limit int
}

// apply appends the query parameters to rawURL.
func (q LineitemQuery) apply(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	params := u.Query()
	if q.ResourceLinkID != "" {
		params.Set("resource_link_id", q.ResourceLinkID)
	}
	if q.ResourceID != "" {
		params.Set("resource_id", q.ResourceID)
	}
	if q.Tag != "" {
		params.Set("tag", q.Tag)
	}
	if q.Limit > 0 {
		params.Set("limit", strconv.Itoa(q.Limit))
	}
	u.RawQuery = params.Encode()
	return u.String(), nil
}

// GetLineitems returns line items from the platform gradebook, following
// pagination automatically. An optional LineitemQuery filters server-side by
// resource_link_id, resource_id, tag and limit (AGS spec query parameters).
func (s *Service) GetLineitems(ctx context.Context, query ...LineitemQuery) ([]Lineitem, error) {
	if s.endpoint.Lineitems == "" {
		return nil, fmt.Errorf("ags: lineitems URL is not available in this launch")
	}

	pageURL := s.endpoint.Lineitems
	if len(query) > 0 {
		var err error
		pageURL, err = query[0].apply(pageURL)
		if err != nil {
			return nil, fmt.Errorf("ags: invalid lineitems URL: %w", err)
		}
	}

	var all []Lineitem
	for pageURL != "" {
		resp, err := s.conn.Request(ctx, http.MethodGet, pageURL, nil,
			[]string{lti.ScopeAGSLineitemReadonly},
			connector.WithAccept(contentTypeLineitems),
		)
		if err != nil {
			return nil, fmt.Errorf("ags: GetLineitems request failed: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("ags: GetLineitems returned %d: %s", resp.StatusCode, resp.Body)
		}
		var page []Lineitem
		if err := json.Unmarshal(resp.Body, &page); err != nil {
			return nil, fmt.Errorf("ags: failed to parse lineitems: %w", err)
		}
		all = append(all, page...)
		pageURL = resp.NextPageURL()
	}
	return all, nil
}

// GetLineitem returns a single line item by its URL.
func (s *Service) GetLineitem(ctx context.Context, lineitemURL string) (*Lineitem, error) {
	resp, err := s.conn.Request(ctx, http.MethodGet, lineitemURL, nil,
		[]string{lti.ScopeAGSLineitemReadonly},
		connector.WithAccept(contentTypeLineitem),
	)
	if err != nil {
		return nil, fmt.Errorf("ags: GetLineitem request failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ags: GetLineitem returned %d: %s", resp.StatusCode, resp.Body)
	}
	var li Lineitem
	if err := json.Unmarshal(resp.Body, &li); err != nil {
		return nil, fmt.Errorf("ags: failed to parse lineitem: %w", err)
	}
	return &li, nil
}

// CreateLineitem creates a new line item in the platform gradebook.
func (s *Service) CreateLineitem(ctx context.Context, li Lineitem) (*Lineitem, error) {
	if s.endpoint.Lineitems == "" {
		return nil, fmt.Errorf("ags: lineitems URL is not available in this launch")
	}
	body, err := json.Marshal(li)
	if err != nil {
		return nil, fmt.Errorf("ags: failed to marshal lineitem: %w", err)
	}
	resp, err := s.conn.Request(ctx, http.MethodPost, s.endpoint.Lineitems, bytes.NewReader(body),
		[]string{lti.ScopeAGSLineitem},
		connector.WithContentType(contentTypeLineitem),
		connector.WithAccept(contentTypeLineitem),
	)
	if err != nil {
		return nil, fmt.Errorf("ags: CreateLineitem request failed: %w", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ags: CreateLineitem returned %d: %s", resp.StatusCode, resp.Body)
	}
	var created Lineitem
	if err := json.Unmarshal(resp.Body, &created); err != nil {
		return nil, fmt.Errorf("ags: failed to parse created lineitem: %w", err)
	}
	return &created, nil
}

// UpdateLineitem replaces an existing line item. The Lineitem.ID field must be set.
func (s *Service) UpdateLineitem(ctx context.Context, li Lineitem) (*Lineitem, error) {
	if li.ID == "" {
		return nil, fmt.Errorf("ags: lineitem ID is required for update")
	}
	body, err := json.Marshal(li)
	if err != nil {
		return nil, fmt.Errorf("ags: failed to marshal lineitem: %w", err)
	}
	resp, err := s.conn.Request(ctx, http.MethodPut, li.ID, bytes.NewReader(body),
		[]string{lti.ScopeAGSLineitem},
		connector.WithContentType(contentTypeLineitem),
		connector.WithAccept(contentTypeLineitem),
	)
	if err != nil {
		return nil, fmt.Errorf("ags: UpdateLineitem request failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ags: UpdateLineitem returned %d: %s", resp.StatusCode, resp.Body)
	}
	var updated Lineitem
	if err := json.Unmarshal(resp.Body, &updated); err != nil {
		return nil, fmt.Errorf("ags: failed to parse updated lineitem: %w", err)
	}
	return &updated, nil
}

// DeleteLineitem deletes the line item at the given URL.
func (s *Service) DeleteLineitem(ctx context.Context, lineitemURL string) error {
	resp, err := s.conn.Request(ctx, http.MethodDelete, lineitemURL, nil,
		[]string{lti.ScopeAGSLineitem},
	)
	if err != nil {
		return fmt.Errorf("ags: DeleteLineitem request failed: %w", err)
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ags: DeleteLineitem returned %d: %s", resp.StatusCode, resp.Body)
	}
	return nil
}

// FindOrCreateLineitem looks for an existing line item matching the given
// ResourceID and Tag (scoped to the launching resource link when known), and
// creates one if none is found. Mirrors the PHP reference library's
// find_or_create_lineitem behaviour, with server-side filtering.
func (s *Service) FindOrCreateLineitem(ctx context.Context, li Lineitem) (*Lineitem, error) {
	// If the launch already provided a specific lineitem URL, use it directly.
	// A failure here is a real error: falling through could create a duplicate.
	if s.endpoint.Lineitem != "" {
		existing, err := s.GetLineitem(ctx, s.endpoint.Lineitem)
		if err != nil {
			return nil, fmt.Errorf("ags: FindOrCreateLineitem: launch lineitem fetch failed: %w", err)
		}
		return existing, nil
	}

	// Filter server-side; platforms that ignore the query parameters are
	// handled by the client-side match below.
	resourceLinkID := li.ResourceLinkID
	if resourceLinkID == "" {
		resourceLinkID = s.resourceLinkID
	}
	existing, err := s.GetLineitems(ctx, LineitemQuery{
		ResourceLinkID: resourceLinkID,
		ResourceID:     li.ResourceID,
		Tag:            li.Tag,
	})
	if err != nil {
		return nil, fmt.Errorf("ags: FindOrCreateLineitem: %w", err)
	}

	for i := range existing {
		if li.ResourceID != "" && existing[i].ResourceID != li.ResourceID {
			continue
		}
		if li.Tag != "" && existing[i].Tag != li.Tag {
			continue
		}
		// Never match a line item bound to a different resource link.
		if resourceLinkID != "" && existing[i].ResourceLinkID != "" && existing[i].ResourceLinkID != resourceLinkID {
			continue
		}
		return &existing[i], nil
	}

	return s.CreateLineitem(ctx, li)
}

// SubmitScore posts a Score to the platform for the given line item URL.
func (s *Service) SubmitScore(ctx context.Context, lineitemURL string, score Score) error {
	if score.UserID == "" {
		return fmt.Errorf("ags: SubmitScore: UserID is required")
	}
	if score.ActivityProgress == "" || score.GradingProgress == "" {
		return fmt.Errorf("ags: SubmitScore: ActivityProgress and GradingProgress are required")
	}
	if score.Timestamp == "" {
		return fmt.Errorf("ags: SubmitScore: Timestamp is required (ISO 8601)")
	}
	// AGS spec: scoreMaximum is required whenever scoreGiven is present.
	if score.ScoreGiven != nil {
		if score.ScoreMaximum == nil {
			return fmt.Errorf("ags: SubmitScore: ScoreMaximum is required when ScoreGiven is set")
		}
		if *score.ScoreMaximum <= 0 {
			return fmt.Errorf("ags: SubmitScore: ScoreMaximum must be a positive number")
		}
	}
	// Scores are posted to <lineitem_url>/scores. Use appendPathSegment so that
	// query parameters (e.g. ?type_id=8 from Moodle) are preserved correctly.
	scoresURL, err := appendPathSegment(lineitemURL, "scores")
	if err != nil {
		return fmt.Errorf("ags: invalid lineitem URL: %w", err)
	}

	body, err := json.Marshal(score)
	if err != nil {
		return fmt.Errorf("ags: failed to marshal score: %w", err)
	}
	resp, err := s.conn.Request(ctx, http.MethodPost, scoresURL, bytes.NewReader(body),
		[]string{lti.ScopeAGSScore},
		connector.WithContentType(contentTypeScore),
	)
	if err != nil {
		return fmt.Errorf("ags: SubmitScore request failed: %w", err)
	}
	// The AGS spec example responds 204 No Content; platforms also use 200/201.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("ags: SubmitScore returned %d: %s", resp.StatusCode, resp.Body)
	}
	return nil
}

// GetResults returns all results for the given line item URL.
func (s *Service) GetResults(ctx context.Context, lineitemURL string) ([]Result, error) {
	resultsURL, err := appendPathSegment(lineitemURL, "results")
	if err != nil {
		return nil, fmt.Errorf("ags: invalid lineitem URL: %w", err)
	}

	var all []Result
	pageURL := resultsURL
	for pageURL != "" {
		resp, err := s.conn.Request(ctx, http.MethodGet, pageURL, nil,
			[]string{lti.ScopeAGSResultReadonly},
			connector.WithAccept(contentTypeResults),
		)
		if err != nil {
			return nil, fmt.Errorf("ags: GetResults request failed: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("ags: GetResults returned %d: %s", resp.StatusCode, resp.Body)
		}
		var page []Result
		if err := json.Unmarshal(resp.Body, &page); err != nil {
			return nil, fmt.Errorf("ags: failed to parse results: %w", err)
		}
		all = append(all, page...)
		pageURL = resp.NextPageURL()
	}
	return all, nil
}
