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

	"github.com/robertjndw/go-lti"
	"github.com/robertjndw/go-lti/internal/connector"
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
}

// New creates an AGS Service using the given Connector and endpoint claim.
func New(conn *connector.Connector, endpoint *lti.AGSClaim) *Service {
	return &Service{conn: conn, endpoint: endpoint}
}

// NewFromLaunch creates an AGS Service from a validated LaunchData.
// Returns ErrAGSNotAvailable if the launch does not include AGS claims.
func NewFromLaunch(ld *lti.Launch) (*Service, error) {
	if !ld.HasAGS() {
		return nil, lti.ErrAGSNotAvailable
	}
	conn := connector.New(ld.Registration)
	return New(conn, ld.Claims.AGS), nil
}

// GetLineitems returns all line items from the platform gradebook.
func (s *Service) GetLineitems(ctx context.Context) ([]Lineitem, error) {
	if s.endpoint.Lineitems == "" {
		return nil, fmt.Errorf("ags: lineitems URL is not available in this launch")
	}

	var all []Lineitem
	pageURL := s.endpoint.Lineitems
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
// ResourceID and Tag, and creates one if none is found. Mirrors the PHP
// reference library's find_or_create_lineitem behaviour.
func (s *Service) FindOrCreateLineitem(ctx context.Context, li Lineitem) (*Lineitem, error) {
	// If the launch already provided a specific lineitem URL, use it directly.
	if s.endpoint.Lineitem != "" {
		existing, err := s.GetLineitem(ctx, s.endpoint.Lineitem)
		if err == nil {
			return existing, nil
		}
	}

	existing, err := s.GetLineitems(ctx)
	if err != nil {
		return nil, fmt.Errorf("ags: FindOrCreateLineitem: %w", err)
	}

	for i := range existing {
		if (li.ResourceID == "" || existing[i].ResourceID == li.ResourceID) &&
			(li.Tag == "" || existing[i].Tag == li.Tag) {
			return &existing[i], nil
		}
	}

	return s.CreateLineitem(ctx, li)
}

// SubmitScore posts a Score to the platform for the given line item URL.
func (s *Service) SubmitScore(ctx context.Context, lineitemURL string, score Score) error {
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
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
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
