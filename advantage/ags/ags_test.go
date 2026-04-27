package ags_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/ags"
	"github.com/robertjndw/go-lti-tool/internal/connector"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
)

// newTokenServer starts a mock OAuth2 token endpoint that always returns a bearer token.
func newTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newConn creates a Connector backed by the given token server URL.
func newConn(t *testing.T, tokenURL string) *connector.Connector {
	t.Helper()
	key := ltitest.NewKey(t)
	reg := &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-123",
		KeySetURL:      "https://platform.example.com/jwks",
		AuthLoginURL:   "https://platform.example.com/auth",
		AuthTokenURL:   tokenURL,
		AuthServer:     tokenURL,
		ToolPrivateKey: key,
		KID:            "tool-key-1",
	}
	return connector.New(reg)
}

// ── NewFromLaunch ─────────────────────────────────────────────────────────────

// AGS spec: NewFromLaunch must return ErrAGSNotAvailable when the launch has no AGS claim.
func TestAGS_NewFromLaunch_NoAGSClaim_ReturnsError(t *testing.T) {
	key := ltitest.NewKey(t)
	ld := &lti.Launch{
		LaunchID:     "launch-1",
		Registration: &lti.Registration{ToolPrivateKey: key},
		Claims:       &lti.LTIClaims{},
	}
	_, err := ags.NewFromLaunch(ld)
	if !errors.Is(err, lti.ErrAGSNotAvailable) {
		t.Errorf("expected ErrAGSNotAvailable, got %v", err)
	}
}

// AGS spec: NewFromLaunch must succeed when the launch includes an AGS claim.
func TestAGS_NewFromLaunch_WithAGSClaim_Succeeds(t *testing.T) {
	key := ltitest.NewKey(t)
	reg := &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-123",
		AuthTokenURL:   "https://platform.example.com/token",
		ToolPrivateKey: key,
		KID:            "tool-key-1",
	}
	ld := &lti.Launch{
		LaunchID:     "launch-1",
		Registration: reg,
		Claims: &lti.LTIClaims{
			AGS: &lti.AGSClaim{
				Scope:     []string{lti.ScopeAGSLineitem},
				Lineitems: "https://platform.example.com/lineitems",
			},
		},
	}
	svc, err := ags.NewFromLaunch(ld)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

// ── GetLineitems ──────────────────────────────────────────────────────────────

// AGS spec §2.1: GetLineitems returns all line items from the platform gradebook.
func TestAGS_GetLineitems_Success_SinglePage(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	items := []ags.Lineitem{
		{ID: "https://platform.example.com/lineitems/1", Label: "Quiz 1", ScoreMaximum: 100},
		{ID: "https://platform.example.com/lineitems/2", Label: "Assignment 1", ScoreMaximum: 50},
	}
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(items) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	got, err := svc.GetLineitems(context.Background())
	if err != nil {
		t.Fatalf("GetLineitems failed: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 items, got %d", len(got))
	}
	if got[0].Label != "Quiz 1" {
		t.Errorf("first item label = %q, want Quiz 1", got[0].Label)
	}
}

// AGS spec §2.1: GetLineitems must follow Link rel="next" headers for pagination.
func TestAGS_GetLineitems_Paginated(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	callCount := 0
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			nextURL := fmt.Sprintf("http://%s%s?page=2", r.Host, r.URL.Path)
			w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, nextURL))
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]ags.Lineitem{{Label: "Item 1", ScoreMaximum: 100}}) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]ags.Lineitem{{Label: "Item 2", ScoreMaximum: 50}}) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	got, err := svc.GetLineitems(context.Background())
	if err != nil {
		t.Fatalf("GetLineitems failed: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 items across pages, got %d", len(got))
	}
	if callCount != 2 {
		t.Errorf("expected 2 requests, got %d", callCount)
	}
}

// GetLineitems must return an error for non-200 responses.
func TestAGS_GetLineitems_Non200_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	_, err := svc.GetLineitems(context.Background())
	if err == nil {
		t.Error("expected error for non-200 response, got nil")
	}
}

// GetLineitems must return an error when the response body is not valid JSON.
func TestAGS_GetLineitems_InvalidJSON_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json")) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	_, err := svc.GetLineitems(context.Background())
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// GetLineitems must return an error when the lineitems endpoint is not set.
func TestAGS_GetLineitems_MissingEndpoint_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svc := ags.New(conn, &lti.AGSClaim{}) // no Lineitems URL

	_, err := svc.GetLineitems(context.Background())
	if err == nil {
		t.Error("expected error when lineitems endpoint is empty, got nil")
	}
}

// GetLineitems must send the correct Accept header per the AGS spec.
func TestAGS_GetLineitems_CorrectAcceptHeader(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	var capturedAccept string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]ags.Lineitem{}) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})
	_, _ = svc.GetLineitems(context.Background())

	const want = "application/vnd.ims.lis.v2.lineitemcontainer+json"
	if capturedAccept != want {
		t.Errorf("Accept = %q, want %q", capturedAccept, want)
	}
}

// ── GetLineitem ───────────────────────────────────────────────────────────────

// AGS spec: GetLineitem returns the line item at the given URL.
func TestAGS_GetLineitem_Success(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	item := ags.Lineitem{ID: "https://platform.example.com/lineitems/1", Label: "Quiz 1", ScoreMaximum: 100}
	var capturedAccept string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(item) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	got, err := svc.GetLineitem(context.Background(), svcSrv.URL+"/lineitems/1")
	if err != nil {
		t.Fatalf("GetLineitem failed: %v", err)
	}
	if got.Label != "Quiz 1" {
		t.Errorf("label = %q, want Quiz 1", got.Label)
	}
	const want = "application/vnd.ims.lis.v2.lineitem+json"
	if capturedAccept != want {
		t.Errorf("Accept = %q, want %q", capturedAccept, want)
	}
}

// GetLineitem must return an error for non-200 responses.
func TestAGS_GetLineitem_Non200_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	_, err := svc.GetLineitem(context.Background(), svcSrv.URL+"/lineitems/1")
	if err == nil {
		t.Error("expected error for non-200 response, got nil")
	}
}

// GetLineitem must return an error for invalid JSON response.
func TestAGS_GetLineitem_InvalidJSON_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json")) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	_, err := svc.GetLineitem(context.Background(), svcSrv.URL+"/lineitems/1")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// ── CreateLineitem ────────────────────────────────────────────────────────────

// AGS spec: CreateLineitem POSTs to the lineitems URL and returns the created item (201).
func TestAGS_CreateLineitem_Success201(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	created := ags.Lineitem{ID: svcURL("/lineitems/new"), Label: "New Quiz", ScoreMaximum: 100}
	var capturedContentType string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(created) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	got, err := svc.CreateLineitem(context.Background(), ags.Lineitem{Label: "New Quiz", ScoreMaximum: 100})
	if err != nil {
		t.Fatalf("CreateLineitem failed: %v", err)
	}
	if got.Label != "New Quiz" {
		t.Errorf("label = %q, want New Quiz", got.Label)
	}
	const want = "application/vnd.ims.lis.v2.lineitem+json"
	if capturedContentType != want {
		t.Errorf("Content-Type = %q, want %q", capturedContentType, want)
	}
}

// AGS spec: CreateLineitem must also succeed when the platform responds with 200 OK.
func TestAGS_CreateLineitem_Success200(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ags.Lineitem{Label: "New Quiz", ScoreMaximum: 100}) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	_, err := svc.CreateLineitem(context.Background(), ags.Lineitem{Label: "New Quiz", ScoreMaximum: 100})
	if err != nil {
		t.Errorf("expected success for 200 response, got %v", err)
	}
}

// CreateLineitem must return an error for non-200/201 responses.
func TestAGS_CreateLineitem_Non200_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	_, err := svc.CreateLineitem(context.Background(), ags.Lineitem{Label: "Quiz", ScoreMaximum: 100})
	if err == nil {
		t.Error("expected error for non-200/201 response, got nil")
	}
}

// CreateLineitem must return an error for invalid JSON in the response body.
func TestAGS_CreateLineitem_InvalidJSON_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("not json")) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	_, err := svc.CreateLineitem(context.Background(), ags.Lineitem{Label: "Quiz", ScoreMaximum: 100})
	if err == nil {
		t.Error("expected error for invalid JSON in response, got nil")
	}
}

// CreateLineitem must return an error when the lineitems endpoint is not set.
func TestAGS_CreateLineitem_MissingEndpoint_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svc := ags.New(conn, &lti.AGSClaim{}) // no Lineitems URL

	_, err := svc.CreateLineitem(context.Background(), ags.Lineitem{Label: "Quiz", ScoreMaximum: 100})
	if err == nil {
		t.Error("expected error when lineitems endpoint is empty, got nil")
	}
}

// ── UpdateLineitem ────────────────────────────────────────────────────────────

// AGS spec: UpdateLineitem must return an error when Lineitem.ID is not set.
func TestAGS_UpdateLineitem_MissingID_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: "https://platform.example.com/lineitems"})

	_, err := svc.UpdateLineitem(context.Background(), ags.Lineitem{Label: "Updated", ScoreMaximum: 100})
	if err == nil {
		t.Error("expected error for missing lineitem ID, got nil")
	}
}

// AGS spec: UpdateLineitem PUTs to the lineitem URL and returns the updated item.
func TestAGS_UpdateLineitem_Success(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	var capturedMethod string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ags.Lineitem{Label: "Updated Quiz", ScoreMaximum: 100}) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	lineitemURL := svcSrv.URL + "/lineitems/1"
	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	got, err := svc.UpdateLineitem(context.Background(), ags.Lineitem{ID: lineitemURL, Label: "Updated Quiz", ScoreMaximum: 100})
	if err != nil {
		t.Fatalf("UpdateLineitem failed: %v", err)
	}
	if capturedMethod != http.MethodPut {
		t.Errorf("HTTP method = %q, want PUT", capturedMethod)
	}
	if got.Label != "Updated Quiz" {
		t.Errorf("label = %q, want Updated Quiz", got.Label)
	}
}

// UpdateLineitem must return an error for non-200 responses.
func TestAGS_UpdateLineitem_Non200_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	_, err := svc.UpdateLineitem(context.Background(), ags.Lineitem{ID: svcSrv.URL + "/lineitems/1", Label: "Updated", ScoreMaximum: 100})
	if err == nil {
		t.Error("expected error for non-200 response, got nil")
	}
}

// UpdateLineitem must return an error for invalid JSON in the response body.
func TestAGS_UpdateLineitem_InvalidJSON_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json")) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	_, err := svc.UpdateLineitem(context.Background(), ags.Lineitem{ID: svcSrv.URL + "/lineitems/1", Label: "Updated", ScoreMaximum: 100})
	if err == nil {
		t.Error("expected error for invalid JSON in response, got nil")
	}
}

// ── DeleteLineitem ────────────────────────────────────────────────────────────

// AGS spec: DeleteLineitem succeeds with 204 No Content.
func TestAGS_DeleteLineitem_Success204(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	if err := svc.DeleteLineitem(context.Background(), svcSrv.URL+"/lineitems/1"); err != nil {
		t.Fatalf("DeleteLineitem failed: %v", err)
	}
}

// AGS spec: DeleteLineitem must also succeed with 200 OK.
func TestAGS_DeleteLineitem_Success200(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	if err := svc.DeleteLineitem(context.Background(), svcSrv.URL+"/lineitems/1"); err != nil {
		t.Errorf("expected success for 200 response, got %v", err)
	}
}

// DeleteLineitem must return an error for non-200/204 responses.
func TestAGS_DeleteLineitem_Non200_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	if err := svc.DeleteLineitem(context.Background(), svcSrv.URL+"/lineitems/1"); err == nil {
		t.Error("expected error for non-200/204 response, got nil")
	}
}

// ── FindOrCreateLineitem ──────────────────────────────────────────────────────

// FindOrCreateLineitem must use the single lineitem endpoint directly when available.
func TestAGS_FindOrCreateLineitem_UsesLineitemEndpoint(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	existing := ags.Lineitem{ID: "https://platform.example.com/lineitems/1", Label: "Quiz 1", ScoreMaximum: 100}
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(existing) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	// Both Lineitems and Lineitem endpoints set; Lineitem takes precedence.
	svc := ags.New(conn, &lti.AGSClaim{
		Lineitems: svcSrv.URL + "/lineitems",
		Lineitem:  svcSrv.URL + "/lineitems/1",
	})

	got, err := svc.FindOrCreateLineitem(context.Background(), ags.Lineitem{Label: "Quiz 1", ScoreMaximum: 100})
	if err != nil {
		t.Fatalf("FindOrCreateLineitem failed: %v", err)
	}
	if got.ID != existing.ID {
		t.Errorf("got lineitem ID = %q, want %q", got.ID, existing.ID)
	}
}

// FindOrCreateLineitem must find an existing line item matching the ResourceID.
func TestAGS_FindOrCreateLineitem_FindsByResourceID(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	items := []ags.Lineitem{
		{ID: "https://platform.example.com/lineitems/1", Label: "Quiz 1", ScoreMaximum: 100, ResourceID: "resource-1"},
		{ID: "https://platform.example.com/lineitems/2", Label: "Quiz 2", ScoreMaximum: 50, ResourceID: "resource-2"},
	}
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(items) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	got, err := svc.FindOrCreateLineitem(context.Background(), ags.Lineitem{ResourceID: "resource-2"})
	if err != nil {
		t.Fatalf("FindOrCreateLineitem failed: %v", err)
	}
	if got.ID != "https://platform.example.com/lineitems/2" {
		t.Errorf("got ID = %q, want lineitems/2", got.ID)
	}
}

// FindOrCreateLineitem must find an existing line item matching the Tag.
func TestAGS_FindOrCreateLineitem_FindsByTag(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	items := []ags.Lineitem{
		{ID: "https://platform.example.com/lineitems/1", Label: "Quiz 1", ScoreMaximum: 100, Tag: "quiz"},
		{ID: "https://platform.example.com/lineitems/2", Label: "Assignment 1", ScoreMaximum: 50, Tag: "assignment"},
	}
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(items) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	got, err := svc.FindOrCreateLineitem(context.Background(), ags.Lineitem{Tag: "assignment"})
	if err != nil {
		t.Fatalf("FindOrCreateLineitem failed: %v", err)
	}
	if got.ID != "https://platform.example.com/lineitems/2" {
		t.Errorf("got ID = %q, want lineitems/2", got.ID)
	}
}

// FindOrCreateLineitem must create a new item when no existing item matches.
func TestAGS_FindOrCreateLineitem_CreatesWhenNoMatch(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	existing := []ags.Lineitem{
		{ID: "https://platform.example.com/lineitems/1", Label: "Old Quiz", ScoreMaximum: 100, Tag: "old"},
	}
	newItem := ags.Lineitem{ID: "https://platform.example.com/lineitems/2", Label: "New Quiz", ScoreMaximum: 50}

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(existing) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(newItem) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	got, err := svc.FindOrCreateLineitem(context.Background(), ags.Lineitem{Label: "New Quiz", ScoreMaximum: 50, Tag: "new"})
	if err != nil {
		t.Fatalf("FindOrCreateLineitem failed: %v", err)
	}
	if got.ID != newItem.ID {
		t.Errorf("got ID = %q, want %q", got.ID, newItem.ID)
	}
}

// ── SubmitScore ───────────────────────────────────────────────────────────────

// AGS spec §3.2: SubmitScore POSTs to <lineitem_url>/scores.
func TestAGS_SubmitScore_PostsToScoresEndpoint(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	var capturedPath string
	var capturedContentType string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	err := svc.SubmitScore(context.Background(), svcSrv.URL+"/lineitems/1", ags.Score{
		UserID:           "user-42",
		ScoreGiven:       85,
		ScoreMaximum:     100,
		ActivityProgress: ags.ActivityProgressCompleted,
		GradingProgress:  ags.GradingProgressFullyGraded,
		Timestamp:        "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("SubmitScore failed: %v", err)
	}
	if !strings.HasSuffix(capturedPath, "/scores") {
		t.Errorf("SubmitScore must POST to <lineitem>/scores, got path %q", capturedPath)
	}
	const want = "application/vnd.ims.lis.v1.score+json"
	if capturedContentType != want {
		t.Errorf("Content-Type = %q, want %q", capturedContentType, want)
	}
}

// AGS spec: SubmitScore must also succeed with 201 Created.
func TestAGS_SubmitScore_Success201(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	err := svc.SubmitScore(context.Background(), svcSrv.URL+"/lineitems/1", ags.Score{
		UserID:           "user-42",
		ActivityProgress: ags.ActivityProgressCompleted,
		GradingProgress:  ags.GradingProgressFullyGraded,
		Timestamp:        "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Errorf("expected success for 201 response, got %v", err)
	}
}

// SubmitScore must return an error for non-200/201 responses.
func TestAGS_SubmitScore_Non200_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	err := svc.SubmitScore(context.Background(), svcSrv.URL+"/lineitems/1", ags.Score{
		UserID:           "user-42",
		ActivityProgress: ags.ActivityProgressCompleted,
		GradingProgress:  ags.GradingProgressFullyGraded,
		Timestamp:        "2026-01-01T00:00:00Z",
	})
	if err == nil {
		t.Error("expected error for non-200/201 response, got nil")
	}
}

// ── GetResults ────────────────────────────────────────────────────────────────

// AGS spec §4: GetResults fetches from <lineitem_url>/results.
func TestAGS_GetResults_Success_SinglePage(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	results := []ags.Result{
		{ID: "https://platform.example.com/results/1", UserID: "user-42", ResultScore: 85, ResultMaximum: 100},
	}
	var capturedPath string
	var capturedAccept string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(results) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	got, err := svc.GetResults(context.Background(), svcSrv.URL+"/lineitems/1")
	if err != nil {
		t.Fatalf("GetResults failed: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 result, got %d", len(got))
	}
	if !strings.HasSuffix(capturedPath, "/results") {
		t.Errorf("GetResults must fetch <lineitem>/results, got path %q", capturedPath)
	}
	const want = "application/vnd.ims.lis.v2.resultcontainer+json"
	if capturedAccept != want {
		t.Errorf("Accept = %q, want %q", capturedAccept, want)
	}
}

// AGS spec: GetResults must follow Link rel="next" headers for pagination.
func TestAGS_GetResults_Paginated(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	callCount := 0
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			nextURL := fmt.Sprintf("http://%s%s?page=2", r.Host, r.URL.Path)
			w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, nextURL))
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]ags.Result{ //nolint:errcheck
				{ID: "https://platform.example.com/results/1", UserID: "user-1", ResultScore: 85},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]ags.Result{ //nolint:errcheck
			{ID: "https://platform.example.com/results/2", UserID: "user-2", ResultScore: 70},
		})
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	got, err := svc.GetResults(context.Background(), svcSrv.URL+"/lineitems/1")
	if err != nil {
		t.Fatalf("GetResults failed: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 results across pages, got %d", len(got))
	}
	if callCount != 2 {
		t.Errorf("expected 2 requests, got %d", callCount)
	}
}

// GetResults must return an error for non-200 responses.
func TestAGS_GetResults_Non200_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	_, err := svc.GetResults(context.Background(), svcSrv.URL+"/lineitems/1")
	if err == nil {
		t.Error("expected error for non-200 response, got nil")
	}
}

// GetResults must return an error for invalid JSON in the response body.
func TestAGS_GetResults_InvalidJSON_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json")) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})

	_, err := svc.GetResults(context.Background(), svcSrv.URL+"/lineitems/1")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// ── Request headers ───────────────────────────────────────────────────────────

// All AGS service requests must carry an Authorization: Bearer <token> header.
func TestAGS_Request_AttachesBearerToken(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	var capturedAuth string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]ags.Lineitem{}) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})
	_, _ = svc.GetLineitems(context.Background())

	if !strings.HasPrefix(capturedAuth, "Bearer ") {
		t.Errorf("Authorization header = %q, want Bearer <token>", capturedAuth)
	}
}

// svcURL is a helper to construct a placeholder URL for lineitem IDs in tests.
func svcURL(path string) string {
	return "https://platform.example.com" + path
}

// ── appendPathSegment (query-string preservation) ─────────────────────────────

// AGS spec / Moodle: lineitem URLs may include query parameters (e.g. ?type_id=8).
// SubmitScore and GetResults must append /scores and /results to the path, not the
// query string.
func TestAGS_SubmitScore_LineitemURLWithQueryString_PreservesQuery(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	var capturedPath string
	var capturedQuery string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(svcSrv.Close)

	lineitemURL := svcSrv.URL + "/lineitems/1?type_id=8"
	svc := ags.New(conn, &lti.AGSClaim{Lineitem: lineitemURL})
	_ = svc.SubmitScore(context.Background(), lineitemURL, ags.Score{})

	if capturedPath != "/lineitems/1/scores" {
		t.Errorf("path = %q, want /lineitems/1/scores", capturedPath)
	}
	if capturedQuery != "type_id=8" {
		t.Errorf("query = %q, want type_id=8", capturedQuery)
	}
}

func TestAGS_GetResults_LineitemURLWithQueryString_PreservesQuery(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	var capturedPath string
	var capturedQuery string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]ags.Result{}) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	lineitemURL := svcSrv.URL + "/lineitems/1?type_id=8"
	svc := ags.New(conn, &lti.AGSClaim{Lineitem: lineitemURL})
	_, _ = svc.GetResults(context.Background(), lineitemURL)

	if capturedPath != "/lineitems/1/results" {
		t.Errorf("path = %q, want /lineitems/1/results", capturedPath)
	}
	if capturedQuery != "type_id=8" {
		t.Errorf("query = %q, want type_id=8", capturedQuery)
	}
}
