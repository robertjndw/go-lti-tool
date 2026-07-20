package nrps_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/nrps"
	"github.com/robertjndw/go-lti-tool/internal/connector"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
)

// newTokenServer starts a mock OAuth2 token endpoint that always returns a bearer token.
func newTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm() //nolint:errcheck
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        r.Form.Get("scope"),
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

// membershipsBody builds a NRPS response envelope with the given members.
func membershipsBody(t *testing.T, members []nrps.Member) []byte {
	t.Helper()
	body := map[string]any{
		"id":      "https://platform.example.com/memberships",
		"context": map[string]string{"id": "course-1"},
		"members": members,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal memberships body: %v", err)
	}
	return b
}

// ── NewFromLaunch ─────────────────────────────────────────────────────────────

// NRPS spec: NewFromLaunch must return ErrNRPSNotAvailable when the launch has no NRPS claim.
func TestNRPS_NewFromLaunch_NoNRPSClaim_ReturnsError(t *testing.T) {
	key := ltitest.NewKey(t)
	ld := &lti.Launch{
		LaunchID:     "launch-1",
		Registration: &lti.Registration{ToolPrivateKey: key},
		Claims:       &lti.LTIClaims{},
	}
	_, err := nrps.NewFromLaunch(ld)
	if !errors.Is(err, lti.ErrNRPSNotAvailable) {
		t.Errorf("expected ErrNRPSNotAvailable, got %v", err)
	}
}

// NRPS spec: NewFromLaunch must succeed when the launch includes an NRPS claim.
func TestNRPS_NewFromLaunch_WithNRPSClaim_Succeeds(t *testing.T) {
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
			NRPS: &lti.NRPSClaim{
				ContextMembershipsURL: "https://platform.example.com/memberships",
				ServiceVersions:       []string{"2.0"},
			},
		},
	}
	svc, err := nrps.NewFromLaunch(ld)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

// ── GetMembers ────────────────────────────────────────────────────────────────

// NRPS spec: GetMembers returns the full course roster.
func TestNRPS_GetMembers_Success_SinglePage(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	members := []nrps.Member{
		{UserID: "user-1", Status: nrps.MemberStatusActive, Roles: []string{lti.RoleInstructor}, Name: "Alice"},
		{UserID: "user-2", Status: nrps.MemberStatusActive, Roles: []string{lti.RoleLearner}, Name: "Bob"},
	}
	var capturedAccept string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
		w.Write(membershipsBody(t, members)) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := nrps.New(conn, &lti.NRPSClaim{ContextMembershipsURL: svcSrv.URL + "/memberships"})

	got, err := svc.GetMembers(context.Background())
	if err != nil {
		t.Fatalf("GetMembers failed: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 members, got %d", len(got))
	}
	if got[0].UserID != "user-1" {
		t.Errorf("first member UserID = %q, want user-1", got[0].UserID)
	}
	const want = "application/vnd.ims.lti-nrps.v2.membershipcontainer+json"
	if capturedAccept != want {
		t.Errorf("Accept = %q, want %q", capturedAccept, want)
	}
}

// NRPS spec: GetMembers must follow Link rel="next" headers for pagination.
func TestNRPS_GetMembers_Paginated(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	page1 := []nrps.Member{
		{UserID: "user-1", Status: nrps.MemberStatusActive, Roles: []string{lti.RoleLearner}},
	}
	page2 := []nrps.Member{
		{UserID: "user-2", Status: nrps.MemberStatusActive, Roles: []string{lti.RoleLearner}},
	}

	callCount := 0
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			nextURL := fmt.Sprintf("http://%s%s?page=2", r.Host, r.URL.Path)
			w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, nextURL))
			w.WriteHeader(http.StatusOK)
			w.Write(membershipsBody(t, page1)) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(membershipsBody(t, page2)) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := nrps.New(conn, &lti.NRPSClaim{ContextMembershipsURL: svcSrv.URL + "/memberships"})

	got, err := svc.GetMembers(context.Background())
	if err != nil {
		t.Fatalf("GetMembers failed: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 members across pages, got %d", len(got))
	}
	if callCount != 2 {
		t.Errorf("expected 2 requests, got %d", callCount)
	}
}

// GetMembers must return an error for non-200 responses.
func TestNRPS_GetMembers_Non200_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(svcSrv.Close)

	svc := nrps.New(conn, &lti.NRPSClaim{ContextMembershipsURL: svcSrv.URL + "/memberships"})

	_, err := svc.GetMembers(context.Background())
	if err == nil {
		t.Error("expected error for non-200 response, got nil")
	}
}

// GetMembers must return an error when the response is not valid JSON.
func TestNRPS_GetMembers_InvalidJSON_ReturnsError(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json")) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := nrps.New(conn, &lti.NRPSClaim{ContextMembershipsURL: svcSrv.URL + "/memberships"})

	_, err := svc.GetMembers(context.Background())
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// GetMembers must return an empty slice (not an error) for a roster with no members.
func TestNRPS_GetMembers_EmptyMemberList(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(membershipsBody(t, []nrps.Member{})) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := nrps.New(conn, &lti.NRPSClaim{ContextMembershipsURL: svcSrv.URL + "/memberships"})

	got, err := svc.GetMembers(context.Background())
	if err != nil {
		t.Fatalf("GetMembers failed on empty roster: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty member list, got %d members", len(got))
	}
}

// All NRPS service requests must carry an Authorization: Bearer <token> header.
func TestNRPS_Request_AttachesBearerToken(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	var capturedAuth string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write(membershipsBody(t, []nrps.Member{})) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := nrps.New(conn, &lti.NRPSClaim{ContextMembershipsURL: svcSrv.URL + "/memberships"})
	_, _ = svc.GetMembers(context.Background())

	if len(capturedAuth) < 8 || capturedAuth[:7] != "Bearer " {
		t.Errorf("Authorization header = %q, want Bearer <token>", capturedAuth)
	}
}
