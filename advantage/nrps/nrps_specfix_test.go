package nrps_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/nrps"
)

// NRPS spec: the memberships endpoint supports role, limit and rlid query
// parameters.
func TestNRPS_GetMemberships_QueryParams(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	var capturedQuery string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":"http://x/m","context":{"id":"ctx-1"},"members":[]}`)
	}))
	t.Cleanup(svcSrv.Close)

	svc := nrps.New(conn, &lti.NRPSClaim{ContextMembershipsURL: svcSrv.URL + "/memberships"})
	_, err := svc.GetMemberships(context.Background(), nrps.MembersQuery{
		Role:           lti.RoleLearner,
		Limit:          50,
		ResourceLinkID: "rl-1",
	})
	if err != nil {
		t.Fatalf("GetMemberships failed: %v", err)
	}
	for _, want := range []string{"role=", "limit=50", "rlid=rl-1"} {
		if !strings.Contains(capturedQuery, want) {
			t.Errorf("query %q missing %q", capturedQuery, want)
		}
	}
}

// The response context and rel="differences" Link header must be surfaced.
func TestNRPS_GetMemberships_ContextAndDifferences(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+"http://"+r.Host+`/memberships?since=42>; rel="differences"`)
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"id":      "http://x/m",
			"context": map[string]string{"id": "ctx-1", "title": "Course 1"},
			"members": []map[string]any{{"status": "Active", "user_id": "u1", "roles": []string{lti.RoleLearner}}},
		}
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := nrps.New(conn, &lti.NRPSClaim{ContextMembershipsURL: svcSrv.URL + "/memberships"})
	m, err := svc.GetMemberships(context.Background())
	if err != nil {
		t.Fatalf("GetMemberships failed: %v", err)
	}
	if m.Context.ID != "ctx-1" || m.Context.Title != "Course 1" {
		t.Errorf("context not surfaced: %+v", m.Context)
	}
	if len(m.Members) != 1 {
		t.Errorf("expected 1 member, got %d", len(m.Members))
	}
	if !strings.Contains(m.DifferencesURL, "since=42") {
		t.Errorf("differences URL not captured, got %q", m.DifferencesURL)
	}
}
