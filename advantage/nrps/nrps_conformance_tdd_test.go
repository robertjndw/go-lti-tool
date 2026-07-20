package nrps_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/nrps"
)

func nrpsLaunch(version ...string) *lti.Launch {
	return &lti.Launch{
		Registration: &lti.Registration{},
		Claims: &lti.LTIClaims{NRPS: &lti.NRPSClaim{
			ContextMembershipsURL: "https://platform.example.com/memberships",
			ServiceVersions:       version,
		}},
	}
}

func TestNRPS_NewFromLaunchRequiresSupportedServiceVersion(t *testing.T) {
	for name, versions := range map[string][]string{
		"missing":     nil,
		"unsupported": {"1.0"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := nrps.NewFromLaunch(nrpsLaunch(versions...)); err == nil {
				t.Errorf("expected NRPS service versions %v to be rejected", versions)
			}
		})
	}

	if _, err := nrps.NewFromLaunch(nrpsLaunch("1.0", "2.0")); err != nil {
		t.Errorf("expected advertised NRPS 2.0 support to be accepted: %v", err)
	}
}

// NRPS 2.0 defines an omitted membership status as Active. Explicit statuses
// must remain untouched, including Inactive and Deleted difference records.
func TestNRPS_MissingStatusDefaultsToActive(t *testing.T) {
	tokenSrv := newTokenServer(t)
	serviceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.ims.lti-nrps.v2.membershipcontainer+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id":"https://platform.example.com/memberships",
			"context":{"id":"course-1"},
			"members":[
				{"user_id":"u1","roles":[]},
				{"status":"Inactive","user_id":"u2","roles":[]},
				{"status":"Deleted","user_id":"u3","roles":[]}
			]
		}`)) //nolint:errcheck
	}))
	t.Cleanup(serviceSrv.Close)

	svc := nrps.New(newConn(t, tokenSrv.URL), &lti.NRPSClaim{ContextMembershipsURL: serviceSrv.URL})
	got, err := svc.GetMemberships(context.Background())
	if err != nil {
		t.Fatalf("GetMemberships failed: %v", err)
	}
	want := []string{nrps.MemberStatusActive, nrps.MemberStatusInactive, nrps.MemberStatusDeleted}
	if len(got.Members) != len(want) {
		t.Fatalf("members = %d, want %d", len(got.Members), len(want))
	}
	for i, status := range want {
		if got.Members[i].Status != status {
			t.Errorf("member %d status = %q, want %q", i, got.Members[i].Status, status)
		}
	}
}

// A tool must not expose a malformed membership container as a valid roster.
// These are required properties in the NRPS 2.0 response schema.
func TestNRPS_RejectsMalformedMembershipContainer(t *testing.T) {
	tests := map[string]map[string]any{
		"missing container id": {
			"context": map[string]any{"id": "course-1"}, "members": []any{},
		},
		"missing context id": {
			"id": "https://platform.example.com/memberships", "context": map[string]any{}, "members": []any{},
		},
		"missing members": {
			"id": "https://platform.example.com/memberships", "context": map[string]any{"id": "course-1"},
		},
		"member missing user_id": {
			"id": "https://platform.example.com/memberships", "context": map[string]any{"id": "course-1"},
			"members": []any{map[string]any{"roles": []string{}}},
		},
		"member missing roles": {
			"id": "https://platform.example.com/memberships", "context": map[string]any{"id": "course-1"},
			"members": []any{map[string]any{"user_id": "u1"}},
		},
		"member invalid status": {
			"id": "https://platform.example.com/memberships", "context": map[string]any{"id": "course-1"},
			"members": []any{map[string]any{"user_id": "u1", "roles": []string{}, "status": "Paused"}},
		},
	}

	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			tokenSrv := newTokenServer(t)
			serviceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/vnd.ims.lti-nrps.v2.membershipcontainer+json")
				json.NewEncoder(w).Encode(payload) //nolint:errcheck
			}))
			t.Cleanup(serviceSrv.Close)

			svc := nrps.New(newConn(t, tokenSrv.URL), &lti.NRPSClaim{ContextMembershipsURL: serviceSrv.URL})
			if _, err := svc.GetMemberships(context.Background()); err == nil {
				t.Error("expected malformed NRPS membership container to be rejected")
			}
		})
	}
}
