package ags_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/ags"
)

// AGS spec: a score of 0 is a valid grade and must be serialized, unlike an
// absent score.
func TestScore_ZeroScoreGiven_IsSerialized(t *testing.T) {
	s := ags.Score{
		UserID:           "user-42",
		ScoreGiven:       ags.Float64(0),
		ScoreMaximum:     ags.Float64(100),
		ActivityProgress: ags.ActivityProgressCompleted,
		GradingProgress:  ags.GradingProgressFullyGraded,
		Timestamp:        "2026-01-01T00:00:00.123Z",
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"scoreGiven":0`) {
		t.Errorf("scoreGiven=0 must be serialized, got %s", data)
	}

	s.ScoreGiven = nil
	s.ScoreMaximum = nil
	data, _ = json.Marshal(s)
	if strings.Contains(string(data), "scoreGiven") {
		t.Errorf("nil scoreGiven must be omitted, got %s", data)
	}
}

// AGS spec: scoreMaximum is required whenever scoreGiven is present.
func TestAGS_SubmitScore_ScoreGivenWithoutMaximum_Rejected(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)
	svc := ags.New(conn, &lti.AGSClaim{Lineitems: "https://platform.example.com/lineitems"})

	err := svc.SubmitScore(context.Background(), "https://platform.example.com/lineitems/1", ags.Score{
		UserID:           "user-42",
		ScoreGiven:       ags.Float64(50),
		ActivityProgress: ags.ActivityProgressCompleted,
		GradingProgress:  ags.GradingProgressFullyGraded,
		Timestamp:        "2026-01-01T00:00:00.123Z",
	})
	if err == nil {
		t.Error("expected error for scoreGiven without scoreMaximum")
	}
}

// AGS spec §3.2: the lineitem container supports resource_link_id, resource_id,
// tag and limit query parameters.
func TestAGS_GetLineitems_QueryParams(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	var capturedQuery string
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]ags.Lineitem{}) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})
	_, err := svc.GetLineitems(context.Background(), ags.LineitemQuery{
		ResourceLinkID: "rl-1",
		ResourceID:     "res-1",
		Tag:            "quiz",
		Limit:          10,
	})
	if err != nil {
		t.Fatalf("GetLineitems failed: %v", err)
	}
	for _, want := range []string{"resource_link_id=rl-1", "resource_id=res-1", "tag=quiz", "limit=10"} {
		if !strings.Contains(capturedQuery, want) {
			t.Errorf("query %q missing %q", capturedQuery, want)
		}
	}
}

// A failing fetch of the launch-provided lineitem URL must propagate as an
// error instead of silently creating a (potentially duplicate) line item.
func TestAGS_FindOrCreateLineitem_LaunchLineitemFetchError_Propagates(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	created := false
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lineitems/broken" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodPost {
			created = true
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]ags.Lineitem{}) //nolint:errcheck
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{
		Lineitems: svcSrv.URL + "/lineitems",
		Lineitem:  svcSrv.URL + "/lineitems/broken",
	})
	_, err := svc.FindOrCreateLineitem(context.Background(), ags.Lineitem{Label: "Quiz", ScoreMaximum: 100})
	if err == nil {
		t.Error("expected error when launch lineitem fetch fails")
	}
	if created {
		t.Error("must not create a new line item when the launch lineitem fetch fails")
	}
}

// AGS spec: SubmitScore must accept the normative 204 No Content response.
func TestAGS_SubmitScore_Success204(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})
	err := svc.SubmitScore(context.Background(), svcSrv.URL+"/lineitems/1", ags.Score{
		UserID:           "user-42",
		ActivityProgress: ags.ActivityProgressCompleted,
		GradingProgress:  ags.GradingProgressFullyGraded,
		Timestamp:        "2026-01-01T00:00:00.123Z",
	})
	if err != nil {
		t.Errorf("expected success for 204 response, got %v", err)
	}
}

// AGS spec: userId, activityProgress, gradingProgress and timestamp are
// required score fields; scoreMaximum must be positive when present.
func TestAGS_SubmitScore_RequiredFields(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)
	svc := ags.New(conn, &lti.AGSClaim{Lineitems: "https://platform.example.com/lineitems"})

	valid := func() ags.Score {
		return ags.Score{
			UserID:           "user-42",
			ActivityProgress: ags.ActivityProgressCompleted,
			GradingProgress:  ags.GradingProgressFullyGraded,
			Timestamp:        "2026-01-01T00:00:00.123Z",
		}
	}
	cases := map[string]func(*ags.Score){
		"missing UserID":           func(s *ags.Score) { s.UserID = "" },
		"missing ActivityProgress": func(s *ags.Score) { s.ActivityProgress = "" },
		"missing GradingProgress":  func(s *ags.Score) { s.GradingProgress = "" },
		"missing Timestamp":        func(s *ags.Score) { s.Timestamp = "" },
		"non-positive ScoreMaximum": func(s *ags.Score) {
			s.ScoreGiven = ags.Float64(1)
			s.ScoreMaximum = ags.Float64(0)
		},
	}
	for name, mutate := range cases {
		s := valid()
		mutate(&s)
		if err := svc.SubmitScore(context.Background(), "https://platform.example.com/lineitems/1", s); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

// A platform-reported result of 0 must be distinguishable from an absent one.
func TestResult_ZeroScore_Unmarshal(t *testing.T) {
	var withZero, withoutScore ags.Result
	if err := json.Unmarshal([]byte(`{"id":"r1","userId":"u1","resultScore":0,"resultMaximum":100}`), &withZero); err != nil {
		t.Fatal(err)
	}
	if withZero.ResultScore == nil || *withZero.ResultScore != 0 {
		t.Errorf("resultScore 0 must unmarshal to a non-nil pointer, got %v", withZero.ResultScore)
	}
	if err := json.Unmarshal([]byte(`{"id":"r2","userId":"u2"}`), &withoutScore); err != nil {
		t.Fatal(err)
	}
	if withoutScore.ResultScore != nil {
		t.Errorf("absent resultScore must unmarshal to nil, got %v", *withoutScore.ResultScore)
	}
}

// FindOrCreateLineitem must never match a line item bound to a different
// resource link, even if resourceId and tag agree.
func TestAGS_FindOrCreateLineitem_OtherResourceLink_NotMatched(t *testing.T) {
	tokenSrv := newTokenServer(t)
	conn := newConn(t, tokenSrv.URL)

	created := false
	svcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			created = true
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(ags.Lineitem{ID: "http://x/li/new", Label: "Quiz"}) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]ags.Lineitem{ //nolint:errcheck
			{ID: "http://x/li/1", Label: "Quiz", ResourceID: "res-1", ResourceLinkID: "other-rl"},
		})
	}))
	t.Cleanup(svcSrv.Close)

	svc := ags.New(conn, &lti.AGSClaim{Lineitems: svcSrv.URL + "/lineitems"})
	got, err := svc.FindOrCreateLineitem(context.Background(), ags.Lineitem{
		Label: "Quiz", ScoreMaximum: 100, ResourceID: "res-1", ResourceLinkID: "rl-1",
	})
	if err != nil {
		t.Fatalf("FindOrCreateLineitem failed: %v", err)
	}
	if !created {
		t.Error("expected a new line item: the existing one belongs to another resource link")
	}
	if got.ID != "http://x/li/new" {
		t.Errorf("got %q, want the newly created line item", got.ID)
	}
}

// gradesReleased must survive serialization as an explicit false, and the
// submissionReview object must round-trip.
func TestLineitem_GradesReleasedAndSubmissionReview_Serialization(t *testing.T) {
	released := false
	li := ags.Lineitem{
		Label:          "Quiz",
		ScoreMaximum:   100,
		GradesReleased: &released,
		SubmissionReview: &ags.SubmissionReview{
			Label:  "Review submission",
			URL:    "https://tool.example.com/review",
			Custom: map[string]string{"stage": "review"},
		},
	}
	data, err := json.Marshal(li)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"gradesReleased":false`) {
		t.Errorf("explicit false gradesReleased must be serialized, got %s", data)
	}
	if !strings.Contains(string(data), `"submissionReview"`) {
		t.Errorf("submissionReview missing, got %s", data)
	}

	li.GradesReleased = nil
	data, _ = json.Marshal(li)
	if strings.Contains(string(data), "gradesReleased") {
		t.Errorf("nil gradesReleased must be omitted, got %s", data)
	}
}
