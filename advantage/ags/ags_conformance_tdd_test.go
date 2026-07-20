package ags_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/ags"
)

func validConformanceScore() ags.Score {
	return ags.Score{
		UserID:           "learner-1",
		ActivityProgress: ags.ActivityProgressCompleted,
		GradingProgress:  ags.GradingProgressFullyGraded,
		Timestamp:        "2026-01-01T00:00:00.123Z",
	}
}

func newScoreService(t *testing.T, status int) (*ags.Service, *int, string) {
	t.Helper()
	tokenSrv := newTokenServer(t)
	requests := 0
	serviceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(status)
		if status != http.StatusNoContent {
			json.NewEncoder(w).Encode(ags.Lineitem{ //nolint:errcheck
				ID: r.URL.String(), Label: "Valid", ScoreMaximum: 100,
			})
		}
	}))
	t.Cleanup(serviceSrv.Close)
	return ags.New(newConn(t, tokenSrv.URL), &lti.AGSClaim{Lineitems: serviceSrv.URL + "/lineitems"}), &requests, serviceSrv.URL
}

// AGS defines scoreGiven as non-negative, scoreMaximum as positive whenever it
// is supplied, and both progress properties as closed vocabularies.
func TestAGS_SubmitScore_RejectsSchemaInvalidValuesBeforeSending(t *testing.T) {
	tests := map[string]func(*ags.Score){
		"negative scoreGiven": func(s *ags.Score) {
			s.ScoreGiven = ags.Float64(-1)
			s.ScoreMaximum = ags.Float64(100)
		},
		"non-positive standalone scoreMaximum": func(s *ags.Score) {
			s.ScoreMaximum = ags.Float64(0)
		},
		"unknown activityProgress": func(s *ags.Score) {
			s.ActivityProgress = "AlmostDone"
		},
		"unknown gradingProgress": func(s *ags.Score) {
			s.GradingProgress = "MaybeGraded"
		},
		"timestamp without fractional seconds": func(s *ags.Score) {
			s.Timestamp = "2026-01-01T00:00:00Z"
		},
		"invalid timestamp": func(s *ags.Score) {
			s.Timestamp = "yesterday"
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			svc, requests, serviceURL := newScoreService(t, http.StatusNoContent)
			score := validConformanceScore()
			mutate(&score)
			err := svc.SubmitScore(context.Background(), serviceURL+"/lineitems/1", score)
			if err == nil {
				t.Error("expected schema validation error")
			}
			if *requests != 0 {
				t.Errorf("invalid score reached the service endpoint (%d requests)", *requests)
			}
		})
	}
}

// AGS requires sub-second precision but permits Z, +HH:MM, and +HH timezone
// forms. Strict validation must not reject any of those normative forms.
func TestAGS_SubmitScore_AcceptsAllNormativeISO8601Offsets(t *testing.T) {
	for _, timestamp := range []string{
		"2026-01-01T00:00:00.123Z",
		"2026-01-01T00:00:00.123+00:00",
		"2026-01-01T00:00:00.123+00",
	} {
		t.Run(timestamp, func(t *testing.T) {
			svc, _, serviceURL := newScoreService(t, http.StatusNoContent)
			score := validConformanceScore()
			score.Timestamp = timestamp
			if err := svc.SubmitScore(context.Background(), serviceURL+"/lineitems/1", score); err != nil {
				t.Errorf("SubmitScore rejected normative timestamp %q: %v", timestamp, err)
			}
		})
	}
}

// Both progress properties are closed vocabularies. Test every normative
// value so adding validation cannot accidentally narrow the specification.
func TestAGS_SubmitScore_AcceptsAllProgressVocabularyValues(t *testing.T) {
	activityValues := []string{
		ags.ActivityProgressInitialized,
		ags.ActivityProgressStarted,
		ags.ActivityProgressInProgress,
		ags.ActivityProgressSubmitted,
		ags.ActivityProgressCompleted,
	}
	gradingValues := []string{
		ags.GradingProgressFullyGraded,
		ags.GradingProgressPending,
		ags.GradingProgressPendingManual,
		ags.GradingProgressFailed,
		ags.GradingProgressNotReady,
	}
	for _, activity := range activityValues {
		for _, grading := range gradingValues {
			name := activity + "/" + grading
			t.Run(name, func(t *testing.T) {
				svc, _, serviceURL := newScoreService(t, http.StatusNoContent)
				score := validConformanceScore()
				score.ActivityProgress = activity
				score.GradingProgress = grading
				if err := svc.SubmitScore(context.Background(), serviceURL+"/lineitems/1", score); err != nil {
					t.Errorf("SubmitScore rejected normative progress values: %v", err)
				}
			})
		}
	}
}

// scoringUserId is part of both Score and Result and is needed by submission
// review workflows where the grader differs from the learner.
func TestAGS_ScoringUserIDSchema(t *testing.T) {
	t.Run("Score serializes scoringUserId", func(t *testing.T) {
		score := validConformanceScore()
		v := reflect.ValueOf(&score).Elem()
		field := v.FieldByName("ScoringUserID")
		if !field.IsValid() {
			t.Fatal("ags.Score must expose ScoringUserID")
		}
		field.SetString("grader-9")
		body, err := json.Marshal(score)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"scoringUserId":"grader-9"`) {
			t.Errorf("scoringUserId missing from Score JSON: %s", body)
		}
	})

	t.Run("Result parses scoringUserId", func(t *testing.T) {
		var result ags.Result
		if err := json.Unmarshal([]byte(`{"id":"r1","userId":"u1","scoringUserId":"grader-9"}`), &result); err != nil {
			t.Fatal(err)
		}
		field := reflect.ValueOf(result).FieldByName("ScoringUserID")
		if !field.IsValid() {
			t.Fatal("ags.Result must expose ScoringUserID")
		}
		if field.String() != "grader-9" {
			t.Errorf("ScoringUserID = %q, want grader-9", field.String())
		}
	})
}

// The optional submission object has two ISO 8601 timestamps and, when both
// are present, startedAt must not be later than submittedAt.
func TestAGS_SubmitScore_SubmissionSchemaAndOrdering(t *testing.T) {
	score := validConformanceScore()
	v := reflect.ValueOf(&score).Elem()
	field := v.FieldByName("Submission")
	if !field.IsValid() {
		t.Fatal("ags.Score must expose Submission")
	}
	if field.Type().Kind() != reflect.Pointer {
		t.Fatalf("Score.Submission must be a pointer, got %v", field.Type())
	}
	submission := reflect.New(field.Type().Elem())
	submission.Elem().FieldByName("StartedAt").SetString("2026-01-02T00:00:00.123Z")
	submission.Elem().FieldByName("SubmittedAt").SetString("2026-01-01T00:00:00.123Z")
	field.Set(submission)

	svc, requests, serviceURL := newScoreService(t, http.StatusNoContent)
	if err := svc.SubmitScore(context.Background(), serviceURL+"/lineitems/1", score); err == nil {
		t.Error("expected startedAt > submittedAt to be rejected")
	}
	if *requests != 0 {
		t.Error("invalid submission ordering must be rejected before network I/O")
	}
}

// AGS applies the same sub-second precision requirement to submission.startedAt
// and submission.submittedAt as it does to the top-level Score timestamp.
func TestAGS_SubmitScore_SubmissionTimestampsRequireSubsecondPrecision(t *testing.T) {
	tests := map[string]*ags.ScoreSubmission{
		"startedAt":   {StartedAt: "2026-01-01T00:00:00Z"},
		"submittedAt": {SubmittedAt: "2026-01-01T00:00:00Z"},
	}

	for name, submission := range tests {
		t.Run(name, func(t *testing.T) {
			svc, requests, serviceURL := newScoreService(t, http.StatusNoContent)
			score := validConformanceScore()
			score.Submission = submission

			if err := svc.SubmitScore(context.Background(), serviceURL+"/lineitems/1", score); err == nil {
				t.Error("expected submission timestamp without fractional seconds to be rejected")
			}
			if *requests != 0 {
				t.Error("invalid submission timestamp must be rejected before network I/O")
			}
		})
	}
}

// The Result schema defines an omitted resultMaximum as 1. Callers need one
// canonical API for that default rather than duplicating it throughout tools.
func TestAGS_ResultMaximumDefaultsToOne(t *testing.T) {
	result := ags.Result{}
	method := reflect.ValueOf(&result).MethodByName("EffectiveResultMaximum")
	if !method.IsValid() {
		t.Fatal("ags.Result must expose EffectiveResultMaximum")
	}
	got := method.Call(nil)
	if len(got) != 1 || got[0].Kind() != reflect.Float64 || got[0].Float() != 1 {
		t.Errorf("EffectiveResultMaximum() = %v, want 1", got)
	}
}

// The results container supports user_id and limit filters, using the same
// optional-query convention as GetLineitems.
func TestAGS_GetResults_QueryParams(t *testing.T) {
	tokenSrv := newTokenServer(t)
	var captured string
	serviceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`)) //nolint:errcheck
	}))
	t.Cleanup(serviceSrv.Close)
	svc := ags.New(newConn(t, tokenSrv.URL), &lti.AGSClaim{})

	method := reflect.ValueOf(svc).MethodByName("GetResults")
	if !method.IsValid() || !method.Type().IsVariadic() || method.Type().NumIn() != 3 {
		t.Fatalf("GetResults must accept optional ResultsQuery; signature is %v", method.Type())
	}
	querySliceType := method.Type().In(2)
	query := reflect.New(querySliceType.Elem()).Elem()
	query.FieldByName("UserID").SetString("learner-1")
	query.FieldByName("Limit").SetInt(25)
	queries := reflect.MakeSlice(querySliceType, 1, 1)
	queries.Index(0).Set(query)
	results := method.CallSlice([]reflect.Value{
		reflect.ValueOf(context.Background()),
		reflect.ValueOf(serviceSrv.URL + "/lineitems/1"),
		queries,
	})
	if errValue := results[1]; !errValue.IsNil() {
		t.Fatalf("GetResults failed: %v", errValue.Interface())
	}
	for _, want := range []string{"user_id=learner-1", "limit=25"} {
		if !strings.Contains(captured, want) {
			t.Errorf("query %q missing %q", captured, want)
		}
	}
}

// A line item sent by a tool requires a non-blank label and positive maximum.
func TestAGS_LineitemWritesRejectInvalidSchemaBeforeSending(t *testing.T) {
	tests := []struct {
		name   string
		create bool
		item   ags.Lineitem
	}{
		{name: "create blank label", create: true, item: ags.Lineitem{Label: "  ", ScoreMaximum: 100}},
		{name: "create non-positive maximum", create: true, item: ags.Lineitem{Label: "Quiz", ScoreMaximum: 0}},
		{name: "update blank label", item: ags.Lineitem{Label: "\t", ScoreMaximum: 100}},
		{name: "update non-positive maximum", item: ags.Lineitem{Label: "Quiz", ScoreMaximum: -1}},
		{name: "create malformed startDateTime", create: true, item: ags.Lineitem{Label: "Quiz", ScoreMaximum: 100, StartDateTime: "tomorrow"}},
		{name: "create startDateTime without timezone", create: true, item: ags.Lineitem{Label: "Quiz", ScoreMaximum: 100, StartDateTime: "2026-01-01T00:00:00"}},
		{name: "update malformed endDateTime", item: ags.Lineitem{Label: "Quiz", ScoreMaximum: 100, EndDateTime: "not-a-date"}},
		{name: "update endDateTime without timezone", item: ags.Lineitem{Label: "Quiz", ScoreMaximum: 100, EndDateTime: "2026-01-01T00:00:00"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, requests, serviceURL := newScoreService(t, http.StatusOK)
			var err error
			if tt.create {
				_, err = svc.CreateLineitem(context.Background(), tt.item)
			} else {
				tt.item.ID = serviceURL + "/lineitems/1"
				_, err = svc.UpdateLineitem(context.Background(), tt.item)
			}
			if err == nil {
				t.Error("expected line item validation error")
			}
			if *requests != 0 {
				t.Error("invalid line item must be rejected before network I/O")
			}
		})
	}
}

// Line-item availability dates use ISO 8601 with a required timezone but do
// not require fractional seconds. Z and both offset spellings are valid.
func TestAGS_LineitemWritesAcceptAllNormativeDateTimeForms(t *testing.T) {
	for _, timestamp := range []string{
		"2026-01-01T00:00:00Z",
		"2026-01-01T00:00:00.123Z",
		"2026-01-01T00:00:00+00:00",
		"2026-01-01T00:00:00+00",
	} {
		t.Run(timestamp, func(t *testing.T) {
			svc, _, _ := newScoreService(t, http.StatusOK)
			item := ags.Lineitem{
				Label: "Quiz", ScoreMaximum: 100,
				StartDateTime: timestamp, EndDateTime: timestamp,
			}
			if _, err := svc.CreateLineitem(context.Background(), item); err != nil {
				t.Errorf("CreateLineitem rejected normative datetime %q: %v", timestamp, err)
			}
		})
	}
}
