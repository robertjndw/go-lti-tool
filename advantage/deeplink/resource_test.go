package deeplink_test

import (
	"encoding/json"
	"testing"

	"github.com/robertjndw/go-lti-tool/advantage/deeplink"
)

// Task 1.2: GradesReleased must be a *bool so an explicit false survives
// serialization (a plain bool with omitempty drops the zero value).
func TestLineItemProperty_GradesReleased_ExplicitFalse(t *testing.T) {
	li := deeplink.LineItemProperty{
		Label:          "Quiz 1",
		ScoreMaximum:   100,
		GradesReleased: deeplink.Bool(false),
	}
	data, err := json.Marshal(li)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	v, ok := got["gradesReleased"]
	if !ok {
		t.Fatalf("gradesReleased key missing from %s, want present with value false", data)
	}
	if v != false {
		t.Errorf("gradesReleased = %v, want false", v)
	}
}

func TestLineItemProperty_GradesReleased_ExplicitTrue(t *testing.T) {
	li := deeplink.LineItemProperty{GradesReleased: deeplink.Bool(true)}
	data, err := json.Marshal(li)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if v := got["gradesReleased"]; v != true {
		t.Errorf("gradesReleased = %v, want true", v)
	}
}

func TestLineItemProperty_GradesReleased_NilOmitted(t *testing.T) {
	li := deeplink.LineItemProperty{Label: "Quiz 1", ScoreMaximum: 100}
	data, err := json.Marshal(li)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if _, ok := got["gradesReleased"]; ok {
		t.Errorf("gradesReleased present in %s, want omitted when nil", data)
	}
}
