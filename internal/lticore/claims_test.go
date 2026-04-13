package lticore

import (
	"encoding/json"
	"testing"
)

func TestAudienceContains(t *testing.T) {
	tests := []struct {
		name     string
		audience Audience
		value    string
		want     bool
	}{
		{"found single", Audience{"abc"}, "abc", true},
		{"found in list", Audience{"x", "y", "z"}, "y", true},
		{"not found", Audience{"a", "b"}, "c", false},
		{"empty audience", Audience{}, "a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.audience.Contains(tt.value); got != tt.want {
				t.Errorf("Contains(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestAudienceUnmarshalJSON(t *testing.T) {
	t.Run("single string", func(t *testing.T) {
		var a Audience
		if err := json.Unmarshal([]byte(`"client-1"`), &a); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(a) != 1 || a[0] != "client-1" {
			t.Errorf("got %v, want [client-1]", a)
		}
	})

	t.Run("array", func(t *testing.T) {
		var a Audience
		if err := json.Unmarshal([]byte(`["client-1","client-2"]`), &a); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(a) != 2 || a[0] != "client-1" || a[1] != "client-2" {
			t.Errorf("got %v, want [client-1 client-2]", a)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		var a Audience
		if err := json.Unmarshal([]byte(`123`), &a); err == nil {
			t.Error("expected error for numeric audience, got nil")
		}
	})
}

func TestAudienceMarshalJSON(t *testing.T) {
	t.Run("single element serialises as array", func(t *testing.T) {
		a := Audience{"client-1"}
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != `["client-1"]` {
			t.Errorf("got %s, want [\"client-1\"]", data)
		}
	})

	t.Run("multiple elements", func(t *testing.T) {
		a := Audience{"x", "y"}
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != `["x","y"]` {
			t.Errorf("got %s, want [\"x\",\"y\"]", data)
		}
	})
}

func TestAudienceRoundTrip(t *testing.T) {
	// A single-string "aud" field in a JWT must round-trip through Unmarshal → Marshal.
	type wrapper struct {
		Aud Audience `json:"aud"`
	}
	original := `{"aud":"client-1"}`
	var w wrapper
	if err := json.Unmarshal([]byte(original), &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !w.Aud.Contains("client-1") {
		t.Fatal("Contains failed after round-trip")
	}
	// Marshal always produces an array form.
	out, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != `{"aud":["client-1"]}` {
		t.Errorf("got %s, want {\"aud\":[\"client-1\"]}", out)
	}
}
