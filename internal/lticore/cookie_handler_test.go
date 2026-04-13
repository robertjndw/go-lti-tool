package lticore

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultCookieHandler_GetCookie(t *testing.T) {
	h := DefaultCookieHandler{}

	t.Run("reads main cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "state", Value: "abc123"})

		got, err := h.GetCookie(req, "state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "abc123" {
			t.Errorf("got %q, want %q", got, "abc123")
		}
	})

	t.Run("falls back to LEGACY_ cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "LEGACY_state", Value: "legacy-val"})

		got, err := h.GetCookie(req, "state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "legacy-val" {
			t.Errorf("got %q, want %q", got, "legacy-val")
		}
	})

	t.Run("prefers main over legacy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "state", Value: "main-val"})
		req.AddCookie(&http.Cookie{Name: "LEGACY_state", Value: "legacy-val"})

		got, err := h.GetCookie(req, "state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "main-val" {
			t.Errorf("got %q, want main-val", got)
		}
	})

	t.Run("returns error when cookie absent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		_, err := h.GetCookie(req, "state")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestDefaultCookieHandler_SetCookie(t *testing.T) {
	h := DefaultCookieHandler{}
	w := httptest.NewRecorder()

	h.SetCookie(w, "state", "xyz789", 300)

	resp := w.Result()
	cookies := resp.Cookies()

	var main, legacy *http.Cookie
	for _, c := range cookies {
		switch c.Name {
		case "state":
			main = c
		case "LEGACY_state":
			legacy = c
		}
	}

	if main == nil {
		t.Fatal("main cookie 'state' not set")
	}
	if main.Value != "xyz789" {
		t.Errorf("main cookie value = %q, want %q", main.Value, "xyz789")
	}
	if main.SameSite != http.SameSiteNoneMode {
		t.Errorf("main cookie SameSite = %v, want SameSiteNoneMode", main.SameSite)
	}
	if !main.Secure {
		t.Error("main cookie Secure = false, want true")
	}
	if !main.HttpOnly {
		t.Error("main cookie HttpOnly = false, want true")
	}

	if legacy == nil {
		t.Fatal("legacy cookie 'LEGACY_state' not set")
	}
	if legacy.Value != "xyz789" {
		t.Errorf("legacy cookie value = %q, want %q", legacy.Value, "xyz789")
	}
	// Legacy cookie must not carry SameSite=None.
	if legacy.SameSite == http.SameSiteNoneMode {
		t.Error("legacy cookie should not have SameSite=None")
	}
}
