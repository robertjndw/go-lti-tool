package lticore

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Deletion cookies must carry the same SameSite=None; Secure attributes as the
// original cookies — browsers drop third-party Set-Cookie headers without them,
// which would make deletion a no-op inside an LMS iframe.
func TestDefaultCookieHandler_DeleteCookie_Attributes(t *testing.T) {
	rec := httptest.NewRecorder()
	DefaultCookieHandler{}.DeleteCookie(rec, "lti1p3_state")

	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 deletion cookies, got %d", len(cookies))
	}
	for _, c := range cookies {
		if c.MaxAge != -1 {
			t.Errorf("cookie %q MaxAge = %d, want -1", c.Name, c.MaxAge)
		}
		if !c.Secure {
			t.Errorf("cookie %q must be Secure", c.Name)
		}
	}
	if cookies[0].SameSite != http.SameSiteNoneMode {
		t.Errorf("primary deletion cookie must be SameSite=None, got %v", cookies[0].SameSite)
	}
}
