package lticore

import (
	"net/http"
)

// CookieHandler abstracts reading and writing HTTP cookies.
// This allows callers to plug in custom cookie behaviour (e.g. encrypted cookies,
// SameSite=None for iframes, legacy fallbacks) without framework coupling.
type CookieHandler interface {
	// GetCookie reads a named cookie from the request.
	// Return an error (e.g. http.ErrNoCookie) if not found.
	GetCookie(r *http.Request, name string) (string, error)

	// SetCookie writes a cookie to the response.
	// maxAge is in seconds; 0 means session cookie.
	SetCookie(w http.ResponseWriter, name, value string, maxAge int) error

	// DeleteCookie removes a cookie from the browser by setting MaxAge to -1.
	DeleteCookie(w http.ResponseWriter, name string)
}

// DefaultCookieHandler writes SameSite=None; Secure cookies and a LEGACY_ prefixed
// fallback for browsers that strip SameSite=None cookies (mirrors the PHP reference
// implementation's iframe compatibility behaviour).
type DefaultCookieHandler struct{}

// GetCookie reads the named cookie. It prefers the SameSite=None version but falls
// back to the LEGACY_ prefixed cookie if the main one is absent.
func (h DefaultCookieHandler) GetCookie(r *http.Request, name string) (string, error) {
	if c, err := r.Cookie(name); err == nil {
		return c.Value, nil
	}
	if c, err := r.Cookie("LEGACY_" + name); err == nil {
		return c.Value, nil
	}
	return "", http.ErrNoCookie
}

// SetCookie writes both a SameSite=None; Secure cookie and a LEGACY_ version without
// SameSite, ensuring compatibility with browsers that block third-party SameSite=None
// cookies while embedded in iframes.
func (h DefaultCookieHandler) SetCookie(w http.ResponseWriter, name, value string, maxAge int) error {
	base := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   maxAge,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(w, base)

	legacy := &http.Cookie{
		Name:     "LEGACY_" + name,
		Value:    value,
		MaxAge:   maxAge,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, legacy)
	return nil
}

// DeleteCookie expires the named cookie and its LEGACY_ counterpart immediately.
func (h DefaultCookieHandler) DeleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, MaxAge: -1, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "LEGACY_" + name, MaxAge: -1, Path: "/"})
}
