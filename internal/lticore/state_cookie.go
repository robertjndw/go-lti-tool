package lticore

import (
	"encoding/base64"
	"encoding/json"
)

// StateCookieData is the payload stored in the LTI launch state cookie. It
// binds the CSRF state token to the nonce and target_link_uri issued in the
// same login-initiation transaction (1EdTech Security Framework), so a state
// cookie from one login cannot be combined with a nonce or target_link_uri
// from a different one.
type StateCookieData struct {
	State         string `json:"state"`
	Nonce         string `json:"nonce,omitempty"`
	TargetLinkURI string `json:"target_link_uri,omitempty"`
}

// EncodeStateCookie serializes StateCookieData into a cookie-safe value.
func EncodeStateCookie(data StateCookieData) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeStateCookie parses a cookie value written by EncodeStateCookie. A
// value that predates this binding (a bare state string, as written directly
// by callers/tests that construct cookies without going through
// login.HandleLogin) or that fails to decode is treated as a bare state, with
// no bound nonce or target_link_uri to check.
func DecodeStateCookie(value string) StateCookieData {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return StateCookieData{State: value}
	}
	var data StateCookieData
	if err := json.Unmarshal(raw, &data); err != nil || data.State == "" {
		return StateCookieData{State: value}
	}
	return data
}
