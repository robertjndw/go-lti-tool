package login_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
	"github.com/robertjndw/go-lti-tool/login"
)

// The Security Framework requires TLS for LTI messages and resource URLs. This
// test keeps the explicit configuration knob covered in addition to the strict
// default asserted below.
func TestLogin_RequireHTTPSTargetLinkURI(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	field := reflect.ValueOf(&cfg).Elem().FieldByName("RequireHTTPSTargetLinkURI")
	if !field.IsValid() {
		t.Fatal("login.Config must expose RequireHTTPSTargetLinkURI for spec-strict deployments")
	}
	if field.Kind() != reflect.Bool || !field.CanSet() {
		t.Fatalf("RequireHTTPSTargetLinkURI must be a settable bool, got %v", field.Type())
	}
	field.SetBool(true)

	params := validParams(reg)
	params["target_link_uri"] = "http://tool.example.com/launch"
	if _, _, err := doLogin(t, cfg, params); err == nil {
		t.Error("expected an HTTP target_link_uri to be rejected in HTTPS-required mode")
	}
}

// TLS is a Security Framework MUST, so the conformant default must reject an
// HTTP target even when the caller did not remember to enable a hardening flag.
func TestLogin_DefaultRejectsHTTPTargetLinkURI(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	params := validParams(reg)
	params["target_link_uri"] = "http://tool.example.com/launch"
	if _, _, err := doLogin(t, cfg, params); err == nil {
		t.Error("default login configuration must reject an HTTP target_link_uri")
	}
}

// A known endpoint receiving an unknown platform is an authorization failure,
// not malformed syntax. The Security Framework status distinction matters to
// callers and monitoring even though the response body stays generic.
func TestLogin_HandlerUnknownIssuerReturnsForbidden(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	params := validParams(reg)
	params["iss"] = "https://unregistered-platform.example.com"
	req := ltitest.MakeLoginRequest(t, params)
	recorder := httptest.NewRecorder()

	login.Handler(cfg).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if body := recorder.Body.String(); body != "login initiation failed\n" {
		t.Errorf("body = %q, want generic login failure", body)
	}
}

// The strict mode must remain reachable through the primary Tool API, not only
// through the low-level login package.
func TestTool_WithLoginConfigCanRequireHTTPSTargetLinkURI(t *testing.T) {
	cfg, reg := newLoginConfig(t)
	tool := lti.NewTool(
		lti.WithDataStore(cfg.Datastore),
		lti.WithNonceStore(cfg.NonceStore),
		lti.WithCookieHandler(cfg.CookieHandler),
		lti.WithLoginConfig(func(c *login.Config) {
			field := reflect.ValueOf(c).Elem().FieldByName("RequireHTTPSTargetLinkURI")
			if !field.IsValid() {
				t.Fatal("login.Config must expose RequireHTTPSTargetLinkURI")
			}
			field.SetBool(true)
		}),
	)
	params := validParams(reg)
	params["target_link_uri"] = "http://tool.example.com/launch"
	recorder := httptest.NewRecorder()

	tool.HandleLogin().ServeHTTP(recorder, ltitest.MakeLoginRequest(t, params))

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}
