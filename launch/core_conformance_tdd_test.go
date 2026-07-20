package launch_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
	"github.com/robertjndw/go-lti-tool/launch"
	"github.com/robertjndw/go-lti-tool/login"
)

func TestLaunch_RequiredOIDCTimeClaims(t *testing.T) {
	tests := map[string]func(jwt.MapClaims){
		"missing exp":           func(c jwt.MapClaims) { delete(c, "exp") },
		"missing iat":           func(c jwt.MapClaims) { delete(c, "iat") },
		"iat too far in future": func(c jwt.MapClaims) { c["iat"] = time.Now().Add(10 * time.Minute).Unix() },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			nonce, state := "nonce-"+name, "state-"+name
			f.storeNonce(t, nonce)
			f.setStateCookie(state)
			if _, err := f.validate(t, state, f.validToken(t, nonce, mutate)); err == nil {
				t.Error("expected invalid OIDC time claims to be rejected")
			}
		})
	}
}

func TestLaunch_UnknownClaimsIgnored(t *testing.T) {
	f := newFixture(t)
	nonce, state := "nonce-extension", "state-extension"
	f.storeNonce(t, nonce)
	f.setStateCookie(state)
	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		c["https://vendor.example.com/session"] = map[string]any{"opaque": true}
	})
	if _, err := f.validate(t, state, token); err != nil {
		t.Errorf("unknown extension claim must be ignored, got %v", err)
	}
}

func TestLaunch_UnknownMessageTypeRejected(t *testing.T) {
	f := newFixture(t)
	nonce, state := "nonce-unknown-message", "state-unknown-message"
	f.storeNonce(t, nonce)
	f.setStateCookie(state)
	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		c[lti.ClaimPrefix+"message_type"] = "VendorMessage"
	})
	if _, err := f.validate(t, state, token); !errors.Is(err, lti.ErrInvalidClaims) {
		t.Errorf("expected ErrInvalidClaims for unsupported message type, got %v", err)
	}
}

// Core 1.3 limits the identifiers below to 255 ASCII characters. These are
// receiver-side contract tests: a signed but schema-invalid launch must not be
// exposed to application code.
func TestLaunch_CoreIdentifierLengthBounds(t *testing.T) {
	tests := map[string]func(jwt.MapClaims){
		"sub": func(c jwt.MapClaims) {
			c["sub"] = strings.Repeat("s", 256)
		},
		"deployment_id": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"deployment_id"] = strings.Repeat("d", 256)
		},
		"resource_link.id": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"resource_link"] = map[string]any{"id": strings.Repeat("r", 256)}
		},
		"context.id": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"context"] = map[string]any{"id": strings.Repeat("c", 256)}
		},
		"tool_platform.guid": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"tool_platform"] = map[string]any{"guid": strings.Repeat("g", 256)}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			nonce := "nonce-bound-" + name
			state := "state-bound-" + name
			f.storeNonce(t, nonce)
			f.setStateCookie(state)

			_, err := f.validate(t, state, f.validToken(t, nonce, mutate))
			if !errors.Is(err, lti.ErrInvalidClaims) {
				t.Errorf("expected ErrInvalidClaims, got %v", err)
			}
		})
	}
}

func TestLaunch_CoreIdentifierMaximumLengthAccepted(t *testing.T) {
	f := newFixture(t)
	nonce, state := "nonce-max-identifiers", "state-max-identifiers"
	f.storeNonce(t, nonce)
	f.setStateCookie(state)
	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		c["sub"] = strings.Repeat("s", 255)
		c[lti.ClaimPrefix+"deployment_id"] = strings.Repeat("d", 255)
		c[lti.ClaimPrefix+"resource_link"] = map[string]any{"id": strings.Repeat("r", 255)}
		c[lti.ClaimPrefix+"context"] = map[string]any{"id": strings.Repeat("c", 255)}
		c[lti.ClaimPrefix+"tool_platform"] = map[string]any{"guid": strings.Repeat("g", 255)}
	})
	if _, err := f.validate(t, state, token); err != nil {
		t.Errorf("255-character identifiers must be accepted: %v", err)
	}
}

// Core 1.3 defines these identifiers as ASCII strings, not arbitrary UTF-8.
// A short non-ASCII value must not bypass the schema check merely because it
// remains below the 255-byte maximum.
func TestLaunch_CoreIdentifiersRequireASCII(t *testing.T) {
	tests := map[string]func(jwt.MapClaims){
		"sub": func(c jwt.MapClaims) {
			c["sub"] = "user-é"
		},
		"deployment_id": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"deployment_id"] = "deployment-é"
		},
		"resource_link.id": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"resource_link"] = map[string]any{"id": "resource-é"}
		},
		"context.id": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"context"] = map[string]any{"id": "context-é"}
		},
		"tool_platform.guid": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"tool_platform"] = map[string]any{"guid": "platform-é"}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			nonce, state := "nonce-ascii-"+name, "state-ascii-"+name
			f.storeNonce(t, nonce)
			f.setStateCookie(state)
			_, err := f.validate(t, state, f.validToken(t, nonce, mutate))
			if !errors.Is(err, lti.ErrInvalidClaims) {
				t.Errorf("expected ErrInvalidClaims, got %v", err)
			}
		})
	}
}

// Optional Core claim objects still have required members when present.
func TestLaunch_OptionalClaimRequiredMembers(t *testing.T) {
	tests := map[string]func(jwt.MapClaims){
		"context requires id": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"context"] = map[string]any{"title": "Course without an ID"}
		},
		"tool_platform requires guid": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"tool_platform"] = map[string]any{"name": "Platform without a GUID"}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			nonce := "nonce-nested-" + name
			state := "state-nested-" + name
			f.storeNonce(t, nonce)
			f.setStateCookie(state)

			_, err := f.validate(t, state, f.validToken(t, nonce, mutate))
			if !errors.Is(err, lti.ErrInvalidClaims) {
				t.Errorf("expected ErrInvalidClaims, got %v", err)
			}
		})
	}
}

func TestLaunch_CoreKnownClaimSchemaConstraints(t *testing.T) {
	tests := map[string]func(jwt.MapClaims){
		"non-empty roles includes a standard role": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"roles"] = []string{"https://vendor.example.com/role/CustomOnly"}
		},
		"context type includes a standard context type": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"context"] = map[string]any{
				"id": "context-1", "type": []string{"https://vendor.example.com/context/CustomOnly"},
			}
		},
		"role namespace prefix alone is not a vocabulary value": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"roles"] = []string{
				"http://purl.imsglobal.org/vocab/lis/v2/membership#NotARealRole",
			}
		},
		"context namespace prefix alone is not a vocabulary value": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"context"] = map[string]any{
				"id": "context-1", "type": []string{
					"http://purl.imsglobal.org/vocab/lis/v2/course#NotARealContextType",
				},
			}
		},
		"role_scope_mentor requires Mentor role": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"role_scope_mentor"] = []string{"mentee-1"}
		},
		"launch_presentation document_target vocabulary": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"launch_presentation"] = map[string]any{"document_target": "popup"}
		},
		"launch_presentation return_url must be fully-qualified HTTPS": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"launch_presentation"] = map[string]any{"return_url": "/relative"}
		},
		"launch_presentation return_url rejects HTTP": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"launch_presentation"] = map[string]any{"return_url": "http://platform.example.com/return"}
		},
		"target_link_uri must be fully-qualified HTTPS": func(c jwt.MapClaims) {
			c[lti.ClaimPrefix+"target_link_uri"] = "http://tool.example.com/launch"
		},
		// NOT tested: "tool_platform.url must be HTTPS". Unlike target_link_uri/
		// return_url above, tool_platform.url is purely descriptive metadata the
		// tool never navigates to or relies on; a direct fetch of the Core spec
		// found no field-specific HTTPS requirement for it, only the general
		// "SHOULD, by best practice" language that applies to every URL in an
		// LTI message. See CONFORMANCE.md's "Known test/spec disagreements".
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			nonce, state := "nonce-schema-"+name, "state-schema-"+name
			f.storeNonce(t, nonce)
			f.setStateCookie(state)
			_, err := f.validate(t, state, f.validToken(t, nonce, mutate))
			if !errors.Is(err, lti.ErrInvalidClaims) {
				t.Errorf("expected ErrInvalidClaims, got %v", err)
			}
		})
	}
}

// Core 1.3 requires the signed target_link_uri to equal the value supplied in
// the login initiation. Merely trusting that each value is syntactically valid
// leaves the OIDC transaction unbound.
func TestLaunch_TargetLinkURIBoundToLoginInitiation(t *testing.T) {
	f := newFixture(t)
	req := ltitest.MakeLoginRequest(t, map[string]string{
		"iss":             f.reg.Issuer,
		"login_hint":      "user-hint",
		"target_link_uri": "https://tool.example.com/original",
	})
	redirect, cookies, err := login.HandleLogin(context.Background(), login.Config{
		Datastore:     f.ds,
		NonceStore:    f.nonces,
		CookieHandler: f.cookies,
	}, req)
	if err != nil {
		t.Fatalf("HandleLogin failed: %v", err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	state, nonce := u.Query().Get("state"), u.Query().Get("nonce")
	for _, cookie := range cookies {
		f.cookies.SetRaw(cookie.Name, cookie.Value)
	}

	token := f.validToken(t, nonce, func(c jwt.MapClaims) {
		c[lti.ClaimPrefix+"target_link_uri"] = "https://tool.example.com/attacker-selected"
	})
	_, err = f.validate(t, state, token)
	if !errors.Is(err, lti.ErrInvalidClaims) {
		t.Errorf("expected ErrInvalidClaims for a target_link_uri transaction mismatch, got %v", err)
	}
}

// A nonce from a different login transaction must not be combinable with a
// valid state cookie. Both values independently being fresh is insufficient.
func TestLaunch_NonceIsBoundToState(t *testing.T) {
	f := newFixture(t)
	loginOnce := func(target string) (state, nonce string, cookies []*http.Cookie) {
		t.Helper()
		redirect, cookies, err := login.HandleLogin(context.Background(), login.Config{
			Datastore: f.ds, NonceStore: f.nonces, CookieHandler: f.cookies,
		}, ltitest.MakeLoginRequest(t, map[string]string{
			"iss": f.reg.Issuer, "login_hint": "hint", "target_link_uri": target,
		}))
		if err != nil {
			t.Fatalf("HandleLogin failed: %v", err)
		}
		u, _ := url.Parse(redirect)
		return u.Query().Get("state"), u.Query().Get("nonce"), cookies
	}

	stateA, _, cookiesA := loginOnce("https://tool.example.com/a")
	_, nonceB, _ := loginOnce("https://tool.example.com/b")
	for _, cookie := range cookiesA {
		f.cookies.SetRaw(cookie.Name, cookie.Value)
	}

	_, err := f.validate(t, stateA, f.validToken(t, nonceB, nil))
	if !errors.Is(err, lti.ErrInvalidNonce) {
		t.Errorf("expected ErrInvalidNonce when nonce and state came from different logins, got %v", err)
	}
}

// The Security Framework requires audience authentication failures to use
// HTTP 401, while malformed messages remain HTTP 400.
func TestLaunch_HandlerUsesAuthenticationStatusForAudienceFailure(t *testing.T) {
	f := newFixture(t)
	state := "state-http-audience"
	f.setStateCookie(state)
	token := f.validToken(t, "unused-nonce", func(c jwt.MapClaims) {
		c["aud"] = "another-client"
	})

	req := ltitest.MakeLaunchRequest(t, state, token)
	recorder := httptest.NewRecorder()
	launch.Handler(f.cfg(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("next handler must not run")
	})).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestLaunch_HandlerSecurityStatusClasses(t *testing.T) {
	tests := []struct {
		name       string
		wantStatus int
		request    func(*testing.T, *fixture) (*http.Request, launch.Config)
	}{
		{
			name: "invalid state", wantStatus: http.StatusUnauthorized,
			request: func(t *testing.T, f *fixture) (*http.Request, launch.Config) {
				return ltitest.MakeLaunchRequest(t, "missing-cookie", f.validToken(t, "nonce", nil)), f.cfg()
			},
		},
		{
			name: "invalid signature", wantStatus: http.StatusUnauthorized,
			request: func(t *testing.T, f *fixture) (*http.Request, launch.Config) {
				state := "state-signature-status"
				f.setStateCookie(state)
				token := ltitest.SignJWT(t, ltitest.NewKey(t), "platform-kid-1", ltitest.DefaultClaims(f.reg, "nonce"))
				return ltitest.MakeLaunchRequest(t, state, token), f.cfg()
			},
		},
		{
			name: "expired token", wantStatus: http.StatusUnauthorized,
			request: func(t *testing.T, f *fixture) (*http.Request, launch.Config) {
				state := "state-expired-status"
				f.setStateCookie(state)
				token := f.validToken(t, "nonce", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
				return ltitest.MakeLaunchRequest(t, state, token), f.cfg()
			},
		},
		{
			name: "invalid nonce", wantStatus: http.StatusUnauthorized,
			request: func(t *testing.T, f *fixture) (*http.Request, launch.Config) {
				state := "state-nonce-status"
				f.setStateCookie(state)
				return ltitest.MakeLaunchRequest(t, state, f.validToken(t, "not-stored", nil)), f.cfg()
			},
		},
		{
			name: "platform authentication error", wantStatus: http.StatusUnauthorized,
			request: func(t *testing.T, f *fixture) (*http.Request, launch.Config) {
				form := url.Values{"error": {"login_required"}, "error_description": {"session ended"}}
				req := httptest.NewRequest(http.MethodPost, "/launch", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req, f.cfg()
			},
		},
		{
			name: "unknown registration", wantStatus: http.StatusForbidden,
			request: func(t *testing.T, f *fixture) (*http.Request, launch.Config) {
				state := "state-registration-status"
				f.setStateCookie(state)
				token := f.validToken(t, "nonce", func(c jwt.MapClaims) { c["iss"] = "https://unknown.example.com" })
				return ltitest.MakeLaunchRequest(t, state, token), f.cfg()
			},
		},
		{
			name: "unknown deployment", wantStatus: http.StatusForbidden,
			request: func(t *testing.T, f *fixture) (*http.Request, launch.Config) {
				state, nonce := "state-deployment-status", "nonce-deployment-status"
				f.setStateCookie(state)
				f.storeNonce(t, nonce)
				cfg := f.cfg()
				cfg.Datastore = &ltitest.StrictDatastore{Reg: f.reg, DeploymentID: "known-deployment"}
				return ltitest.MakeLaunchRequest(t, state, f.validToken(t, nonce, nil)), cfg
			},
		},
		{
			name: "malformed request", wantStatus: http.StatusBadRequest,
			request: func(t *testing.T, f *fixture) (*http.Request, launch.Config) {
				return ltitest.MakeLaunchRequest(t, "state", ""), f.cfg()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			req, cfg := tt.request(t, f)
			recorder := httptest.NewRecorder()
			launch.Handler(cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("next handler must not run")
			})).ServeHTTP(recorder, req)
			if recorder.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if recorder.Body.String() != "launch failed\n" {
				t.Errorf("body leaks validation detail: %q", recorder.Body.String())
			}
		})
	}
}
