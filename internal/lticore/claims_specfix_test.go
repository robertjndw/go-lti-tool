package lticore

import (
	"encoding/json"
	"testing"
)

// The azp, role_scope_mentor, for_user and lti1p1 claims must parse from a
// launch JWT payload.
func TestLTIClaims_NewClaims_Unmarshal(t *testing.T) {
	payload := `{
		"iss": "https://platform.example.com",
		"sub": "user-1",
		"aud": ["client-a", "other"],
		"azp": "client-a",
		"https://purl.imsglobal.org/spec/lti/claim/role_scope_mentor": ["student-1", "student-2"],
		"https://purl.imsglobal.org/spec/lti/claim/for_user": {
			"user_id": "student-1",
			"name": "Jane Learner",
			"email": "jane@example.com",
			"roles": ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"]
		},
		"https://purl.imsglobal.org/spec/lti/claim/lti1p1": {
			"user_id": "legacy-42",
			"oauth_consumer_key": "key-1",
			"oauth_consumer_key_sign": "sig"
		}
	}`

	var c LTIClaims
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Azp != "client-a" {
		t.Errorf("azp = %q", c.Azp)
	}
	if len(c.RoleScopeMentor) != 2 || c.RoleScopeMentor[0] != "student-1" {
		t.Errorf("role_scope_mentor = %v", c.RoleScopeMentor)
	}
	if c.ForUser == nil || c.ForUser.UserID != "student-1" || c.ForUser.Email != "jane@example.com" || len(c.ForUser.Roles) != 1 {
		t.Errorf("for_user = %+v", c.ForUser)
	}
	if c.LTI11 == nil || c.LTI11.UserID != "legacy-42" || c.LTI11.OAuthConsumerKey != "key-1" || c.LTI11.OAuthConsumerKeySign != "sig" {
		t.Errorf("lti1p1 = %+v", c.LTI11)
	}
}

// Core defines custom as a string-to-string map. Numeric, boolean, null,
// array, and object values are schema violations and must not be silently
// coerced or discarded by strict launch decoding.
func TestCustomParameters_RejectsNonStringValues(t *testing.T) {
	for name, payload := range map[string]string{
		"number":  `{"points": 5}`,
		"boolean": `{"flag": true}`,
		"null":    `{"value": null}`,
		"array":   `{"value": [1]}`,
		"object":  `{"value": {"a": 1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var c CustomParameters
			if err := json.Unmarshal([]byte(payload), &c); err == nil {
				t.Errorf("expected non-string custom value to be rejected: %s", payload)
			}
		})
	}
}

func TestCustomParameters_StringValuesRoundTrip(t *testing.T) {
	payload := `{"empty":"","points":"5","flag":"true"}`
	var c CustomParameters
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("valid string custom values rejected: %v", err)
	}
	if c["empty"] != "" || c["points"] != "5" || c["flag"] != "true" {
		t.Errorf("Custom = %v", c)
	}
}

// Core's launch_presentation schema defines height and width as JSON numbers.
func TestLaunchPresentation_HeightWidthRequireNumbers(t *testing.T) {
	for name, payload := range map[string]string{
		"numeric height string": `{"height":"800"}`,
		"invalid height string": `{"height":"not-a-number"}`,
		"numeric width string":  `{"width":"600"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var lp LaunchPresentation
			if err := json.Unmarshal([]byte(payload), &lp); err == nil {
				t.Errorf("expected string dimension to be rejected: %s", payload)
			}
		})
	}
}

func TestLaunchPresentation_HeightWidthNumbersAccepted(t *testing.T) {
	var lp LaunchPresentation
	if err := json.Unmarshal([]byte(`{"height":800,"width":600}`), &lp); err != nil {
		t.Fatalf("numeric dimensions rejected: %v", err)
	}
	if lp.Height != 800 || lp.Width != 600 {
		t.Errorf("dimensions = %vx%v, want 600x800", lp.Width, lp.Height)
	}
}

// Task 1.7: ToolPlatform gains url, description, and contact_email.
func TestLTIClaims_ToolPlatform_FullObject(t *testing.T) {
	payload := `{
		"iss": "https://platform.example.com",
		"https://purl.imsglobal.org/spec/lti/claim/tool_platform": {
			"guid": "platform-guid-1",
			"name": "Example Platform",
			"version": "1.0",
			"product_family_code": "example",
			"url": "https://platform.example.com",
			"description": "An example LMS",
			"contact_email": "support@platform.example.com"
		}
	}`
	var c LTIClaims
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.ToolPlatform == nil {
		t.Fatal("ToolPlatform is nil")
	}
	tp := c.ToolPlatform
	if tp.GUID != "platform-guid-1" || tp.Name != "Example Platform" || tp.Version != "1.0" || tp.ProductFamilyCode != "example" {
		t.Errorf("existing fields regressed: %+v", tp)
	}
	if tp.URL != "https://platform.example.com" {
		t.Errorf("URL = %q", tp.URL)
	}
	if tp.Description != "An example LMS" {
		t.Errorf("Description = %q", tp.Description)
	}
	if tp.ContactEmail != "support@platform.example.com" {
		t.Errorf("ContactEmail = %q", tp.ContactEmail)
	}
}

func TestLaunchPresentation_OtherFields_RoundTrip(t *testing.T) {
	payload := `{"document_target": "iframe", "return_url": "https://platform.example.com/return", "locale": "en-US", "height": 100, "width": 200}`
	var lp LaunchPresentation
	if err := json.Unmarshal([]byte(payload), &lp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if lp.DocumentTarget != "iframe" || lp.ReturnURL != "https://platform.example.com/return" || lp.Locale != "en-US" {
		t.Errorf("lp = %+v", lp)
	}
}
