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

// Task 1.6: custom claim values sent as numbers/booleans are coerced to
// strings instead of failing the launch; null/array/object values are
// skipped. A full-claims unmarshal with a numeric custom value must not error.
func TestCustomParameters_CoercesScalarsAndSkipsComplexValues(t *testing.T) {
	var c CustomParameters
	payload := `{"points": 5, "flag": true, "name": "x", "bad": [1], "nullish": null, "obj": {"a":1}}`
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := CustomParameters{"points": "5", "flag": "true", "name": "x"}
	if len(c) != len(want) {
		t.Fatalf("got %v, want %v", c, want)
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("c[%q] = %q, want %q", k, c[k], v)
		}
	}
	if _, ok := c["bad"]; ok {
		t.Error("array value must be skipped, not present")
	}
	if _, ok := c["nullish"]; ok {
		t.Error("null value must be skipped, not present")
	}
	if _, ok := c["obj"]; ok {
		t.Error("object value must be skipped, not present")
	}
}

func TestLTIClaims_FullUnmarshal_NumericCustomValue_NoError(t *testing.T) {
	payload := `{
		"iss": "https://platform.example.com",
		"https://purl.imsglobal.org/spec/lti/claim/custom": {"points": 5, "flag": true, "name": "x"}
	}`
	var c LTIClaims
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("unmarshal must not fail on numeric/boolean custom values: %v", err)
	}
	if c.Custom["points"] != "5" || c.Custom["flag"] != "true" || c.Custom["name"] != "x" {
		t.Errorf("Custom = %v", c.Custom)
	}
}

// Task 1.6: launch_presentation height/width accept a JSON number or a
// numeric string; an unparsable string decodes as 0, not an error.
func TestLaunchPresentation_HeightWidth_AcceptsNumberOrString(t *testing.T) {
	payload := `{"height": "800", "width": 600}`
	var lp LaunchPresentation
	if err := json.Unmarshal([]byte(payload), &lp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if lp.Height != 800 {
		t.Errorf("Height = %v, want 800", lp.Height)
	}
	if lp.Width != 600 {
		t.Errorf("Width = %v, want 600", lp.Width)
	}
}

func TestLaunchPresentation_UnparsableHeightString_DecodesAsZero(t *testing.T) {
	payload := `{"height": "not-a-number"}`
	var lp LaunchPresentation
	if err := json.Unmarshal([]byte(payload), &lp); err != nil {
		t.Fatalf("unmarshal must not error on an unparsable numeric string: %v", err)
	}
	if lp.Height != 0 {
		t.Errorf("Height = %v, want 0", lp.Height)
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
