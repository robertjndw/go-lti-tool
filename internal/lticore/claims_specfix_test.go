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
