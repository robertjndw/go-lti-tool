package lticore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
)

// computeSign independently reproduces the base_string + HMAC-SHA256 +
// base64 formula, using the same field order as the migration guide's
// worked example (oauth_consumer_key & deployment_id & iss & client_id &
// exp & nonce).
func computeSign(t *testing.T, oauthConsumerKey, deploymentID, iss, clientID string, exp int64, nonce, secret string) string {
	t.Helper()
	baseString := oauthConsumerKey + "&" + deploymentID + "&" + iss + "&" + clientID + "&" +
		strconv.FormatInt(exp, 10) + "&" + nonce
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(baseString))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// golden values from the migration guide's §6.2.2 worked example.
const (
	goldenConsumerKey = "179248902"
	goldenDeployment  = "689302"
	goldenIssuer      = "https://lmsvendor.com"
	goldenClientID    = "PM48OJSfGDTAzAo"
	goldenExp         = int64(1551290856)
	goldenNonce       = "172we8671fd8z"
	goldenSecret      = "my-lti11-secret"
)

func goldenClaims(t *testing.T, sign string) *LTIClaims {
	t.Helper()
	return &LTIClaims{
		Issuer:       goldenIssuer,
		Audience:     Audience{goldenClientID},
		DeploymentID: goldenDeployment,
		ExpiresAt:    goldenExp,
		Nonce:        goldenNonce,
		LTI11: &LTI11Claim{
			OAuthConsumerKey:     goldenConsumerKey,
			OAuthConsumerKeySign: sign,
		},
	}
}

func TestVerifyLTI11ConsumerKeySign_Valid(t *testing.T) {
	sign := computeSign(t, goldenConsumerKey, goldenDeployment, goldenIssuer, goldenClientID, goldenExp, goldenNonce, goldenSecret)
	claims := goldenClaims(t, sign)

	if err := VerifyLTI11ConsumerKeySign(claims, goldenClientID, goldenSecret); err != nil {
		t.Errorf("expected nil error for a valid signature, got %v", err)
	}
}

func TestVerifyLTI11ConsumerKeySign_WrongSecret(t *testing.T) {
	sign := computeSign(t, goldenConsumerKey, goldenDeployment, goldenIssuer, goldenClientID, goldenExp, goldenNonce, goldenSecret)
	claims := goldenClaims(t, sign)

	err := VerifyLTI11ConsumerKeySign(claims, goldenClientID, "wrong-secret")
	if !errors.Is(err, ErrLTI11SignInvalid) {
		t.Errorf("want ErrLTI11SignInvalid, got %v", err)
	}
}

func TestVerifyLTI11ConsumerKeySign_TamperedDeploymentID(t *testing.T) {
	sign := computeSign(t, goldenConsumerKey, goldenDeployment, goldenIssuer, goldenClientID, goldenExp, goldenNonce, goldenSecret)
	claims := goldenClaims(t, sign)
	claims.DeploymentID = "tampered-deploy"

	err := VerifyLTI11ConsumerKeySign(claims, goldenClientID, goldenSecret)
	if !errors.Is(err, ErrLTI11SignInvalid) {
		t.Errorf("want ErrLTI11SignInvalid for a tampered deployment_id, got %v", err)
	}
}

func TestVerifyLTI11ConsumerKeySign_ClaimMissing(t *testing.T) {
	claims := &LTIClaims{
		Issuer:       goldenIssuer,
		Audience:     Audience{goldenClientID},
		DeploymentID: goldenDeployment,
		ExpiresAt:    goldenExp,
		Nonce:        goldenNonce,
	}
	err := VerifyLTI11ConsumerKeySign(claims, goldenClientID, goldenSecret)
	if !errors.Is(err, ErrLTI11ClaimMissing) {
		t.Errorf("want ErrLTI11ClaimMissing when lti1p1 is absent, got %v", err)
	}

	claims.LTI11 = &LTI11Claim{OAuthConsumerKey: goldenConsumerKey} // no sign
	err = VerifyLTI11ConsumerKeySign(claims, goldenClientID, goldenSecret)
	if !errors.Is(err, ErrLTI11ClaimMissing) {
		t.Errorf("want ErrLTI11ClaimMissing when oauth_consumer_key_sign is empty, got %v", err)
	}
}

func TestVerifyLTI11ConsumerKeySign_ClientIDNotInAudience(t *testing.T) {
	sign := computeSign(t, goldenConsumerKey, goldenDeployment, goldenIssuer, goldenClientID, goldenExp, goldenNonce, goldenSecret)
	claims := goldenClaims(t, sign)

	err := VerifyLTI11ConsumerKeySign(claims, "some-other-client", goldenSecret)
	if err == nil {
		t.Error("expected an error when clientID is not an audience of the token")
	}
}

// New LTI11Claim fields (context_id, tool_consumer_instance_guid,
// resource_link_id) must round-trip.
func TestLTI11Claim_NewFields_RoundTrip(t *testing.T) {
	payload := `{
		"https://purl.imsglobal.org/spec/lti/claim/lti1p1": {
			"user_id": "legacy-42",
			"oauth_consumer_key": "key-1",
			"oauth_consumer_key_sign": "sig",
			"context_id": "ctx-legacy-1",
			"tool_consumer_instance_guid": "tci-guid-1",
			"resource_link_id": "rl-legacy-1"
		}
	}`
	var c LTIClaims
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.LTI11 == nil {
		t.Fatal("LTI11 is nil")
	}
	if c.LTI11.ContextID != "ctx-legacy-1" {
		t.Errorf("ContextID = %q", c.LTI11.ContextID)
	}
	if c.LTI11.ToolConsumerInstanceGUID != "tci-guid-1" {
		t.Errorf("ToolConsumerInstanceGUID = %q", c.LTI11.ToolConsumerInstanceGUID)
	}
	if c.LTI11.ResourceLinkID != "rl-legacy-1" {
		t.Errorf("ResourceLinkID = %q", c.LTI11.ResourceLinkID)
	}
}
