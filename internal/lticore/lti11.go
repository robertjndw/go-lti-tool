package lticore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// VerifyLTI11ConsumerKeySign checks the lti1p1 migration claim signature:
// base64(hmac_sha256("<oauth_consumer_key>&<deployment_id>&<iss>&<client_id>&<exp>&<nonce>", secret)).
// clientID must be the registration's client_id; it is verified to be an
// audience of the token before use, which removes the ambiguity a
// multi-audience token would otherwise create. Returns nil when the
// signature is valid.
//
// Confirmed against the LTI 1.1 migration guide §6.2.2: the base string
// concatenates oauth_consumer_key, deployment_id, iss, client_id (aud), exp,
// and nonce with "&", HMAC-SHA256 signed with the LTI 1.1 shared secret
// (UTF-8 bytes), and base64-encoded (RFC 4648, standard alphabet).
func VerifyLTI11ConsumerKeySign(claims *LTIClaims, clientID, oauthConsumerSecret string) error {
	if claims.LTI11 == nil || claims.LTI11.OAuthConsumerKey == "" || claims.LTI11.OAuthConsumerKeySign == "" {
		return ErrLTI11ClaimMissing
	}
	if !claims.Audience.Contains(clientID) {
		return fmt.Errorf("%w: clientID %q is not an audience of the token", ErrLTI11SignInvalid, clientID)
	}

	baseString := strings.Join([]string{
		claims.LTI11.OAuthConsumerKey,
		claims.DeploymentID,
		claims.Issuer,
		clientID,
		strconv.FormatInt(claims.ExpiresAt, 10),
		claims.Nonce,
	}, "&")

	mac := hmac.New(sha256.New, []byte(oauthConsumerSecret))
	mac.Write([]byte(baseString))
	computed := mac.Sum(nil)

	given, err := base64.StdEncoding.DecodeString(claims.LTI11.OAuthConsumerKeySign)
	if err != nil {
		return ErrLTI11SignInvalid
	}
	if !hmac.Equal(computed, given) {
		return ErrLTI11SignInvalid
	}
	return nil
}
