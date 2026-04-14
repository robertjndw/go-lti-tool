// Package deeplink implements the LTI Advantage Deep Linking v2.0 response flow.
//
// During a deep link launch (LtiDeepLinkingRequest), the tool presents a content
// selector UI. When the user selects content, the tool builds a signed
// LtiDeepLinkingResponse JWT and POSTs it back to the platform via an HTML form.
//
// Usage:
//
//	builder, err := deeplink.NewFromLaunch(launchData)
//	resources := []deeplink.Resource{
//	    deeplink.NewLTIResourceLink("Quiz 1", "https://tool.example.com/quiz/1"),
//	}
//	html, err := builder.ResponseFormHTML(resources)
//	// write html to the response
package deeplink

import (
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/robertjndw/go-lti"
	"github.com/robertjndw/go-lti/internal/randutil"
)

// Builder constructs LTI Deep Linking response JWTs and forms.
type Builder struct {
	reg          *lti.Registration
	deploymentID string
	settings     *lti.DeepLinkingSettings
}

// New creates a Builder from the given registration, deployment ID and deep linking settings.
func New(reg *lti.Registration, deploymentID string, settings *lti.DeepLinkingSettings) *Builder {
	return &Builder{
		reg:          reg,
		deploymentID: deploymentID,
		settings:     settings,
	}
}

// NewFromLaunch creates a Builder from a validated LaunchData.
// Returns ErrDeepLinkingNotAvailable if the launch is not a deep linking request.
func NewFromLaunch(ld *lti.Launch) (*Builder, error) {
	if !ld.HasDeepLinking() {
		return nil, lti.ErrDeepLinkingNotAvailable
	}
	var deploymentID string
	if ld.Deployment != nil {
		deploymentID = ld.Deployment.DeploymentID
	}
	return New(ld.Registration, deploymentID, ld.Claims.DeepLinkingSettings), nil
}

// ResponseJWT builds and signs an LtiDeepLinkingResponse JWT containing the
// selected content items.
func (b *Builder) ResponseJWT(resources []Resource) (string, error) {
	nonce, err := randomNonce()
	if err != nil {
		return "", fmt.Errorf("deeplink: failed to generate nonce: %w", err)
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":                               b.reg.ClientID,
		"aud":                               b.reg.Issuer, // DL 2.0 §4.1: aud must be the platform's issuer
		"iat":                               now.Unix(),
		"exp":                               now.Add(600 * time.Second).Unix(),
		"nonce":                             nonce,
		lti.ClaimPrefix + "message_type":    lti.MessageTypeDeepLinkingResponse,
		lti.ClaimPrefix + "version":         lti.LTIVersion,
		lti.ClaimPrefix + "deployment_id":   b.deploymentID,
		lti.ClaimPrefixDL + "content_items": resources,
	}

	if b.settings.Data != "" {
		claims[lti.ClaimPrefixDL+"data"] = b.settings.Data
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = b.reg.KID

	signed, err := token.SignedString(b.reg.ToolPrivateKey)
	if err != nil {
		return "", fmt.Errorf("deeplink: failed to sign response JWT: %w", err)
	}
	return signed, nil
}

func randomNonce() (string, error) {
	return randutil.Token(16)
}

// formTmpl is the HTML auto-submit form template.
var formTmpl = template.Must(template.New("dl").Parse(`<!DOCTYPE html>
<html>
<head><title>Returning to platform...</title></head>
<body>
<form id="dlForm" action="{{.ReturnURL}}" method="POST">
  <input type="hidden" name="JWT" value="{{.JWT}}">
</form>
<script>document.getElementById('dlForm').submit();</script>
</body>
</html>`))

// ResponseFormHTML builds an LtiDeepLinkingResponse JWT and wraps it in an
// auto-submitting HTML form that POSTs it back to the platform.
func (b *Builder) ResponseFormHTML(resources []Resource) (string, error) {
	jwtStr, err := b.ResponseJWT(resources)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	if err := formTmpl.Execute(&sb, struct {
		ReturnURL string
		JWT       string
	}{
		ReturnURL: b.settings.DeepLinkReturnURL,
		JWT:       jwtStr,
	}); err != nil {
		return "", fmt.Errorf("deeplink: failed to render form: %w", err)
	}
	return sb.String(), nil
}
