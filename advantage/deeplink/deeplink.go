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
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/internal/randutil"
)

// Builder constructs LTI Deep Linking response JWTs and forms.
type Builder struct {
	reg          *lti.Registration
	deploymentID string
	settings     *lti.DeepLinkingSettings

	// Msg is an optional message the platform should show the user after a
	// successful content selection (dl claim "msg").
	Msg string
	// Log is an optional message for the platform's logs (dl claim "log").
	Log string
	// ErrorMsg is an optional error message shown to the user when the tool
	// could not fulfil the selection (dl claim "errormsg").
	ErrorMsg string
	// ErrorLog is an optional error message for the platform's logs (dl claim
	// "errorlog").
	ErrorLog string
}

// New creates a Builder from the given registration, deployment ID and deep linking settings.
func New(reg *lti.Registration, deploymentID string, settings *lti.DeepLinkingSettings) *Builder {
	return &Builder{
		reg:          reg,
		deploymentID: deploymentID,
		settings:     settings,
	}
}

// NewFromLaunch creates a Builder from a validated *lti.Launch.
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

// validateResources checks the selection against the platform's deep linking
// settings so an invalid response is caught before it is signed and POSTed
// (platforms reject such responses with opaque errors).
func (b *Builder) validateResources(resources []Resource) error {
	if len(resources) > 1 && !b.settings.AcceptMultiple {
		return fmt.Errorf("deeplink: platform does not accept multiple content items (%d given)", len(resources))
	}
	for i, r := range resources {
		if r.Type == "" {
			return fmt.Errorf("deeplink: resource %d has no type", i)
		}
		if !slices.Contains(b.settings.AcceptTypes, r.Type) {
			return fmt.Errorf("deeplink: resource %d type %q is not in the platform's accept_types %v", i, r.Type, b.settings.AcceptTypes)
		}
	}
	return nil
}

// ResponseJWT builds and signs an LtiDeepLinkingResponse JWT containing the
// selected content items.
func (b *Builder) ResponseJWT(resources []Resource) (string, error) {
	if err := b.validateResources(resources); err != nil {
		return "", err
	}
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
	if b.Msg != "" {
		claims[lti.ClaimPrefixDL+"msg"] = b.Msg
	}
	if b.Log != "" {
		claims[lti.ClaimPrefixDL+"log"] = b.Log
	}
	if b.ErrorMsg != "" {
		claims[lti.ClaimPrefixDL+"errormsg"] = b.ErrorMsg
	}
	if b.ErrorLog != "" {
		claims[lti.ClaimPrefixDL+"errorlog"] = b.ErrorLog
	}

	if b.reg.ToolPrivateKey == nil {
		return "", fmt.Errorf("deeplink: registration has no private key")
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
