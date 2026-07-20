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
	"net/url"
	"regexp"
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

// contentItemSchema describes, for each standard DL 2.0 content item type,
// which optional properties its schema defines. A type absent from this map
// is a custom/extension type, which skips all of these applicability checks
// (extensibility) but must use a fully-qualified URL as its type identifier
// (validateTypeRequiredFields) to avoid collisions with standard/vendor types.
type contentItemSchemaEntry struct {
	window, iframe, embed bool // presentation target applicability
	lineItem              bool // lineItem property applicability
	availability          bool // available/submission property applicability
	expiresAt             bool // expiresAt property applicability
}

var contentItemSchema = map[string]contentItemSchemaEntry{
	lti.DeepLinkTypeLink:            {window: true, iframe: true, embed: true},
	lti.DeepLinkTypeLTIResourceLink: {window: true, iframe: true, embed: false, lineItem: true, availability: true},
	lti.DeepLinkTypeFile:            {expiresAt: true},
	lti.DeepLinkTypeHTML:            {},
	lti.DeepLinkTypeImage:           {},
}

// validateResources checks the selection against the platform's deep linking
// settings so an invalid response is caught before it is signed and POSTed
// (platforms reject such responses with opaque errors). Unknown/custom
// content item types skip the type-specific checks below (extensibility).
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
		if err := b.validateDocumentTargets(i, r); err != nil {
			return err
		}
		if err := b.validateMediaType(i, r); err != nil {
			return err
		}
		if err := validateTypeRequiredFields(i, r); err != nil {
			return err
		}
		if err := validateResourceURLs(i, r); err != nil {
			return err
		}
		if err := validateResourceDateTimes(i, r); err != nil {
			return err
		}
		if schema, known := contentItemSchema[r.Type]; known {
			if r.LineItem != nil && !schema.lineItem {
				return fmt.Errorf("deeplink: resource %d type %q does not support lineItem", i, r.Type)
			}
			if (r.Available != nil || r.Submission != nil) && !schema.availability {
				return fmt.Errorf("deeplink: resource %d type %q does not support available/submission", i, r.Type)
			}
			if r.ExpiresAt != "" && !schema.expiresAt {
				return fmt.Errorf("deeplink: resource %d type %q does not support expiresAt", i, r.Type)
			}
		}
		if r.LineItem != nil && r.LineItem.ScoreMaximum <= 0 {
			return fmt.Errorf("deeplink: resource %d lineItem.scoreMaximum must be a positive number", i)
		}
		if r.LineItem != nil && b.settings.AcceptLineItem != nil && !*b.settings.AcceptLineItem {
			return fmt.Errorf("deeplink: resource %d sets lineItem but the platform's deep_linking_settings sent accept_lineitem: false", i)
		}
	}
	return nil
}

// validateDocumentTargets enforces target parity (a resource may only set
// Window/Iframe/Embed when the platform accepted that document target) and
// type applicability (only content item types the DL 2.0 schema defines
// window/iframe/embed for may set them).
func (b *Builder) validateDocumentTargets(i int, r Resource) error {
	applicability, known := contentItemSchema[r.Type]
	if r.Window != nil {
		if known && !applicability.window {
			return fmt.Errorf("deeplink: resource %d type %q does not support the window target", i, r.Type)
		}
		if !slices.Contains(b.settings.AcceptPresentationDocumentTargets, lti.PresentationTargetWindow) {
			return fmt.Errorf("deeplink: resource %d sets window but the platform's accept_presentation_document_targets %v does not include %q", i, b.settings.AcceptPresentationDocumentTargets, lti.PresentationTargetWindow)
		}
	}
	if r.Iframe != nil {
		if known && !applicability.iframe {
			return fmt.Errorf("deeplink: resource %d type %q does not support the iframe target", i, r.Type)
		}
		if !slices.Contains(b.settings.AcceptPresentationDocumentTargets, lti.PresentationTargetIframe) {
			return fmt.Errorf("deeplink: resource %d sets iframe but the platform's accept_presentation_document_targets %v does not include %q", i, b.settings.AcceptPresentationDocumentTargets, lti.PresentationTargetIframe)
		}
	}
	if r.Embed != nil {
		if known && !applicability.embed {
			return fmt.Errorf("deeplink: resource %d type %q does not support the embed target", i, r.Type)
		}
		if !slices.Contains(b.settings.AcceptPresentationDocumentTargets, lti.PresentationTargetEmbed) {
			return fmt.Errorf("deeplink: resource %d sets embed but the platform's accept_presentation_document_targets %v does not include %q", i, b.settings.AcceptPresentationDocumentTargets, lti.PresentationTargetEmbed)
		}
	}
	return nil
}

// isFullyQualifiedURL reports whether s is an absolute URL with a host, as
// required by every URL-valued property in the DL 2.0 content item schemas.
func isFullyQualifiedURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.IsAbs() && u.Host != ""
}

// validateResourceURLs enforces that URL-valued properties are fully
// qualified URLs, not merely non-empty strings, and that custom/extension
// content item types use a fully-qualified URL as their type identifier (DL
// 2.0 requires this to avoid collisions with standard and vendor types).
func validateResourceURLs(i int, r Resource) error {
	if _, known := contentItemSchema[r.Type]; !known && !isFullyQualifiedURL(r.Type) {
		return fmt.Errorf("deeplink: resource %d custom type %q must be a fully qualified URL", i, r.Type)
	}
	if r.URL != "" && !isFullyQualifiedURL(r.URL) {
		return fmt.Errorf("deeplink: resource %d url %q must be a fully qualified URL", i, r.URL)
	}
	if r.Iframe != nil && r.Iframe.Src != "" && !isFullyQualifiedURL(r.Iframe.Src) {
		return fmt.Errorf("deeplink: resource %d iframe.src %q must be a fully qualified URL", i, r.Iframe.Src)
	}
	if r.Icon != nil && !isFullyQualifiedURL(r.Icon.URL) {
		return fmt.Errorf("deeplink: resource %d icon.url %q must be a fully qualified URL", i, r.Icon.URL)
	}
	if r.Thumbnail != nil && !isFullyQualifiedURL(r.Thumbnail.URL) {
		return fmt.Errorf("deeplink: resource %d thumbnail.url %q must be a fully qualified URL", i, r.Thumbnail.URL)
	}
	return nil
}

// iso8601Pattern matches an ISO 8601 datetime with an optional
// fractional-seconds component and a Z or ±HH:MM UTC offset.
var iso8601Pattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)

// isValidISO8601 reports whether s is a well-formed ISO 8601 datetime.
func isValidISO8601(s string) bool {
	if !iso8601Pattern.MatchString(s) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

// validateResourceDateTimes enforces that available/submission/expiresAt
// datetimes are valid ISO 8601 values, catching a malformed date before the
// platform receives an opaque schema error.
func validateResourceDateTimes(i int, r Resource) error {
	checkWindow := func(field string, w *TimeWindow) error {
		if w == nil {
			return nil
		}
		if w.StartDateTime != "" && !isValidISO8601(w.StartDateTime) {
			return fmt.Errorf("deeplink: resource %d %s.startDateTime %q is not a valid ISO 8601 datetime", i, field, w.StartDateTime)
		}
		if w.EndDateTime != "" && !isValidISO8601(w.EndDateTime) {
			return fmt.Errorf("deeplink: resource %d %s.endDateTime %q is not a valid ISO 8601 datetime", i, field, w.EndDateTime)
		}
		return nil
	}
	if err := checkWindow("available", r.Available); err != nil {
		return err
	}
	if err := checkWindow("submission", r.Submission); err != nil {
		return err
	}
	if r.ExpiresAt != "" && !isValidISO8601(r.ExpiresAt) {
		return fmt.Errorf("deeplink: resource %d expiresAt %q is not a valid ISO 8601 datetime", i, r.ExpiresAt)
	}
	return nil
}

// validateMediaType enforces accept_media_types for "file" items: it only
// applies to that type per the DL 2.0 schema, and only when both the
// resource's MediaType and the platform's AcceptMediaTypes are set.
func (b *Builder) validateMediaType(i int, r Resource) error {
	if r.Type != lti.DeepLinkTypeFile || r.MediaType == "" || b.settings.AcceptMediaTypes == "" {
		return nil
	}
	for accepted := range strings.SplitSeq(b.settings.AcceptMediaTypes, ",") {
		accepted = strings.TrimSpace(accepted)
		if accepted == r.MediaType {
			return nil
		}
		if typ, _, ok := strings.Cut(accepted, "/*"); ok && strings.HasPrefix(r.MediaType, typ+"/") {
			return nil
		}
	}
	return fmt.Errorf("deeplink: resource %d mediaType %q does not match the platform's accept_media_types %q", i, r.MediaType, b.settings.AcceptMediaTypes)
}

// validateTypeRequiredFields enforces the type-specific required fields from
// the DL 2.0 content item schema. Unknown/custom types are skipped.
func validateTypeRequiredFields(i int, r Resource) error {
	switch r.Type {
	case lti.DeepLinkTypeLink, lti.DeepLinkTypeFile, lti.DeepLinkTypeImage:
		if r.URL == "" {
			return fmt.Errorf("deeplink: resource %d (type %q) requires a non-empty URL", i, r.Type)
		}
	case lti.DeepLinkTypeHTML:
		if r.HTML == "" {
			return fmt.Errorf("deeplink: resource %d (type %q) requires a non-empty HTML fragment", i, r.Type)
		}
	}
	if r.Embed != nil && r.Embed.HTML == "" {
		return fmt.Errorf("deeplink: resource %d embed target requires a non-empty HTML fragment", i)
	}
	if r.Type == lti.DeepLinkTypeLink && r.Iframe != nil && r.Iframe.Src == "" {
		return fmt.Errorf("deeplink: resource %d (type %q) iframe target requires a non-empty Src", i, r.Type)
	}
	return nil
}

// ResponseJWT builds and signs an LtiDeepLinkingResponse JWT containing the
// selected content items.
func (b *Builder) ResponseJWT(resources []Resource) (string, error) {
	if b.deploymentID == "" {
		return "", fmt.Errorf("deeplink: deployment ID is required to build a response JWT")
	}
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
