package deeplink_test

import (
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/deeplink"
)

// Each final DL 2.0 content-item type has its own schema. Presentation targets
// belong only to link/ltiResourceLink (embed only to link), while lineItem and
// availability windows belong only to ltiResourceLink.
func TestDeepLink_ContentItemPropertyApplicability(t *testing.T) {
	tests := []struct {
		name     string
		accept   string
		targets  []string
		resource deeplink.Resource
	}{
		{
			name: "file cannot set window", accept: lti.DeepLinkTypeFile,
			targets:  []string{lti.PresentationTargetWindow},
			resource: deeplink.Resource{Type: lti.DeepLinkTypeFile, URL: "https://tool.example.com/f.pdf", Window: &deeplink.WindowTarget{}},
		},
		{
			name: "html cannot set iframe", accept: lti.DeepLinkTypeHTML,
			targets:  []string{lti.PresentationTargetIframe},
			resource: deeplink.Resource{Type: lti.DeepLinkTypeHTML, HTML: "<p>x</p>", Iframe: &deeplink.IframeTarget{Src: "https://tool.example.com/x"}},
		},
		{
			name: "image cannot set embed", accept: lti.DeepLinkTypeImage,
			targets:  []string{lti.PresentationTargetEmbed},
			resource: deeplink.Resource{Type: lti.DeepLinkTypeImage, URL: "https://tool.example.com/i.png", Embed: &deeplink.EmbedTarget{HTML: "<img>"}},
		},
		{
			name: "link cannot set lineItem", accept: lti.DeepLinkTypeLink,
			resource: deeplink.Resource{Type: lti.DeepLinkTypeLink, URL: "https://tool.example.com/x", LineItem: &deeplink.LineItemProperty{ScoreMaximum: 10}},
		},
		{
			name: "link cannot set available", accept: lti.DeepLinkTypeLink,
			resource: deeplink.Resource{Type: lti.DeepLinkTypeLink, URL: "https://tool.example.com/x", Available: &deeplink.TimeWindow{StartDateTime: "2026-01-01T00:00:00Z"}},
		},
		{
			name: "image cannot set expiresAt", accept: lti.DeepLinkTypeImage,
			resource: deeplink.Resource{Type: lti.DeepLinkTypeImage, URL: "https://tool.example.com/i.png", ExpiresAt: "2026-01-01T00:00:00Z"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := defaultSettings([]string{tt.accept}, tt.targets)
			builder := newFlexibleBuilder(t, settings)
			if _, err := builder.ResponseJWT([]deeplink.Resource{tt.resource}); err == nil {
				t.Error("expected content item to be rejected by its DL 2.0 type schema")
			}
		})
	}
}

// URL-valued properties in the DL schemas are fully qualified URLs, not merely
// non-empty strings.
func TestDeepLink_RequiresFullyQualifiedURLs(t *testing.T) {
	tests := []struct {
		name     string
		resource deeplink.Resource
	}{
		{
			name:     "resource URL",
			resource: deeplink.Resource{Type: lti.DeepLinkTypeLink, URL: "/relative"},
		},
		{
			name:     "iframe src",
			resource: deeplink.Resource{Type: lti.DeepLinkTypeLink, URL: "https://tool.example.com/x", Iframe: &deeplink.IframeTarget{Src: "/relative"}},
		},
		{
			name:     "icon URL",
			resource: deeplink.Resource{Type: lti.DeepLinkTypeLink, URL: "https://tool.example.com/x", Icon: &deeplink.ImageObject{}},
		},
		{
			name:     "thumbnail URL",
			resource: deeplink.Resource{Type: lti.DeepLinkTypeLink, URL: "https://tool.example.com/x", Thumbnail: &deeplink.ImageObject{URL: "thumb.png"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets := []string(nil)
			if tt.resource.Iframe != nil {
				targets = []string{lti.PresentationTargetIframe}
			}
			builder := newFlexibleBuilder(t, defaultSettings([]string{lti.DeepLinkTypeLink}, targets))
			if _, err := builder.ResponseJWT([]deeplink.Resource{tt.resource}); err == nil {
				t.Error("expected non-fully-qualified URL to be rejected")
			}
		})
	}
}

// lineItem.scoreMaximum is required and strictly positive when a Deep Linking
// response asks the platform to create a gradebook column.
func TestDeepLink_LineItemScoreMaximumMustBePositive(t *testing.T) {
	settings := defaultSettings([]string{lti.DeepLinkTypeLTIResourceLink}, nil)
	settings.AcceptLineItem = deeplink.Bool(true)
	builder := newFlexibleBuilder(t, settings)
	resource := deeplink.Resource{
		Type:     lti.DeepLinkTypeLTIResourceLink,
		LineItem: &deeplink.LineItemProperty{Label: "Quiz", ScoreMaximum: 0},
	}
	if _, err := builder.ResponseJWT([]deeplink.Resource{resource}); err == nil {
		t.Error("expected non-positive lineItem.scoreMaximum to be rejected")
	}
}

// Dates in available/submission/expiresAt are ISO 8601 values. Invalid values
// should be caught before the platform receives an opaque schema error.
func TestDeepLink_DateTimePropertiesRequireISO8601(t *testing.T) {
	tests := map[string]deeplink.Resource{
		"available": {
			Type:      lti.DeepLinkTypeLTIResourceLink,
			Available: &deeplink.TimeWindow{StartDateTime: "next Tuesday"},
		},
		"submission": {
			Type:       lti.DeepLinkTypeLTIResourceLink,
			Submission: &deeplink.TimeWindow{EndDateTime: "not-a-date"},
		},
		"expiresAt": {
			Type: lti.DeepLinkTypeFile, URL: "https://tool.example.com/f.pdf", ExpiresAt: "tomorrow",
		},
	}
	for name, resource := range tests {
		t.Run(name, func(t *testing.T) {
			builder := newFlexibleBuilder(t, defaultSettings([]string{resource.Type}, nil))
			if _, err := builder.ResponseJWT([]deeplink.Resource{resource}); err == nil {
				t.Error("expected invalid ISO 8601 value to be rejected")
			}
		})
	}
}

// Extension types are open, but DL 2.0 requires their type identifier to be a
// fully qualified URL to avoid collisions with standard and vendor types.
func TestDeepLink_CustomTypeMustBeFullyQualifiedURL(t *testing.T) {
	const customType = "vendorQuiz"
	builder := newFlexibleBuilder(t, defaultSettings([]string{customType}, nil))
	if _, err := builder.ResponseJWT([]deeplink.Resource{{Type: customType}}); err == nil {
		t.Error("expected a non-URL custom content item type to be rejected")
	}
}

// The response form posts directly to deep_link_return_url, so the builder
// must enforce the same fully-qualified HTTPS URL constraint as launch
// validation even when callers construct a Builder directly.
func TestDeepLink_ResponseFormRejectsInvalidReturnURL(t *testing.T) {
	for name, returnURL := range map[string]string{
		"relative":     "/deep-links/return",
		"missing host": "https:///deep-links/return",
		"non-HTTPS":    "http://platform.example.com/deep-links/return",
	} {
		t.Run(name, func(t *testing.T) {
			settings := defaultSettings([]string{lti.DeepLinkTypeLTIResourceLink}, nil)
			settings.DeepLinkReturnURL = returnURL
			builder := newFlexibleBuilder(t, settings)
			if _, err := builder.ResponseFormHTML(nil); err == nil {
				t.Errorf("expected invalid deep_link_return_url %q to be rejected", returnURL)
			}
		})
	}
}
