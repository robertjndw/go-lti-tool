package deeplink

// Resource represents a content item selected by the tool during a deep linking flow.
type Resource struct {
	// Type is the content item type. Use the DeepLinkType* constants.
	Type string `json:"type"`

	// Title is the human-readable label for this resource.
	Title string `json:"title,omitempty"`

	// Text is a plain-text description.
	Text string `json:"text,omitempty"`

	// URL is the resource endpoint (for ltiResourceLink this is the launch URL).
	URL string `json:"url,omitempty"`

	// Custom contains tool-defined key-value parameters.
	Custom map[string]string `json:"custom,omitempty"`

	// LineItem configures a gradebook column for this resource (ltiResourceLink only).
	LineItem *LineItemProperty `json:"lineItem,omitempty"`

	// Presentation controls how the resource is displayed.
	//
	// Deprecated: this is an LTI 1.x-era shape not present in the DL 2.0
	// schema. Use Iframe, Window, and Embed instead. Retained for backward
	// compatibility; will be removed in the next major version.
	Presentation *Presentation `json:"presentation,omitempty"`

	// Icon is an icon for the resource.
	Icon *ImageObject `json:"icon,omitempty"`

	// Thumbnail is a thumbnail image for the resource.
	Thumbnail *ImageObject `json:"thumbnail,omitempty"`

	// Window is included for window target resources (link, ltiResourceLink).
	Window *WindowTarget `json:"window,omitempty"`

	// Iframe is included for iframe target resources (link, ltiResourceLink).
	Iframe *IframeTarget `json:"iframe,omitempty"`

	// HTML is the HTML fragment for "html" content items. Required for that type.
	HTML string `json:"html,omitempty"`

	// Embed supplies an HTML fragment platforms may embed in place of a link.
	// Only applicable to "link" content items.
	Embed *EmbedTarget `json:"embed,omitempty"`

	// MediaType is the content type of "file" content items.
	MediaType string `json:"mediaType,omitempty"`

	// Width is the top-level recommended pixel width, used by "image" content items.
	Width int `json:"width,omitempty"`

	// Height is the top-level recommended pixel height, used by "image" content items.
	Height int `json:"height,omitempty"`

	// Available bounds when an ltiResourceLink is available to learners.
	Available *TimeWindow `json:"available,omitempty"`

	// Submission bounds when an ltiResourceLink accepts submissions.
	Submission *TimeWindow `json:"submission,omitempty"`

	// ExpiresAt is the expiry datetime (ISO 8601) for "file" content items.
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// EmbedTarget supplies an HTML fragment platforms may embed in place of a link.
type EmbedTarget struct {
	HTML string `json:"html"`
}

// TimeWindow bounds when a resource is available or accepts submissions (ISO 8601).
type TimeWindow struct {
	StartDateTime string `json:"startDateTime,omitempty"`
	EndDateTime   string `json:"endDateTime,omitempty"`
}

// LineItemProperty configures a gradebook column associated with the resource.
type LineItemProperty struct {
	// Label is the line item display name.
	Label string `json:"label,omitempty"`

	// ScoreMaximum is the maximum possible score.
	ScoreMaximum float64 `json:"scoreMaximum"`

	// ResourceID is a tool-defined identifier.
	ResourceID string `json:"resourceId,omitempty"`

	// Tag is an optional tag.
	Tag string `json:"tag,omitempty"`

	// GradesReleased, when true, makes grades visible to learners. Nil means
	// the platform default; use deeplink.Bool so an explicit false survives
	// serialization (a plain bool with omitempty cannot distinguish absent
	// from false).
	GradesReleased *bool `json:"gradesReleased,omitempty"`
}

// Bool returns a pointer to v, for filling optional fields such as
// LineItemProperty.GradesReleased inline: deeplink.LineItemProperty{
// GradesReleased: deeplink.Bool(false), ...}.
func Bool(v bool) *bool { return &v }

// String returns a pointer to v, for filling optional string fields that
// distinguish "absent" from an explicit empty value, such as
// lti.DeepLinkingSettings.Data: deeplink.New(reg, deploymentID,
// &lti.DeepLinkingSettings{Data: deeplink.String(""), ...}).
func String(v string) *string { return &v }

// Presentation controls how the resource content is rendered.
type Presentation struct {
	// DocumentTarget specifies the rendering target (e.g. "iframe", "window").
	DocumentTarget string `json:"documentTarget,omitempty"`

	// Width is the recommended pixel width.
	Width int `json:"width,omitempty"`

	// Height is the recommended pixel height.
	Height int `json:"height,omitempty"`

	// Return URL is where the platform should send the user after the tool closes.
	ReturnURL string `json:"returnUrl,omitempty"`
}

// ImageObject represents an icon or thumbnail.
type ImageObject struct {
	// URL is the image source URL.
	URL string `json:"url"`
	// Width is the recommended pixel width of the image.
	Width int `json:"width,omitempty"`
	// Height is the recommended pixel height of the image.
	Height int `json:"height,omitempty"`
}

// WindowTarget specifies properties for a new browser window.
type WindowTarget struct {
	// TargetName is the window name (window.open target).
	TargetName string `json:"targetName,omitempty"`
	// Width is the recommended pixel width of the window.
	Width int `json:"width,omitempty"`
	// Height is the recommended pixel height of the window.
	Height int `json:"height,omitempty"`
	// WindowFeatures is the feature string passed to window.open.
	WindowFeatures string `json:"windowFeatures,omitempty"`
}

// IframeTarget specifies properties for an iframe.
type IframeTarget struct {
	// Src is the iframe's source URL. Required on "link" content items (the
	// link's own target); absent on "ltiResourceLink" items, whose iframe
	// derives its src from the launch URL instead.
	Src string `json:"src,omitempty"`
	// Width is the recommended pixel width of the iframe.
	Width int `json:"width,omitempty"`
	// Height is the recommended pixel height of the iframe.
	Height int `json:"height,omitempty"`
}

// NewLTIResourceLink creates a minimal ltiResourceLink content item.
func NewLTIResourceLink(title, launchURL string) Resource {
	return Resource{
		Type:  "ltiResourceLink",
		Title: title,
		URL:   launchURL,
	}
}

// NewLTIResourceLinkWithGrade creates an ltiResourceLink content item with a
// gradebook line item configured.
func NewLTIResourceLinkWithGrade(title, launchURL string, li LineItemProperty) Resource {
	r := NewLTIResourceLink(title, launchURL)
	r.LineItem = &li
	return r
}
