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

	// LineItem configures a gradebook column for this resource.
	LineItem *LineItemProperty `json:"lineItem,omitempty"`

	// Presentation controls how the resource is displayed.
	Presentation *Presentation `json:"presentation,omitempty"`

	// Icon is an icon for the resource.
	Icon *ImageObject `json:"icon,omitempty"`

	// Thumbnail is a thumbnail image for the resource.
	Thumbnail *ImageObject `json:"thumbnail,omitempty"`

	// Window is included for window target resources.
	Window *WindowTarget `json:"window,omitempty"`

	// Iframe is included for iframe target resources.
	Iframe *IframeTarget `json:"iframe,omitempty"`
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

	// GradesReleased, when true, makes grades visible to learners.
	GradesReleased bool `json:"gradesReleased,omitempty"`
}

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
	URL    string `json:"url"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
}

// WindowTarget specifies properties for a new browser window.
type WindowTarget struct {
	TargetName string `json:"targetName,omitempty"`
	Width      int    `json:"width,omitempty"`
	Height     int    `json:"height,omitempty"`
	WindowFeatures string `json:"windowFeatures,omitempty"`
}

// IframeTarget specifies properties for an iframe.
type IframeTarget struct {
	Width  int `json:"width,omitempty"`
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
