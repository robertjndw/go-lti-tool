package ags

// Lineitem represents a gradebook column (line item) in LTI AGS v2.
type Lineitem struct {
	// ID is the line item URL (assigned by the platform; omitted when creating).
	ID string `json:"id,omitempty"`

	// ScoreMaximum is the maximum possible score for this line item.
	ScoreMaximum float64 `json:"scoreMaximum"`

	// Label is the human-readable name of the line item (e.g. "Assignment 1").
	Label string `json:"label"`

	// ResourceID is an optional tool-defined identifier for the associated resource.
	ResourceID string `json:"resourceId,omitempty"`

	// Tag is an optional platform-agnostic tag for filtering.
	Tag string `json:"tag,omitempty"`

	// StartDateTime is the ISO 8601 datetime from which submissions are accepted.
	StartDateTime string `json:"startDateTime,omitempty"`

	// EndDateTime is the ISO 8601 deadline for submissions.
	EndDateTime string `json:"endDateTime,omitempty"`

	// ResourceLinkID scopes the line item to a specific resource link when present.
	ResourceLinkID string `json:"resourceLinkId,omitempty"`
}
