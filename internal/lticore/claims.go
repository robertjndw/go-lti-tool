package lticore

import (
	"encoding/json"
	"strconv"
)

// LTIClaims is the fully-parsed body of a validated LTI launch JWT.
// Standard OIDC fields sit alongside LTI-namespaced claims.
type LTIClaims struct {
	// Standard OIDC claims.
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	Nonce     string   `json:"nonce"`
	// Azp is the OIDC authorized party. Required when aud has multiple values.
	Azp string `json:"azp,omitempty"`

	// OpenID Connect profile claims (optional).
	Name       string `json:"name,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	MiddleName string `json:"middle_name,omitempty"`
	Email      string `json:"email,omitempty"`
	Picture    string `json:"picture,omitempty"`
	Locale     string `json:"locale,omitempty"`

	// LTI-required claims.
	MessageType   string   `json:"https://purl.imsglobal.org/spec/lti/claim/message_type"`
	Version       string   `json:"https://purl.imsglobal.org/spec/lti/claim/version"`
	DeploymentID  string   `json:"https://purl.imsglobal.org/spec/lti/claim/deployment_id"`
	TargetLinkURI string   `json:"https://purl.imsglobal.org/spec/lti/claim/target_link_uri"`
	Roles         []string `json:"https://purl.imsglobal.org/spec/lti/claim/roles"`

	// LTI resource link (required for LtiResourceLinkRequest).
	ResourceLink *ResourceLink `json:"https://purl.imsglobal.org/spec/lti/claim/resource_link,omitempty"`

	// Optional LTI context claim.
	Context *ContextClaim `json:"https://purl.imsglobal.org/spec/lti/claim/context,omitempty"`

	// Optional key-value custom parameters.
	Custom CustomParameters `json:"https://purl.imsglobal.org/spec/lti/claim/custom,omitempty"`

	// RoleScopeMentor lists the user IDs a Mentor-role user may access.
	RoleScopeMentor []string `json:"https://purl.imsglobal.org/spec/lti/claim/role_scope_mentor,omitempty"`

	// ForUser identifies the user a message is about (not the launching user).
	// Required in LtiSubmissionReviewRequest launches.
	ForUser *ForUserClaim `json:"https://purl.imsglobal.org/spec/lti/claim/for_user,omitempty"`

	// LTI11 carries LTI 1.1 migration identifiers when the platform migrated
	// this deployment from LTI 1.1 (LTI 1.3 migration guide).
	LTI11 *LTI11Claim `json:"https://purl.imsglobal.org/spec/lti/claim/lti1p1,omitempty"`

	// Optional LIS (Learning Information Services) identifiers.
	LIS *LISClaim `json:"https://purl.imsglobal.org/spec/lti/claim/lis,omitempty"`

	// Optional launch presentation hints.
	LaunchPresentation *LaunchPresentation `json:"https://purl.imsglobal.org/spec/lti/claim/launch_presentation,omitempty"`

	// Optional tool platform info.
	ToolPlatform *ToolPlatform `json:"https://purl.imsglobal.org/spec/lti/claim/tool_platform,omitempty"`

	// LTI Advantage: AGS endpoint claim.
	AGS *AGSClaim `json:"https://purl.imsglobal.org/spec/lti-ags/claim/endpoint,omitempty"`

	// LTI Advantage: NRPS endpoint claim.
	NRPS *NRPSClaim `json:"https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice,omitempty"`

	// LTI Advantage: Deep Linking settings (present in LtiDeepLinkingRequest).
	DeepLinkingSettings *DeepLinkingSettings `json:"https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings,omitempty"`
}

// ResourceLink represents a placed resource on the platform.
type ResourceLink struct {
	ID          string `json:"id"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

// ForUserClaim identifies the user that a launch message concerns, e.g. the
// student whose submission an instructor is reviewing.
type ForUserClaim struct {
	UserID          string   `json:"user_id"`
	PersonSourcedID string   `json:"person_sourcedid,omitempty"`
	Name            string   `json:"name,omitempty"`
	GivenName       string   `json:"given_name,omitempty"`
	FamilyName      string   `json:"family_name,omitempty"`
	Email           string   `json:"email,omitempty"`
	Roles           []string `json:"roles,omitempty"`
}

// LTI11Claim holds LTI 1.1 → 1.3 migration identifiers.
type LTI11Claim struct {
	UserID               string `json:"user_id,omitempty"`
	OAuthConsumerKey     string `json:"oauth_consumer_key,omitempty"`
	OAuthConsumerKeySign string `json:"oauth_consumer_key_sign,omitempty"`
	// ContextID is the launch's LTI 1.1 context_id, present when it differs
	// from the LTI 1.3 context.id (migration guide §6.1).
	ContextID string `json:"context_id,omitempty"`
	// ToolConsumerInstanceGUID is the LTI 1.1 tool_consumer_instance_guid.
	ToolConsumerInstanceGUID string `json:"tool_consumer_instance_guid,omitempty"`
	// ResourceLinkID is the LTI 1.1 resource_link_id, present when it differs
	// from the LTI 1.3 resource_link.id.
	ResourceLinkID string `json:"resource_link_id,omitempty"`
}

// ContextClaim holds course/section context information.
type ContextClaim struct {
	ID    string   `json:"id"`
	Label string   `json:"label,omitempty"`
	Title string   `json:"title,omitempty"`
	Type  []string `json:"type,omitempty"`
}

// LISClaim holds Learning Information Services identifiers.
type LISClaim struct {
	PersonSourcedID         string `json:"person_sourcedid,omitempty"`
	CourseOfferingSourcedID string `json:"course_offering_sourcedid,omitempty"`
	CourseSectionSourcedID  string `json:"course_section_sourcedid,omitempty"`
}

// LaunchPresentation holds display hints from the platform.
type LaunchPresentation struct {
	DocumentTarget string  `json:"document_target,omitempty"`
	Height         float64 `json:"height,omitempty"`
	Width          float64 `json:"width,omitempty"`
	ReturnURL      string  `json:"return_url,omitempty"`
	Locale         string  `json:"locale,omitempty"`
}

// UnmarshalJSON tolerates platforms that send height/width as numeric
// strings instead of numbers (a schema violation, but one that shouldn't
// fail the whole launch). An unparsable string decodes as 0, not an error.
func (lp *LaunchPresentation) UnmarshalJSON(data []byte) error {
	type shadow LaunchPresentation
	aux := &struct {
		Height json.RawMessage `json:"height,omitempty"`
		Width  json.RawMessage `json:"width,omitempty"`
		*shadow
	}{shadow: (*shadow)(lp)}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	lp.Height = parseNumericOrString(aux.Height)
	lp.Width = parseNumericOrString(aux.Width)
	return nil
}

// parseNumericOrString decodes raw as a JSON number or, failing that, a
// numeric string. Absent or unparsable input yields 0.
func parseNumericOrString(raw json.RawMessage) float64 {
	if len(raw) == 0 {
		return 0
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return f
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			return v
		}
	}
	return 0
}

// ToolPlatform holds platform product information.
type ToolPlatform struct {
	GUID              string `json:"guid,omitempty"`
	Name              string `json:"name,omitempty"`
	Version           string `json:"version,omitempty"`
	ProductFamilyCode string `json:"product_family_code,omitempty"`
	URL               string `json:"url,omitempty"`
	Description       string `json:"description,omitempty"`
	ContactEmail      string `json:"contact_email,omitempty"`
}

// AGSClaim is the LTI Advantage Assignment & Grade Services endpoint descriptor.
type AGSClaim struct {
	// Scope lists the AGS scopes the platform has granted.
	Scope []string `json:"scope"`
	// Lineitems is the gradebook container URL (present when the platform supports multiple line items).
	Lineitems string `json:"lineitems,omitempty"`
	// Lineitem is the URL for the single line item associated with the resource link (may be absent).
	Lineitem string `json:"lineitem,omitempty"`
}

// NRPSClaim is the LTI Advantage Names & Role Provisioning Services endpoint descriptor.
type NRPSClaim struct {
	// ContextMembershipsURL is the endpoint for fetching course roster membership data.
	ContextMembershipsURL string `json:"context_memberships_url"`
	// ServiceVersions lists the NRPS specification versions supported by the platform.
	ServiceVersions []string `json:"service_versions,omitempty"`
}

// DeepLinkingSettings is present in LtiDeepLinkingRequest launches.
type DeepLinkingSettings struct {
	DeepLinkReturnURL                 string   `json:"deep_link_return_url"`
	AcceptTypes                       []string `json:"accept_types"`
	AcceptPresentationDocumentTargets []string `json:"accept_presentation_document_targets"`
	AcceptMediaTypes                  string   `json:"accept_media_types,omitempty"`
	AcceptMultiple                    bool     `json:"accept_multiple,omitempty"`
	AutoCreate                        bool     `json:"auto_create,omitempty"`
	Title                             string   `json:"title,omitempty"`
	Text                              string   `json:"text,omitempty"`
	// Data is an opaque value the tool must echo back unmodified in its
	// response when present (DL 2.0 §5.1). A *string distinguishes an absent
	// data property (nil, nothing to echo) from an explicit empty string
	// (non-nil, must still be echoed) — a plain string cannot represent that
	// distinction once decoded.
	Data *string `json:"data,omitempty"`
	// AcceptLineItem indicates whether the platform supports a lineItem on an
	// ltiResourceLink content item. Nil means no assumption can be made
	// (added to the DL 2.0 schema in 2023); false means line items will be
	// ignored; true means the platform will create one.
	AcceptLineItem *bool `json:"accept_lineitem,omitempty"`
}

// CustomParameters is a map of custom launch parameters. The LTI spec
// requires string values; the UnmarshalJSON below tolerates platforms that
// send numbers or booleans by coercing them to strings, since failing the
// whole launch punishes the user for a platform-side spec violation, not the
// platform. null/array/object values are skipped rather than erroring.
type CustomParameters map[string]string

// UnmarshalJSON coerces numeric and boolean values to strings; null, array,
// and object values are skipped (the key is dropped, not an error).
func (c *CustomParameters) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	out := make(CustomParameters, len(raw))
	for k, v := range raw {
		switch val := v.(type) {
		case string:
			out[k] = val
		case float64:
			out[k] = strconv.FormatFloat(val, 'f', -1, 64)
		case bool:
			out[k] = strconv.FormatBool(val)
		default:
			// null, array, object: skip key, never error.
		}
	}
	*c = out
	return nil
}

// Audience handles the JWT "aud" claim which may be a single string or an array of strings.
type Audience []string

// Contains returns true if the audience contains the given value.
func (a Audience) Contains(v string) bool {
	for _, s := range a {
		if s == v {
			return true //nolint:slicescontains // slices pkg not available in older toolchains
		}
	}
	return false
}

// UnmarshalJSON handles both "aud":"single" and "aud":["a","b"] forms.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return err
	}
	*a = Audience(multiple)
	return nil
}

// MarshalJSON serialises as an array to stay consistent.
func (a Audience) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(a))
}
