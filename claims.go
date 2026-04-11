package lti

import "encoding/json"

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
	Custom map[string]string `json:"https://purl.imsglobal.org/spec/lti/claim/custom,omitempty"`

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

// ContextClaim holds course/section context information.
type ContextClaim struct {
	ID    string   `json:"id"`
	Label string   `json:"label,omitempty"`
	Title string   `json:"title,omitempty"`
	Type  []string `json:"type,omitempty"`
}

// LISClaim holds Learning Information Services identifiers.
type LISClaim struct {
	PersonSourcedID          string `json:"person_sourcedid,omitempty"`
	CourseOfferingSourcedID  string `json:"course_offering_sourcedid,omitempty"`
	CourseSectionSourcedID   string `json:"course_section_sourcedid,omitempty"`
}

// LaunchPresentation holds display hints from the platform.
type LaunchPresentation struct {
	DocumentTarget string  `json:"document_target,omitempty"`
	Height         float64 `json:"height,omitempty"`
	Width          float64 `json:"width,omitempty"`
	ReturnURL      string  `json:"return_url,omitempty"`
	Locale         string  `json:"locale,omitempty"`
}

// ToolPlatform holds platform product information.
type ToolPlatform struct {
	GUID            string `json:"guid,omitempty"`
	Name            string `json:"name,omitempty"`
	Version         string `json:"version,omitempty"`
	ProductFamilyCode string `json:"product_family_code,omitempty"`
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
	ContextMembershipsURL string   `json:"context_memberships_url"`
	ServiceVersions       []string `json:"service_versions,omitempty"`
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
	Data                              string   `json:"data,omitempty"`
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
