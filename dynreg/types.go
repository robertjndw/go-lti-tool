package dynreg

// OpenIDConfiguration represents the OpenID Provider Configuration returned
// by a platform's well-known endpoint.
type OpenIDConfiguration struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	JWKSURL                                    string   `json:"jwks_uri"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	// ClaimsSupported lists the standard OIDC claims_supported metadata.
	// Not currently used to filter anything, but kept so a decode/re-encode
	// round trip does not silently discard normative discovery metadata.
	ClaimsSupported []string `json:"claims_supported,omitempty"`
	// AuthorizationServer, if set, is used as the aud claim in token-endpoint
	// client assertions instead of TokenEndpoint.
	AuthorizationServer      string             `json:"authorization_server,omitempty"`
	LTIPlatformConfiguration *LTIPlatformConfig `json:"https://purl.imsglobal.org/spec/lti-platform-configuration,omitempty"`
}

// LTIPlatformConfig holds the LTI-specific extension of the OpenID Provider
// Configuration.
type LTIPlatformConfig struct {
	ProductFamilyCode string            `json:"product_family_code,omitempty"`
	Version           string            `json:"version,omitempty"`
	MessagesSupported []PlatformMessage `json:"messages_supported,omitempty"`
	Variables         []string          `json:"variables,omitempty"`
}

// PlatformMessage describes a message type supported by the platform.
type PlatformMessage struct {
	Type       string   `json:"type"`
	Placements []string `json:"placements,omitempty"`
}

// ClientMetadata holds the client registration properties shared between the
// registration request, the registration response, and the RFC 7592 update
// payload (RFC 7591 §2 plus the LTI-specific tool configuration extension).
// Extracting it once keeps the three call shapes from drifting apart.
type ClientMetadata struct {
	ApplicationType         string         `json:"application_type,omitempty"`
	GrantTypes              []string       `json:"grant_types,omitempty"`
	ResponseTypes           []string       `json:"response_types,omitempty"`
	RedirectURIs            []string       `json:"redirect_uris,omitempty"`
	InitiateLoginURI        string         `json:"initiate_login_uri,omitempty"`
	ClientName              string         `json:"client_name,omitempty"`
	JWKSURL                 string         `json:"jwks_uri,omitempty"`
	TokenEndpointAuthMethod string         `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string         `json:"scope,omitempty"`
	LogoURI                 string         `json:"logo_uri,omitempty"`
	Contacts                []string       `json:"contacts,omitempty"`
	ClientURI               string         `json:"client_uri,omitempty"`
	TOSURI                  string         `json:"tos_uri,omitempty"`
	PolicyURI               string         `json:"policy_uri,omitempty"`
	LTIToolConfiguration    *LTIToolConfig `json:"https://purl.imsglobal.org/spec/lti-tool-configuration,omitempty"`
}

// ClientRegistrationRequest is the payload POSTed to the platform's
// registration endpoint.
type ClientRegistrationRequest struct {
	ClientMetadata
}

// LTIToolConfig is the LTI-specific tool configuration embedded in both the
// registration request and response.
type LTIToolConfig struct {
	Domain           string   `json:"domain"`
	SecondaryDomains []string `json:"secondary_domains,omitempty"`
	// DeploymentID is set by the platform in the response when it combines
	// registration and deployment creation into a single step.
	DeploymentID     string            `json:"deployment_id,omitempty"`
	TargetLinkURI    string            `json:"target_link_uri"`
	CustomParameters map[string]string `json:"custom_parameters,omitempty"`
	Description      string            `json:"description,omitempty"`
	// Claims lists the OIDC/LTI claims the tool requires (e.g. "sub", "email").
	Claims []string `json:"claims"`
	// Messages is a required array property: an otherwise valid tool with no
	// placement-specific messages (resource-link support may be implicit)
	// sends [] rather than omitting the property or sending null.
	Messages []ToolMessage `json:"messages"`
}

// ToolMessage describes one message type (placement) the tool supports.
type ToolMessage struct {
	Type             string            `json:"type"`
	TargetLinkURI    string            `json:"target_link_uri,omitempty"`
	Label            string            `json:"label,omitempty"`
	IconURI          string            `json:"icon_uri,omitempty"`
	CustomParameters map[string]string `json:"custom_parameters,omitempty"`
	Placements       []string          `json:"placements,omitempty"`
	Roles            []string          `json:"roles,omitempty"`
	// SupportedTypes and SupportedMediaTypes are DL 2.0-specific properties
	// for an LtiDeepLinkingRequest message: the content-item types and media
	// types the placement accepts.
	SupportedTypes      []string `json:"supported_types,omitempty"`
	SupportedMediaTypes []string `json:"supported_media_types,omitempty"`
}

// ClientRegistrationResponse is the response from the platform's registration
// endpoint. It mirrors the request, with platform-assigned values (client_id,
// possibly deployment_id) added.
type ClientRegistrationResponse struct {
	ClientID string `json:"client_id"`
	ClientMetadata
	// RegistrationClientURI and RegistrationAccessToken are present when the
	// platform supports subsequent GET/PUT of the registration record
	// (RFC 7592). Use them with ReadRegistration/UpdateRegistration.
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
}

// ClientRegistrationUpdate is the RFC 7592 §2.2 update payload: the client_id
// plus the full registered metadata. Build it from a ReadRegistration result,
// mutate, then send with UpdateRegistration — partial updates are not
// defined by the RFC. registration_access_token/registration_client_uri are
// deliberately absent: RFC 7592 §2.2 excludes them from the PUT body.
type ClientRegistrationUpdate struct {
	ClientID string `json:"client_id"`
	ClientMetadata
}
