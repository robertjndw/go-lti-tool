// Package dynreg implements the LTI Dynamic Registration flow (v1.0).
//
// The flow is browser-mediated: a platform opens the tool's registration
// endpoint in an iframe or new tab, the tool fetches the platform's OpenID
// Provider Configuration, POSTs a client registration request, and finally
// sends an org.imsglobal.lti.close postMessage to signal completion.
//
// Spec: https://www.imsglobal.org/spec/lti-dr/v1p0
package dynreg

// OpenIDConfiguration represents the OpenID Provider Configuration returned
// by a platform's well-known endpoint.
type OpenIDConfiguration struct {
	Issuer                                     string             `json:"issuer"`
	AuthorizationEndpoint                      string             `json:"authorization_endpoint"`
	RegistrationEndpoint                       string             `json:"registration_endpoint"`
	JWKSUri                                    string             `json:"jwks_uri"`
	TokenEndpoint                              string             `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string           `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string           `json:"token_endpoint_auth_signing_alg_values_supported"`
	ScopesSupported                            []string           `json:"scopes_supported"`
	ResponseTypesSupported                     []string           `json:"response_types_supported"`
	IDTokenSigningAlgValuesSupported           []string           `json:"id_token_signing_alg_values_supported"`
	SubjectTypesSupported                      []string           `json:"subject_types_supported"`
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

// ClientRegistrationRequest is the payload POSTed to the platform's
// registration endpoint.
type ClientRegistrationRequest struct {
	ApplicationType         string         `json:"application_type"`
	GrantTypes              []string       `json:"grant_types"`
	ResponseTypes           []string       `json:"response_types"`
	RedirectURIs            []string       `json:"redirect_uris"`
	InitiateLoginURI        string         `json:"initiate_login_uri"`
	ClientName              string         `json:"client_name"`
	JWKSUri                 string         `json:"jwks_uri"`
	TokenEndpointAuthMethod string         `json:"token_endpoint_auth_method"`
	Scope                   string         `json:"scope"`
	LogoURI                 string         `json:"logo_uri,omitempty"`
	Contacts                []string       `json:"contacts,omitempty"`
	ClientURI               string         `json:"client_uri,omitempty"`
	TOSURI                  string         `json:"tos_uri,omitempty"`
	PolicyURI               string         `json:"policy_uri,omitempty"`
	LTIToolConfiguration    *LTIToolConfig `json:"https://purl.imsglobal.org/spec/lti-tool-configuration"`
}

// LTIToolConfig is the LTI-specific tool configuration embedded in both the
// registration request and response.
type LTIToolConfig struct {
	Domain           string            `json:"domain"`
	SecondaryDomains []string          `json:"secondary_domains,omitempty"`
	// DeploymentID is set by the platform in the response when it combines
	// registration and deployment creation into a single step.
	DeploymentID     string            `json:"deployment_id,omitempty"`
	TargetLinkURI    string            `json:"target_link_uri"`
	CustomParameters map[string]string `json:"custom_parameters,omitempty"`
	Description      string            `json:"description,omitempty"`
	// Claims lists the OIDC/LTI claims the tool requires (e.g. "sub", "email").
	Claims           []string          `json:"claims"`
	Messages         []ToolMessage     `json:"messages,omitempty"`
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
}

// ClientRegistrationResponse is the response from the platform's registration
// endpoint. It mirrors the request, with platform-assigned values (client_id,
// possibly deployment_id) added.
type ClientRegistrationResponse struct {
	ClientID                string         `json:"client_id"`
	ApplicationType         string         `json:"application_type"`
	GrantTypes              []string       `json:"grant_types"`
	ResponseTypes           []string       `json:"response_types"`
	RedirectURIs            []string       `json:"redirect_uris"`
	InitiateLoginURI        string         `json:"initiate_login_uri"`
	ClientName              string         `json:"client_name"`
	JWKSUri                 string         `json:"jwks_uri"`
	TokenEndpointAuthMethod string         `json:"token_endpoint_auth_method"`
	Scope                   string         `json:"scope"`
	// RegistrationClientURI and RegistrationAccessToken are present when the
	// platform supports subsequent GET/PUT of the registration record.
	RegistrationClientURI   string         `json:"registration_client_uri,omitempty"`
	RegistrationAccessToken string         `json:"registration_access_token,omitempty"`
	LTIToolConfiguration    *LTIToolConfig `json:"https://purl.imsglobal.org/spec/lti-tool-configuration,omitempty"`
}
