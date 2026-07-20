package dynreg_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/robertjndw/go-lti-tool/dynreg"
)

// Dynamic Registration 1.0 forbids a fragment in the
// openid_configuration URL. Fragments are client-side data and therefore
// cannot identify the discovery document fetched from the platform.
func TestRegister_OpenIDConfigurationURLWithFragmentRejected(t *testing.T) {
	srv := newPlatform(t, http.StatusOK)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()

	_, err := dynreg.Register(
		context.Background(),
		cfg,
		srv.URL+"/.well-known/openid-configuration#unexpected",
		"",
	)
	if !errors.Is(err, dynreg.ErrInvalidOpenIDConfigURL) {
		t.Errorf("want ErrInvalidOpenIDConfigURL, got %v", err)
	}
}

// Every endpoint advertised by discovery is a fully-qualified URL. Merely
// checking for an https scheme permits opaque values such as "https:token".
func TestRegister_DiscoveryEndpointsMustBeAbsoluteURLs(t *testing.T) {
	for name, mutate := range map[string]func(*dynreg.OpenIDConfiguration){
		"authorization_endpoint": func(cfg *dynreg.OpenIDConfiguration) {
			cfg.AuthorizationEndpoint = "https:authorize"
		},
		"registration_endpoint": func(cfg *dynreg.OpenIDConfiguration) {
			cfg.RegistrationEndpoint = "https:register"
		},
		"jwks_uri": func(cfg *dynreg.OpenIDConfiguration) {
			cfg.JWKSURL = "https:jwks"
		},
		"token_endpoint": func(cfg *dynreg.OpenIDConfiguration) {
			cfg.TokenEndpoint = "https:token"
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newCapturingPlatform(t, mutate, nil)
			cfg := minimalConfig(t)
			cfg.HTTPClient = srv.Client()
			_, err := dynreg.Register(
				context.Background(), cfg,
				srv.URL+"/.well-known/openid-configuration", "",
			)
			if !errors.Is(err, dynreg.ErrInvalidOpenIDConfigURL) {
				t.Errorf("want ErrInvalidOpenIDConfigURL, got %v", err)
			}
		})
	}
}

// The discovery issuer follows the Security Framework issuer profile: HTTPS,
// scheme and host present, with no query or fragment.
func TestRegister_DiscoveryIssuerRejectsQueryAndFragment(t *testing.T) {
	for name, suffix := range map[string]string{
		"query":    "?tenant=one",
		"fragment": "#tenant-one",
	} {
		t.Run(name, func(t *testing.T) {
			srv := newCapturingPlatform(t, func(cfg *dynreg.OpenIDConfiguration) {
				cfg.Issuer += suffix
			}, nil)
			cfg := minimalConfig(t)
			cfg.HTTPClient = srv.Client()
			_, err := dynreg.Register(
				context.Background(), cfg,
				srv.URL+"/.well-known/openid-configuration", "",
			)
			if !errors.Is(err, dynreg.ErrInvalidOpenIDConfigURL) {
				t.Errorf("want ErrInvalidOpenIDConfigURL, got %v", err)
			}
		})
	}
}

// claims_supported is required LTI platform discovery metadata. Keeping it in
// the public discovery type prevents a decode/re-encode cycle from silently
// discarding a normative field.
func TestOpenIDConfiguration_ClaimsSupportedRoundTrips(t *testing.T) {
	raw := []byte(`{
		"issuer":"https://platform.example.com",
		"claims_supported":["sub","email","name"]
	}`)
	var cfg dynreg.OpenIDConfiguration
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal discovery metadata: %v", err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal discovery metadata: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode round-trip output: %v", err)
	}
	claims, ok := got["claims_supported"].([]any)
	if !ok || len(claims) != 3 {
		t.Errorf("claims_supported was not preserved: %s", encoded)
	}
}

// DL 2.0 dynamic-registration messages can advertise the content-item types
// and media types supported by a placement. Those properties must survive a
// metadata round trip even though they are optional for any one message.
func TestToolMessage_DeepLinkCapabilitiesRoundTrip(t *testing.T) {
	raw := []byte(`{
		"type":"LtiDeepLinkingRequest",
		"target_link_uri":"https://tool.example.com/deep-link",
		"supported_types":["ltiResourceLink","link","file"],
		"supported_media_types":["image/*","application/pdf"]
	}`)
	var message dynreg.ToolMessage
	if err := json.Unmarshal(raw, &message); err != nil {
		t.Fatalf("unmarshal tool message: %v", err)
	}
	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatalf("marshal tool message: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode round-trip output: %v", err)
	}
	for _, property := range []string{"supported_types", "supported_media_types"} {
		values, ok := got[property].([]any)
		if !ok || len(values) == 0 {
			t.Errorf("%s was not preserved: %s", property, encoded)
		}
	}
}

// The LTI tool-configuration schema requires messages to be a JSON array.
// Resource-link support may be implicit, so an otherwise valid tool with no
// explicit message entries must send [] rather than omit the property.
func TestRegister_EmptyMessagesEncodedAsRequiredArray(t *testing.T) {
	var captured dynreg.ClientRegistrationRequest
	srv := newCapturingPlatform(t, nil, &captured)
	cfg := minimalConfig(t)
	cfg.HTTPClient = srv.Client()

	if _, err := dynreg.Register(
		context.Background(), cfg,
		srv.URL+"/.well-known/openid-configuration", "",
	); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if captured.LTIToolConfiguration == nil {
		t.Fatal("registration request omitted lti-tool-configuration")
	}
	if captured.LTIToolConfiguration.Messages == nil {
		t.Error("messages must be encoded as an empty array, not omitted or null")
	}
}

// Tool metadata has its own URL/domain profile: domain excludes a protocol,
// while every browser or message endpoint uses HTTPS.
func TestRegister_RejectsInvalidToolEndpointMetadata(t *testing.T) {
	tests := map[string]func(*dynreg.DynRegConfig){
		"domain contains protocol": func(cfg *dynreg.DynRegConfig) {
			cfg.ToolDomain = "https://tool.example.com"
		},
		"HTTP jwks_uri": func(cfg *dynreg.DynRegConfig) {
			cfg.JWKSURL = "http://tool.example.com/jwks"
		},
		"HTTP initiate_login_uri": func(cfg *dynreg.DynRegConfig) {
			cfg.InitiateLoginURL = "http://tool.example.com/login"
		},
		"HTTP redirect_uri": func(cfg *dynreg.DynRegConfig) {
			cfg.RedirectURIs = []string{"http://tool.example.com/launch"}
		},
		"HTTP target_link_uri": func(cfg *dynreg.DynRegConfig) {
			cfg.TargetLinkURL = "http://tool.example.com/launch"
		},
		"HTTP message target_link_uri": func(cfg *dynreg.DynRegConfig) {
			cfg.Messages = []dynreg.ToolMessage{{
				Type: "LtiDeepLinkingRequest", TargetLinkURI: "http://tool.example.com/deep-link",
			}}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			srv := newCapturingPlatform(t, nil, nil)
			cfg := minimalConfig(t)
			cfg.HTTPClient = srv.Client()
			mutate(&cfg)
			if _, err := dynreg.Register(
				context.Background(), cfg,
				srv.URL+"/.well-known/openid-configuration", "",
			); err == nil {
				t.Error("expected invalid tool metadata to be rejected")
			}
		})
	}
}
