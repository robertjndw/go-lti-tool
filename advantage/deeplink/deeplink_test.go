package deeplink_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/deeplink"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
)

// newBuilder creates a Builder backed by a test registration and deep linking settings.
func newBuilder(t *testing.T) (*deeplink.Builder, *lti.Registration) {
	t.Helper()
	key := ltitest.NewKey(t)
	reg := &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-xyz",
		KeySetURL:      "https://platform.example.com/jwks",
		AuthLoginURL:   "https://platform.example.com/auth",
		AuthTokenURL:   "https://platform.example.com/token",
		ToolPrivateKey: key,
		KID:            "tool-key-1",
	}
	settings := &lti.DeepLinkingSettings{
		DeepLinkReturnURL:                 "https://platform.example.com/dl-return",
		AcceptTypes:                       []string{"ltiResourceLink"},
		AcceptPresentationDocumentTargets: []string{"iframe"},
		AcceptMultiple:                    true,
	}
	return deeplink.New(reg, "deploy-1", settings), reg
}

// parseResponseJWT decodes a deep linking response JWT without verifying the signature.
func parseResponseJWT(t *testing.T, tokenStr string) (jwt.MapClaims, *jwt.Token) {
	t.Helper()
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	tok, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse response JWT: %v", err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("unexpected claims type")
	}
	return claims, tok
}

// ── ResponseJWT structure ─────────────────────────────────────────────────────

// Task 1.3: an empty deployment ID must be rejected before signing, not
// silently produce a response JWT with an empty deployment_id claim.
func TestResponseJWT_EmptyDeploymentID_Rejected(t *testing.T) {
	_, reg := newBuilder(t)
	settings := &lti.DeepLinkingSettings{
		DeepLinkReturnURL:                 "https://platform.example.com/dl-return",
		AcceptTypes:                       []string{"ltiResourceLink"},
		AcceptPresentationDocumentTargets: []string{"iframe"},
	}
	b := deeplink.New(reg, "", settings)
	if _, err := b.ResponseJWT(nil); err == nil {
		t.Fatal("expected error for empty deployment ID, got nil")
	}
}

// The happy path (non-empty deployment ID) must be unaffected by the guard.
func TestResponseJWT_NonEmptyDeploymentID_Accepted(t *testing.T) {
	b, _ := newBuilder(t)
	if _, err := b.ResponseJWT(nil); err != nil {
		t.Fatalf("ResponseJWT failed with a valid deployment ID: %v", err)
	}
}

// Spec: iss must be the tool's client_id.
func TestResponseJWT_IssIsClientID(t *testing.T) {
	b, reg := newBuilder(t)
	tok, err := b.ResponseJWT(nil)
	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	claims, _ := parseResponseJWT(t, tok)
	if claims["iss"] != reg.ClientID {
		t.Errorf("iss = %v, want %q", claims["iss"], reg.ClientID)
	}
}

// Spec DL 2.0 §4.1: aud must be the platform's issuer (iss of the LtiDeepLinkingRequest),
// not the deep_link_return_url.
func TestResponseJWT_AudIsPlatformIssuer(t *testing.T) {
	b, reg := newBuilder(t)
	tok, err := b.ResponseJWT(nil)
	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	claims, _ := parseResponseJWT(t, tok)
	aud, _ := claims["aud"].(string)
	if aud != reg.Issuer {
		t.Errorf("aud = %q, want platform issuer %q", aud, reg.Issuer)
	}
}

// Spec: message_type claim must be LtiDeepLinkingResponse.
func TestResponseJWT_MessageTypeIsDeepLinkingResponse(t *testing.T) {
	b, _ := newBuilder(t)
	tok, err := b.ResponseJWT(nil)
	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	claims, _ := parseResponseJWT(t, tok)
	const claimKey = "https://purl.imsglobal.org/spec/lti/claim/message_type"
	if claims[claimKey] != "LtiDeepLinkingResponse" {
		t.Errorf("message_type = %v, want LtiDeepLinkingResponse", claims[claimKey])
	}
}

// Spec: version must be "1.3.0".
func TestResponseJWT_VersionIs130(t *testing.T) {
	b, _ := newBuilder(t)
	tok, err := b.ResponseJWT(nil)
	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	claims, _ := parseResponseJWT(t, tok)
	const claimKey = "https://purl.imsglobal.org/spec/lti/claim/version"
	if claims[claimKey] != "1.3.0" {
		t.Errorf("version = %v, want 1.3.0", claims[claimKey])
	}
}

// Spec: deployment_id must match the deployment used to create the builder.
func TestResponseJWT_DeploymentID(t *testing.T) {
	b, _ := newBuilder(t)
	tok, err := b.ResponseJWT(nil)
	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	claims, _ := parseResponseJWT(t, tok)
	const claimKey = "https://purl.imsglobal.org/spec/lti/claim/deployment_id"
	if claims[claimKey] != "deploy-1" {
		t.Errorf("deployment_id = %v, want deploy-1", claims[claimKey])
	}
}

// Spec: JWT must be signed with RS256.
func TestResponseJWT_SignedWithRS256(t *testing.T) {
	b, _ := newBuilder(t)
	tok, err := b.ResponseJWT(nil)
	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	_, raw := parseResponseJWT(t, tok)
	if raw.Method.Alg() != "RS256" {
		t.Errorf("alg = %q, want RS256", raw.Method.Alg())
	}
}

// Spec: kid in header must match the registration's KID.
func TestResponseJWT_KIDInHeader(t *testing.T) {
	b, reg := newBuilder(t)
	tok, err := b.ResponseJWT(nil)
	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	_, raw := parseResponseJWT(t, tok)
	if raw.Header["kid"] != reg.KID {
		t.Errorf("kid = %v, want %q", raw.Header["kid"], reg.KID)
	}
}

// ── Content items ─────────────────────────────────────────────────────────────

// The content_items claim must contain the resources passed in.
func TestResponseJWT_ContentItemsIncluded(t *testing.T) {
	b, _ := newBuilder(t)
	resources := []deeplink.Resource{
		deeplink.NewLTIResourceLink("Quiz 1", "https://tool.example.com/quiz/1"),
		deeplink.NewLTIResourceLink("Quiz 2", "https://tool.example.com/quiz/2"),
	}
	tok, err := b.ResponseJWT(resources)
	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	claims, _ := parseResponseJWT(t, tok)
	const claimKey = "https://purl.imsglobal.org/spec/lti-dl/claim/content_items"
	items, ok := claims[claimKey].([]any)
	if !ok {
		t.Fatalf("content_items missing or wrong type: %T", claims[claimKey])
	}
	if len(items) != 2 {
		t.Errorf("content_items len = %d, want 2", len(items))
	}
}

// DL 2.0 permits a response with no selections by omitting content_items or by
// sending an empty JSON array. JSON null is not a content-items array.
func TestResponseJWT_EmptyResources(t *testing.T) {
	for name, resources := range map[string][]deeplink.Resource{
		"nil slice":   nil,
		"empty slice": {},
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := newBuilder(t)
			tok, err := b.ResponseJWT(resources)
			if err != nil {
				t.Fatalf("ResponseJWT failed with no resources: %v", err)
			}
			claims, _ := parseResponseJWT(t, tok)
			const claimKey = "https://purl.imsglobal.org/spec/lti-dl/claim/content_items"
			value, present := claims[claimKey]
			if !present {
				return
			}
			items, ok := value.([]any)
			if !ok {
				t.Fatalf("content_items = %#v (%T), want omitted or an empty array", value, value)
			}
			if len(items) != 0 {
				t.Errorf("content_items has %d entries, want zero", len(items))
			}
		})
	}
}

// NewLTIResourceLink must set type=ltiResourceLink.
func TestNewLTIResourceLink_Type(t *testing.T) {
	r := deeplink.NewLTIResourceLink("title", "https://tool.example.com/launch")
	if r.Type != "ltiResourceLink" {
		t.Errorf("Type = %q, want ltiResourceLink", r.Type)
	}
}

// NewLTIResourceLink must set the title and URL.
func TestNewLTIResourceLink_TitleAndURL(t *testing.T) {
	r := deeplink.NewLTIResourceLink("My Quiz", "https://tool.example.com/quiz")
	if r.Title != "My Quiz" {
		t.Errorf("Title = %q, want My Quiz", r.Title)
	}
	if r.URL != "https://tool.example.com/quiz" {
		t.Errorf("URL = %q, want https://tool.example.com/quiz", r.URL)
	}
}

// NewLTIResourceLinkWithGrade must attach a LineItem.
func TestNewLTIResourceLinkWithGrade_HasLineItem(t *testing.T) {
	li := deeplink.LineItemProperty{Label: "Quiz Score", ScoreMaximum: 100}
	r := deeplink.NewLTIResourceLinkWithGrade("Quiz", "https://tool.example.com/quiz", li)
	if r.LineItem == nil {
		t.Fatal("LineItem must not be nil")
	}
	if r.LineItem.ScoreMaximum != 100 {
		t.Errorf("ScoreMaximum = %v, want 100", r.LineItem.ScoreMaximum)
	}
}

// ── Data echo ────────────────────────────────────────────────────────────────

// Spec DL §5.1: if deep_linking_settings.data is set, it must be echoed back.
func TestResponseJWT_EchoesDataField(t *testing.T) {
	key := ltitest.NewKey(t)
	reg := &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-xyz",
		KeySetURL:      "https://platform.example.com/jwks",
		AuthLoginURL:   "https://platform.example.com/auth",
		AuthTokenURL:   "https://platform.example.com/token",
		ToolPrivateKey: key,
		KID:            "tool-key-1",
	}
	settings := &lti.DeepLinkingSettings{
		DeepLinkReturnURL:                 "https://platform.example.com/dl-return",
		AcceptTypes:                       []string{"ltiResourceLink"},
		AcceptPresentationDocumentTargets: []string{"iframe"},
		Data:                              deeplink.String("platform-state-opaque"),
	}
	b := deeplink.New(reg, "deploy-1", settings)
	tok, err := b.ResponseJWT(nil)
	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	claims, _ := parseResponseJWT(t, tok)
	const dataKey = "https://purl.imsglobal.org/spec/lti-dl/claim/data"
	if claims[dataKey] != "platform-state-opaque" {
		t.Errorf("data = %v, want platform-state-opaque", claims[dataKey])
	}
}

// The request's data property is opaque and must be echoed whenever present;
// an empty string remains a present value and is not equivalent to omission.
func TestResponseJWT_EchoesPresentEmptyDataField(t *testing.T) {
	_, reg := newBuilder(t)
	var settings lti.DeepLinkingSettings
	if err := json.Unmarshal([]byte(`{
		"deep_link_return_url":"https://platform.example.com/dl-return",
		"accept_types":["ltiResourceLink"],
		"accept_presentation_document_targets":["iframe"],
		"data":""
	}`), &settings); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	b := deeplink.New(reg, "deploy-1", &settings)
	tok, err := b.ResponseJWT(nil)
	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	claims, _ := parseResponseJWT(t, tok)
	const claimKey = "https://purl.imsglobal.org/spec/lti-dl/claim/data"
	value, present := claims[claimKey]
	if !present || value != "" {
		t.Errorf("data claim = %#v (present %v), want present empty string", value, present)
	}
}

// ── ResponseFormHTML ─────────────────────────────────────────────────────────

// The HTML response must contain a form that POSTs to the deep_link_return_url.
func TestResponseFormHTML_ContainsFormWithReturnURL(t *testing.T) {
	b, _ := newBuilder(t)
	html, err := b.ResponseFormHTML(nil)
	if err != nil {
		t.Fatalf("ResponseFormHTML failed: %v", err)
	}
	if !strings.Contains(html, "https://platform.example.com/dl-return") {
		t.Errorf("form action URL not found in HTML:\n%s", html)
	}
	if !strings.Contains(html, `method="POST"`) {
		t.Errorf("form method POST not found in HTML")
	}
}

// The HTML form must include a hidden JWT field named "JWT".
func TestResponseFormHTML_ContainsJWTField(t *testing.T) {
	b, _ := newBuilder(t)
	html, err := b.ResponseFormHTML(nil)
	if err != nil {
		t.Fatalf("ResponseFormHTML failed: %v", err)
	}
	if !strings.Contains(html, `name="JWT"`) {
		t.Errorf(`hidden input name="JWT" not found in HTML`)
	}
	if !strings.Contains(html, "eyJ") { // all JWTs begin with base64url of "{"
		t.Errorf("JWT value not present in HTML")
	}
}

// ── JWT TTL ───────────────────────────────────────────────────────────────────

// DL spec §5.3: The response JWT must include iat and exp claims.
// exp must be iat + 600 seconds (10 minutes).
func TestResponseJWT_IATAndEXPAreSet(t *testing.T) {
	b, _ := newBuilder(t)

	before := time.Now().Unix()
	tok, err := b.ResponseJWT(nil)
	after := time.Now().Unix()

	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	claims, _ := parseResponseJWT(t, tok)

	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatalf("iat missing or wrong type: %T", claims["iat"])
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp missing or wrong type: %T", claims["exp"])
	}

	if int64(iat) < before || int64(iat) > after {
		t.Errorf("iat = %v, expected between %d and %d", iat, before, after)
	}
	const wantTTL = 600
	if int64(exp)-int64(iat) != wantTTL {
		t.Errorf("exp-iat = %v, want %d seconds", int64(exp)-int64(iat), wantTTL)
	}
}

// ── HTML form safety ──────────────────────────────────────────────────────────

// ResponseFormHTML must HTML-escape the return URL to prevent form injection.
// A return URL containing HTML meta-characters must not produce injectable markup.
func TestResponseFormHTML_ReturnURL_IsHTMLEscaped(t *testing.T) {
	key := ltitest.NewKey(t)
	reg := &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-xyz",
		KeySetURL:      "https://platform.example.com/jwks",
		AuthLoginURL:   "https://platform.example.com/auth",
		AuthTokenURL:   "https://platform.example.com/token",
		ToolPrivateKey: key,
		KID:            "tool-key-1",
	}
	settings := &lti.DeepLinkingSettings{
		DeepLinkReturnURL:                 `https://platform.example.com/return?next=%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E`,
		AcceptTypes:                       []string{"ltiResourceLink"},
		AcceptPresentationDocumentTargets: []string{"iframe"},
	}
	b := deeplink.New(reg, "deploy-1", settings)

	html, err := b.ResponseFormHTML(nil)
	if err != nil {
		t.Fatalf("ResponseFormHTML failed: %v", err)
	}
	// Percent-encoded metacharacters must remain data and must not become markup.
	if strings.Contains(html, `"><script>`) {
		t.Error("return URL injection not escaped: raw <script> tag found in HTML output")
	}
}

// ── NewFromLaunch ─────────────────────────────────────────────────────────────

// NewFromLaunch must return ErrDeepLinkingNotAvailable for a resource link launch.
func TestNewFromLaunch_ResourceLaunch_ReturnsError(t *testing.T) {
	key := ltitest.NewKey(t)
	reg := &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-xyz",
		KeySetURL:      "https://platform.example.com/jwks",
		AuthLoginURL:   "https://platform.example.com/auth",
		AuthTokenURL:   "https://platform.example.com/token",
		ToolPrivateKey: key,
		KID:            "tool-key-1",
	}
	ld := &lti.Launch{
		LaunchID:     "launch-1",
		Registration: reg,
		Deployment:   &lti.Deployment{DeploymentID: "deploy-1"},
		Claims: &lti.LTIClaims{
			MessageType: lti.MessageTypeResourceLink,
		},
	}
	_, err := deeplink.NewFromLaunch(ld)
	if err == nil {
		t.Error("expected ErrDeepLinkingNotAvailable for resource link launch")
	}
}

// NewFromLaunch must succeed for a deep linking launch.
func TestNewFromLaunch_DeepLinkLaunch_Succeeds(t *testing.T) {
	key := ltitest.NewKey(t)
	reg := &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-xyz",
		KeySetURL:      "https://platform.example.com/jwks",
		AuthLoginURL:   "https://platform.example.com/auth",
		AuthTokenURL:   "https://platform.example.com/token",
		ToolPrivateKey: key,
		KID:            "tool-key-1",
	}
	ld := &lti.Launch{
		LaunchID:     "launch-1",
		Registration: reg,
		Deployment:   &lti.Deployment{DeploymentID: "deploy-1"},
		Claims: &lti.LTIClaims{
			MessageType: lti.MessageTypeDeepLinking,
			DeepLinkingSettings: &lti.DeepLinkingSettings{
				DeepLinkReturnURL:                 "https://platform.example.com/dl-return",
				AcceptTypes:                       []string{"ltiResourceLink"},
				AcceptPresentationDocumentTargets: []string{"iframe"},
			},
		},
	}
	b, err := deeplink.NewFromLaunch(ld)
	if err != nil {
		t.Fatalf("NewFromLaunch failed: %v", err)
	}
	if b == nil {
		t.Fatal("builder must not be nil")
	}
}
