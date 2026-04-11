package launch_test

import (
	"testing"

	lti "github.com/robertjndw/go-lti"
	"github.com/robertjndw/go-lti/launch"
)

// minimalResourceClaims returns the minimal valid LTI claims for a resource link request.
func minimalResourceClaims() *lti.LTIClaims {
	return &lti.LTIClaims{
		Subject:      "user-1",
		MessageType:  lti.MessageTypeResourceLink,
		Version:      lti.LTIVersion,
		DeploymentID: "deploy-1",
		Roles:        []string{},
		ResourceLink: &lti.ResourceLink{ID: "link-1"},
	}
}

func minimalDeepLinkClaims() *lti.LTIClaims {
	return &lti.LTIClaims{
		Subject:     "user-1",
		MessageType: lti.MessageTypeDeepLinking,
		Version:     lti.LTIVersion,
		Roles:       []string{},
		DeepLinkingSettings: &lti.DeepLinkingSettings{
			DeepLinkReturnURL:                 "https://platform.example.com/return",
			AcceptTypes:                       []string{"ltiResourceLink"},
			AcceptPresentationDocumentTargets: []string{"iframe"},
		},
	}
}

// ── ResourceMessageValidator ──────────────────────────────────────────────────

// Spec: ResourceMessageValidator must only handle LtiResourceLinkRequest.
func TestResourceValidator_CanValidate(t *testing.T) {
	v := launch.ResourceMessageValidator{}

	if !v.CanValidate(&lti.LTIClaims{MessageType: lti.MessageTypeResourceLink}) {
		t.Error("must return true for LtiResourceLinkRequest")
	}
	if v.CanValidate(&lti.LTIClaims{MessageType: lti.MessageTypeDeepLinking}) {
		t.Error("must return false for LtiDeepLinkingRequest")
	}
	if v.CanValidate(&lti.LTIClaims{MessageType: "Unknown"}) {
		t.Error("must return false for unknown message types")
	}
}

// Spec: A valid LtiResourceLinkRequest must pass validation.
func TestResourceValidator_Valid_Passes(t *testing.T) {
	v := launch.ResourceMessageValidator{}
	if err := v.Validate(minimalResourceClaims()); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// Spec: sub claim must be present in LtiResourceLinkRequest.
func TestResourceValidator_MissingSub_Fails(t *testing.T) {
	v := launch.ResourceMessageValidator{}
	c := minimalResourceClaims()
	c.Subject = ""
	if err := v.Validate(c); err == nil {
		t.Error("expected error for missing sub")
	}
}

// Spec: version must be "1.3.0".
func TestResourceValidator_WrongVersion_Fails(t *testing.T) {
	v := launch.ResourceMessageValidator{}
	c := minimalResourceClaims()
	c.Version = "1.0.0"
	if err := v.Validate(c); err == nil {
		t.Error("expected error for wrong version")
	}
}

// Spec: roles claim must be present (may be an empty array).
func TestResourceValidator_NilRoles_Fails(t *testing.T) {
	v := launch.ResourceMessageValidator{}
	c := minimalResourceClaims()
	c.Roles = nil
	if err := v.Validate(c); err == nil {
		t.Error("expected error for nil roles")
	}
}

// Spec: roles may be an empty array.
func TestResourceValidator_EmptyRolesAllowed(t *testing.T) {
	v := launch.ResourceMessageValidator{}
	c := minimalResourceClaims()
	c.Roles = []string{} // empty but present
	if err := v.Validate(c); err != nil {
		t.Errorf("empty roles slice must be allowed, got %v", err)
	}
}

// Spec: resource_link claim must be present for LtiResourceLinkRequest.
func TestResourceValidator_MissingResourceLink_Fails(t *testing.T) {
	v := launch.ResourceMessageValidator{}
	c := minimalResourceClaims()
	c.ResourceLink = nil
	if err := v.Validate(c); err == nil {
		t.Error("expected error for missing resource_link")
	}
}

// Spec: resource_link.id must be non-empty.
func TestResourceValidator_EmptyResourceLinkID_Fails(t *testing.T) {
	v := launch.ResourceMessageValidator{}
	c := minimalResourceClaims()
	c.ResourceLink = &lti.ResourceLink{ID: ""}
	if err := v.Validate(c); err == nil {
		t.Error("expected error for empty resource_link.id")
	}
}

// ── DeepLinkMessageValidator ──────────────────────────────────────────────────

// Spec: DeepLinkMessageValidator must only handle LtiDeepLinkingRequest.
func TestDeepLinkValidator_CanValidate(t *testing.T) {
	v := launch.DeepLinkMessageValidator{}

	if !v.CanValidate(&lti.LTIClaims{MessageType: lti.MessageTypeDeepLinking}) {
		t.Error("must return true for LtiDeepLinkingRequest")
	}
	if v.CanValidate(&lti.LTIClaims{MessageType: lti.MessageTypeResourceLink}) {
		t.Error("must return false for LtiResourceLinkRequest")
	}
}

// Spec: A valid LtiDeepLinkingRequest must pass validation.
func TestDeepLinkValidator_Valid_Passes(t *testing.T) {
	v := launch.DeepLinkMessageValidator{}
	if err := v.Validate(minimalDeepLinkClaims()); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// Spec: sub must be present.
func TestDeepLinkValidator_MissingSub_Fails(t *testing.T) {
	v := launch.DeepLinkMessageValidator{}
	c := minimalDeepLinkClaims()
	c.Subject = ""
	if err := v.Validate(c); err == nil {
		t.Error("expected error for missing sub")
	}
}

// Spec: version must be "1.3.0".
func TestDeepLinkValidator_WrongVersion_Fails(t *testing.T) {
	v := launch.DeepLinkMessageValidator{}
	c := minimalDeepLinkClaims()
	c.Version = "1.2.0"
	if err := v.Validate(c); err == nil {
		t.Error("expected error for wrong version")
	}
}

// Spec: deep_linking_settings must be present.
func TestDeepLinkValidator_MissingSettings_Fails(t *testing.T) {
	v := launch.DeepLinkMessageValidator{}
	c := minimalDeepLinkClaims()
	c.DeepLinkingSettings = nil
	if err := v.Validate(c); err == nil {
		t.Error("expected error for missing deep_linking_settings")
	}
}

// Spec: deep_link_return_url must be non-empty.
func TestDeepLinkValidator_EmptyReturnURL_Fails(t *testing.T) {
	v := launch.DeepLinkMessageValidator{}
	c := minimalDeepLinkClaims()
	c.DeepLinkingSettings.DeepLinkReturnURL = ""
	if err := v.Validate(c); err == nil {
		t.Error("expected error for empty deep_link_return_url")
	}
}

// Spec: accept_types must be non-empty.
func TestDeepLinkValidator_EmptyAcceptTypes_Fails(t *testing.T) {
	v := launch.DeepLinkMessageValidator{}
	c := minimalDeepLinkClaims()
	c.DeepLinkingSettings.AcceptTypes = nil
	if err := v.Validate(c); err == nil {
		t.Error("expected error for empty accept_types")
	}
}

// Spec: accept_presentation_document_targets must be non-empty.
func TestDeepLinkValidator_EmptyDocumentTargets_Fails(t *testing.T) {
	v := launch.DeepLinkMessageValidator{}
	c := minimalDeepLinkClaims()
	c.DeepLinkingSettings.AcceptPresentationDocumentTargets = nil
	if err := v.Validate(c); err == nil {
		t.Error("expected error for empty accept_presentation_document_targets")
	}
}

// ── SubmissionReviewMessageValidator ─────────────────────────────────────────

// Spec: SubmissionReviewMessageValidator must only handle LtiSubmissionReviewRequest.
func TestSubmissionReviewValidator_CanValidate(t *testing.T) {
	v := launch.SubmissionReviewMessageValidator{}

	if !v.CanValidate(&lti.LTIClaims{MessageType: lti.MessageTypeSubmissionReview}) {
		t.Error("must return true for LtiSubmissionReviewRequest")
	}
	if v.CanValidate(&lti.LTIClaims{MessageType: lti.MessageTypeResourceLink}) {
		t.Error("must return false for LtiResourceLinkRequest")
	}
}

// Spec: A valid LtiSubmissionReviewRequest must pass validation.
func TestSubmissionReviewValidator_Valid_Passes(t *testing.T) {
	v := launch.SubmissionReviewMessageValidator{}
	c := &lti.LTIClaims{
		Subject:     "user-1",
		MessageType: lti.MessageTypeSubmissionReview,
		Version:     lti.LTIVersion,
		Roles:       []string{lti.RoleInstructor},
		ResourceLink: &lti.ResourceLink{ID: "link-1"},
	}
	if err := v.Validate(c); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// Spec: resource_link.id is required for LtiSubmissionReviewRequest.
func TestSubmissionReviewValidator_MissingResourceLink_Fails(t *testing.T) {
	v := launch.SubmissionReviewMessageValidator{}
	c := &lti.LTIClaims{
		Subject:     "user-1",
		MessageType: lti.MessageTypeSubmissionReview,
		Version:     lti.LTIVersion,
		Roles:       []string{},
		ResourceLink: nil,
	}
	if err := v.Validate(c); err == nil {
		t.Error("expected error for missing resource_link")
	}
}

// ── DefaultValidators ─────────────────────────────────────────────────────────

// DefaultValidators must return all three standard validators.
func TestDefaultValidators_ContainsAllTypes(t *testing.T) {
	validators := launch.DefaultValidators()

	types := []string{
		lti.MessageTypeResourceLink,
		lti.MessageTypeDeepLinking,
		lti.MessageTypeSubmissionReview,
	}
	for _, mt := range types {
		handled := false
		for _, v := range validators {
			if v.CanValidate(&lti.LTIClaims{MessageType: mt}) {
				handled = true
				break
			}
		}
		if !handled {
			t.Errorf("no default validator handles message_type %q", mt)
		}
	}
}
