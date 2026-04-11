package launch

import (
	"fmt"

	"github.com/robertjndw/go-lti"
)

// MessageValidator validates the LTI-specific claims for a particular message type.
type MessageValidator interface {
	// CanValidate returns true if this validator handles the given claims.
	CanValidate(claims *lti.LTIClaims) bool

	// Validate checks LTI-specific claims. Return a descriptive error if invalid.
	Validate(claims *lti.LTIClaims) error
}

// DefaultValidators returns the standard set of message validators.
func DefaultValidators() []MessageValidator {
	return []MessageValidator{
		ResourceMessageValidator{},
		DeepLinkMessageValidator{},
		SubmissionReviewMessageValidator{},
	}
}

// ResourceMessageValidator validates LtiResourceLinkRequest messages.
type ResourceMessageValidator struct{}

func (ResourceMessageValidator) CanValidate(claims *lti.LTIClaims) bool {
	return claims.MessageType == lti.MessageTypeResourceLink
}

// Validate checks LTI-specific claims for an LtiResourceLinkRequest.
//
// Anonymous launches: The LTI 1.3 spec (§3) allows sub to be absent when the
// platform does not know the user's identity. sub is therefore NOT required
// here. Callers should check Claims.Subject == "" to detect anonymous launches
// and handle them according to their own policy.
func (ResourceMessageValidator) Validate(claims *lti.LTIClaims) error {
	if claims.Version != lti.LTIVersion {
		return fmt.Errorf("lti: LtiResourceLinkRequest version must be %q, got %q", lti.LTIVersion, claims.Version)
	}
	if claims.Roles == nil {
		return fmt.Errorf("lti: LtiResourceLinkRequest missing 'roles' claim")
	}
	if claims.ResourceLink == nil {
		return fmt.Errorf("lti: LtiResourceLinkRequest missing 'resource_link' claim")
	}
	if claims.ResourceLink.ID == "" {
		return fmt.Errorf("lti: LtiResourceLinkRequest resource_link.id is empty")
	}
	return nil
}

// DeepLinkMessageValidator validates LtiDeepLinkingRequest messages.
type DeepLinkMessageValidator struct{}

func (DeepLinkMessageValidator) CanValidate(claims *lti.LTIClaims) bool {
	return claims.MessageType == lti.MessageTypeDeepLinking
}

// Validate checks LTI-specific claims for an LtiDeepLinkingRequest.
// See ResourceMessageValidator.Validate for the anonymous-launch policy.
func (DeepLinkMessageValidator) Validate(claims *lti.LTIClaims) error {
	if claims.Version != lti.LTIVersion {
		return fmt.Errorf("lti: LtiDeepLinkingRequest version must be %q, got %q", lti.LTIVersion, claims.Version)
	}
	if claims.Roles == nil {
		return fmt.Errorf("lti: LtiDeepLinkingRequest missing 'roles' claim")
	}
	if claims.DeepLinkingSettings == nil {
		return fmt.Errorf("lti: LtiDeepLinkingRequest missing deep_linking_settings claim")
	}
	if claims.DeepLinkingSettings.DeepLinkReturnURL == "" {
		return fmt.Errorf("lti: LtiDeepLinkingRequest deep_link_return_url is empty")
	}
	if len(claims.DeepLinkingSettings.AcceptTypes) == 0 {
		return fmt.Errorf("lti: LtiDeepLinkingRequest accept_types is empty")
	}
	if len(claims.DeepLinkingSettings.AcceptPresentationDocumentTargets) == 0 {
		return fmt.Errorf("lti: LtiDeepLinkingRequest accept_presentation_document_targets is empty")
	}
	return nil
}

// SubmissionReviewMessageValidator validates LtiSubmissionReviewRequest messages.
type SubmissionReviewMessageValidator struct{}

func (SubmissionReviewMessageValidator) CanValidate(claims *lti.LTIClaims) bool {
	return claims.MessageType == lti.MessageTypeSubmissionReview
}

func (SubmissionReviewMessageValidator) Validate(claims *lti.LTIClaims) error {
	if claims.Version != lti.LTIVersion {
		return fmt.Errorf("lti: LtiSubmissionReviewRequest version must be %q, got %q", lti.LTIVersion, claims.Version)
	}
	if claims.Roles == nil {
		return fmt.Errorf("lti: LtiSubmissionReviewRequest missing 'roles' claim")
	}
	if claims.ResourceLink == nil {
		return fmt.Errorf("lti: LtiSubmissionReviewRequest missing 'resource_link' claim")
	}
	if claims.ResourceLink.ID == "" {
		return fmt.Errorf("lti: LtiSubmissionReviewRequest resource_link.id is empty")
	}
	return nil
}
