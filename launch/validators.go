package launch

import (
	"fmt"

	lticore "github.com/robertjndw/go-lti-tool/internal/lticore"
)

// MessageValidator validates the LTI-specific claims for a particular message type.
type MessageValidator interface {
	// CanValidate returns true if this validator handles the given claims.
	CanValidate(claims *lticore.LTIClaims) bool

	// Validate checks LTI-specific claims. Return a descriptive error if invalid.
	Validate(claims *lticore.LTIClaims) error
}

// DefaultValidators returns the standard set of message validators.
func DefaultValidators() []MessageValidator {
	return []MessageValidator{
		ResourceMessageValidator{},
		DeepLinkMessageValidator{},
		SubmissionReviewMessageValidator{},
	}
}

// validateVersion checks that the LTI version claim equals "1.3.0".
func validateVersion(msgType string, claims *lticore.LTIClaims) error {
	if claims.Version != lticore.LTIVersion {
		return fmt.Errorf("lti: %s version must be %q, got %q", msgType, lticore.LTIVersion, claims.Version)
	}
	return nil
}

// validateResourceLink checks that roles and resource_link claims are present and valid.
func validateResourceLink(msgType string, claims *lticore.LTIClaims) error {
	if claims.Roles == nil {
		return fmt.Errorf("lti: %s missing 'roles' claim", msgType)
	}
	if claims.ResourceLink == nil {
		return fmt.Errorf("lti: %s missing 'resource_link' claim", msgType)
	}
	if claims.ResourceLink.ID == "" {
		return fmt.Errorf("lti: %s resource_link.id is empty", msgType)
	}
	return nil
}

// ResourceMessageValidator validates LtiResourceLinkRequest messages.
type ResourceMessageValidator struct{}

func (ResourceMessageValidator) CanValidate(claims *lticore.LTIClaims) bool {
	return claims.MessageType == lticore.MessageTypeResourceLink
}

// Validate checks LTI-specific claims for an LtiResourceLinkRequest.
//
// Anonymous launches: The LTI 1.3 spec (§3) allows sub to be absent when the
// platform does not know the user's identity. sub is therefore NOT required
// here. Callers should check Claims.Subject == "" to detect anonymous launches
// and handle them according to their own policy.
func (ResourceMessageValidator) Validate(claims *lticore.LTIClaims) error {
	if err := validateVersion(lticore.MessageTypeResourceLink, claims); err != nil {
		return err
	}
	return validateResourceLink(lticore.MessageTypeResourceLink, claims)
}

// DeepLinkMessageValidator validates LtiDeepLinkingRequest messages.
type DeepLinkMessageValidator struct{}

func (DeepLinkMessageValidator) CanValidate(claims *lticore.LTIClaims) bool {
	return claims.MessageType == lticore.MessageTypeDeepLinking
}

// Validate checks LTI-specific claims for an LtiDeepLinkingRequest.
// See ResourceMessageValidator.Validate for the anonymous-launch policy.
func (DeepLinkMessageValidator) Validate(claims *lticore.LTIClaims) error {
	if err := validateVersion(lticore.MessageTypeDeepLinking, claims); err != nil {
		return err
	}
	// DL 2.0 defines roles as optional on LtiDeepLinkingRequest, unlike Core's
	// requirement for LtiResourceLinkRequest.
	if claims.DeepLinkingSettings == nil {
		return fmt.Errorf("lti: %s missing deep_linking_settings claim", lticore.MessageTypeDeepLinking)
	}
	if claims.DeepLinkingSettings.DeepLinkReturnURL == "" {
		return fmt.Errorf("lti: %s deep_link_return_url is empty", lticore.MessageTypeDeepLinking)
	}
	// 1EdTech Security Framework §3 requires TLS for LTI message URLs; the
	// tool's response is later POSTed directly to this URL.
	if !isFullyQualifiedHTTPSURL(claims.DeepLinkingSettings.DeepLinkReturnURL) {
		return fmt.Errorf("lti: %s deep_link_return_url must be a fully-qualified https URL", lticore.MessageTypeDeepLinking)
	}
	if len(claims.DeepLinkingSettings.AcceptTypes) == 0 {
		return fmt.Errorf("lti: %s accept_types is empty", lticore.MessageTypeDeepLinking)
	}
	// accept_presentation_document_targets is a required property: the key
	// must be present (a nil slice means it was absent from the JSON), but
	// the DL 2.0 schema does not set minItems: 1, so an empty array — a
	// platform accepting no presentation target — is a valid present value.
	if claims.DeepLinkingSettings.AcceptPresentationDocumentTargets == nil {
		return fmt.Errorf("lti: %s missing accept_presentation_document_targets", lticore.MessageTypeDeepLinking)
	}
	for _, target := range claims.DeepLinkingSettings.AcceptPresentationDocumentTargets {
		switch target {
		case lticore.PresentationTargetEmbed, lticore.PresentationTargetIframe, lticore.PresentationTargetWindow:
		default:
			return fmt.Errorf("lti: %s accept_presentation_document_targets contains unrecognized target %q", lticore.MessageTypeDeepLinking, target)
		}
	}
	return nil
}

// DataPrivacyMessageValidator validates LtiDataPrivacyLaunchRequest messages
// (Data Privacy Launch, a 1EdTech Draft spec as of this writing). Platforms
// such as Canvas send this message type to let an administrative user manage
// and execute data-privacy requests (e.g. right-to-be-forgotten) for a
// specific user, identified via the for_user claim.
//
// NOT included in DefaultValidators(): this is a Draft spec, and its
// requirements can change between revisions without notice. A default
// validator silently changing launch acceptance as the spec evolves would be
// surprising. Opt in explicitly:
//
//	cfg.Validators = append(launch.DefaultValidators(), launch.DataPrivacyMessageValidator{})
//
// Confirmation status: the 1EdTech Data Privacy Launch specification document
// is member-gated, so the exact claim requirements below (for_user required)
// could not be independently verified against the live text at the time this
// validator was written. Re-confirm against the current revision before
// relying on this in a certification context.
type DataPrivacyMessageValidator struct{}

func (DataPrivacyMessageValidator) CanValidate(claims *lticore.LTIClaims) bool {
	return claims.MessageType == lticore.MessageTypeDataPrivacyLaunch
}

// Validate checks LTI-specific claims for an LtiDataPrivacyLaunchRequest.
func (DataPrivacyMessageValidator) Validate(claims *lticore.LTIClaims) error {
	if err := validateVersion(lticore.MessageTypeDataPrivacyLaunch, claims); err != nil {
		return err
	}
	if claims.Roles == nil {
		return fmt.Errorf("lti: %s missing 'roles' claim", lticore.MessageTypeDataPrivacyLaunch)
	}
	if claims.ForUser == nil {
		return fmt.Errorf("lti: %s missing 'for_user' claim", lticore.MessageTypeDataPrivacyLaunch)
	}
	if claims.ForUser.UserID == "" {
		return fmt.Errorf("lti: %s for_user.user_id is empty", lticore.MessageTypeDataPrivacyLaunch)
	}
	return nil
}

// SubmissionReviewMessageValidator validates LtiSubmissionReviewRequest messages.
type SubmissionReviewMessageValidator struct{}

func (SubmissionReviewMessageValidator) CanValidate(claims *lticore.LTIClaims) bool {
	return claims.MessageType == lticore.MessageTypeSubmissionReview
}

// Validate checks LTI-specific claims for an LtiSubmissionReviewRequest.
// The Submission Review spec requires the for_user claim identifying whose
// submission is being reviewed and the AGS endpoint claim with the lineitem
// under review. resource_link is deliberately not required: standalone line
// items are not coupled to a resource link.
//
// launch_presentation.return_url is not checked here: the primary spec
// document is 1EdTech member-gated, and the accessible secondary material
// describes obligations that apply only when return_url IS present (the
// sender must support lti_errormsg/lti_msg query parameters on it), not a
// requirement that it be present. Tools implementing submission review
// should still read Claims.LaunchPresentation.ReturnURL when set to offer
// the instructor a way back to the platform's gradebook; see CONFORMANCE.md.
func (SubmissionReviewMessageValidator) Validate(claims *lticore.LTIClaims) error {
	if err := validateVersion(lticore.MessageTypeSubmissionReview, claims); err != nil {
		return err
	}
	if claims.Roles == nil {
		return fmt.Errorf("lti: %s missing 'roles' claim", lticore.MessageTypeSubmissionReview)
	}
	if claims.ForUser == nil {
		return fmt.Errorf("lti: %s missing 'for_user' claim", lticore.MessageTypeSubmissionReview)
	}
	if claims.ForUser.UserID == "" {
		return fmt.Errorf("lti: %s for_user.user_id is empty", lticore.MessageTypeSubmissionReview)
	}
	if claims.AGS == nil || claims.AGS.Lineitem == "" {
		return fmt.Errorf("lti: %s missing AGS endpoint claim with 'lineitem'", lticore.MessageTypeSubmissionReview)
	}
	return nil
}
