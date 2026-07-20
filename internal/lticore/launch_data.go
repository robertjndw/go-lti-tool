package lticore

import "slices"

// NRPSServiceVersion is the NRPS specification version this client speaks.
const NRPSServiceVersion = "2.0"

// Launch is the validated, trusted payload produced after a successful launch.
type Launch struct {
	// LaunchID is a unique identifier for this launch, used to retrieve it from the store.
	LaunchID string

	// Claims contains the fully parsed and validated JWT body.
	Claims *LTIClaims

	// Registration is the platform registration resolved during validation.
	Registration *Registration

	// Deployment is the deployment resolved during validation.
	Deployment *Deployment
}

// HasAGS reports whether the launch includes an AGS endpoint.
func (ld *Launch) HasAGS() bool {
	return ld.Claims.AGS != nil && (ld.Claims.AGS.Lineitems != "" || ld.Claims.AGS.Lineitem != "")
}

// HasNRPS reports whether the launch includes an NRPS endpoint whose
// advertised service_versions include the 2.0 version this client speaks.
func (ld *Launch) HasNRPS() bool {
	return ld.Claims.NRPS != nil && ld.Claims.NRPS.ContextMembershipsURL != "" &&
		slices.Contains(ld.Claims.NRPS.ServiceVersions, NRPSServiceVersion)
}

// HasDeepLinking reports whether the launch is a deep linking request.
func (ld *Launch) HasDeepLinking() bool {
	return ld.Claims.DeepLinkingSettings != nil && ld.Claims.DeepLinkingSettings.DeepLinkReturnURL != ""
}

// IsResourceLaunch reports whether this is an LtiResourceLinkRequest.
func (ld *Launch) IsResourceLaunch() bool {
	return ld.Claims.MessageType == MessageTypeResourceLink
}

// IsDeepLinkLaunch reports whether this is an LtiDeepLinkingRequest.
func (ld *Launch) IsDeepLinkLaunch() bool {
	return ld.Claims.MessageType == MessageTypeDeepLinking
}
