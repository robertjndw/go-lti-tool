// Package lti is a Go SDK for LTI 1.3 (Learning Tools Interoperability).
// It targets tool implementations, covering the full LTI Advantage surface:
// OIDC launch flow, Assignment & Grade Services (AGS), Names & Role Provisioning
// Services (NRPS), and Deep Linking.
//
// The easiest entry point is [NewTool], which wires everything together and
// returns http.Handlers directly. Sub-packages (login, launch, jwks, …) remain
// available for callers that need lower-level control.
package lti

import (
	"crypto/rsa"

	"github.com/robertjndw/go-lti-tool/dynreg"
	lticore "github.com/robertjndw/go-lti-tool/internal/lticore"
)

// ── Type aliases ──────────────────────────────────────────────────────────────
// These are transparent aliases: lti.X and lticore.X are the exact same type.

type (
	LTIClaims           = lticore.LTIClaims
	Audience            = lticore.Audience
	ResourceLink        = lticore.ResourceLink
	ContextClaim        = lticore.ContextClaim
	LISClaim            = lticore.LISClaim
	LaunchPresentation  = lticore.LaunchPresentation
	ToolPlatform        = lticore.ToolPlatform
	AGSClaim            = lticore.AGSClaim
	NRPSClaim           = lticore.NRPSClaim
	DeepLinkingSettings = lticore.DeepLinkingSettings

	Registration = lticore.Registration
	Deployment   = lticore.Deployment
	Launch       = lticore.Launch

	Datastore          = lticore.Datastore
	RegistrationWriter = lticore.RegistrationWriter
	NonceStore         = lticore.NonceStore
	LaunchDataStore    = lticore.LaunchDataStore
	CookieHandler      = lticore.CookieHandler

	DefaultCookieHandler = lticore.DefaultCookieHandler

	ToolMessage = dynreg.ToolMessage
)

// ParsePrivateKey parses a PEM-encoded RSA private key (PKCS#1 or PKCS#8).
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	return lticore.ParsePrivateKey(pemBytes)
}

// ── Error re-exports ──────────────────────────────────────────────────────────
// Assigning the lticore var means both names hold the same error pointer,
// so errors.Is(err, lti.ErrX) and errors.Is(err, lticore.ErrX) are equivalent.

var (
	ErrRegistrationNotFound    = lticore.ErrRegistrationNotFound
	ErrDeploymentNotFound      = lticore.ErrDeploymentNotFound
	ErrInvalidState            = lticore.ErrInvalidState
	ErrInvalidNonce            = lticore.ErrInvalidNonce
	ErrInvalidJWT              = lticore.ErrInvalidJWT
	ErrInvalidSignature        = lticore.ErrInvalidSignature
	ErrInvalidClaims           = lticore.ErrInvalidClaims
	ErrExpiredJWT              = lticore.ErrExpiredJWT
	ErrMissingClaim            = lticore.ErrMissingClaim
	ErrLaunchNotFound          = lticore.ErrLaunchNotFound
	ErrNoCookieHandler         = lticore.ErrNoCookieHandler
	ErrAGSNotAvailable         = lticore.ErrAGSNotAvailable
	ErrNRPSNotAvailable        = lticore.ErrNRPSNotAvailable
	ErrDeepLinkingNotAvailable = lticore.ErrDeepLinkingNotAvailable
)

// ── Constant re-exports ───────────────────────────────────────────────────────

const (
	ClaimPrefix     = lticore.ClaimPrefix
	ClaimPrefixAGS  = lticore.ClaimPrefixAGS
	ClaimPrefixNRPS = lticore.ClaimPrefixNRPS
	ClaimPrefixDL   = lticore.ClaimPrefixDL

	MessageTypeResourceLink        = lticore.MessageTypeResourceLink
	MessageTypeDeepLinking         = lticore.MessageTypeDeepLinking
	MessageTypeDeepLinkingResponse = lticore.MessageTypeDeepLinkingResponse
	MessageTypeSubmissionReview    = lticore.MessageTypeSubmissionReview

	LTIVersion = lticore.LTIVersion

	ContextTypeCourseTemplate = lticore.ContextTypeCourseTemplate
	ContextTypeCourseOffering = lticore.ContextTypeCourseOffering
	ContextTypeCourseSection  = lticore.ContextTypeCourseSection
	ContextTypeGroup          = lticore.ContextTypeGroup

	RoleSystemAdministrator = lticore.RoleSystemAdministrator
	RoleSystemNone          = lticore.RoleSystemNone
	RoleSystemAccountAdmin  = lticore.RoleSystemAccountAdmin
	RoleSystemCreator       = lticore.RoleSystemCreator
	RoleSystemSysAdmin      = lticore.RoleSystemSysAdmin
	RoleSystemSysSupport    = lticore.RoleSystemSysSupport
	RoleSystemUser          = lticore.RoleSystemUser

	RoleInstitutionAdministrator      = lticore.RoleInstitutionAdministrator
	RoleInstitutionFaculty            = lticore.RoleInstitutionFaculty
	RoleInstitutionGuest              = lticore.RoleInstitutionGuest
	RoleInstitutionNone               = lticore.RoleInstitutionNone
	RoleInstitutionOther              = lticore.RoleInstitutionOther
	RoleInstitutionStaff              = lticore.RoleInstitutionStaff
	RoleInstitutionStudent            = lticore.RoleInstitutionStudent
	RoleInstitutionAlumni             = lticore.RoleInstitutionAlumni
	RoleInstitutionInstructor         = lticore.RoleInstitutionInstructor
	RoleInstitutionLearner            = lticore.RoleInstitutionLearner
	RoleInstitutionMember             = lticore.RoleInstitutionMember
	RoleInstitutionMentor             = lticore.RoleInstitutionMentor
	RoleInstitutionObserver           = lticore.RoleInstitutionObserver
	RoleInstitutionProspectiveStudent = lticore.RoleInstitutionProspectiveStudent

	RoleAdministrator    = lticore.RoleAdministrator
	RoleContentDeveloper = lticore.RoleContentDeveloper
	RoleInstructor       = lticore.RoleInstructor
	RoleLearner          = lticore.RoleLearner
	RoleMentor           = lticore.RoleMentor
	RoleManager          = lticore.RoleManager
	RoleMember           = lticore.RoleMember
	RoleOfficer          = lticore.RoleOfficer

	ScopeAGSLineitem         = lticore.ScopeAGSLineitem
	ScopeAGSLineitemReadonly = lticore.ScopeAGSLineitemReadonly
	ScopeAGSScore            = lticore.ScopeAGSScore
	ScopeAGSResultReadonly   = lticore.ScopeAGSResultReadonly
	ScopeNRPS                = lticore.ScopeNRPS

	DeepLinkTypeLink            = lticore.DeepLinkTypeLink
	DeepLinkTypeLTIResourceLink = lticore.DeepLinkTypeLTIResourceLink
	DeepLinkTypeFile            = lticore.DeepLinkTypeFile
	DeepLinkTypeHTML            = lticore.DeepLinkTypeHTML
	DeepLinkTypeImage           = lticore.DeepLinkTypeImage

	PresentationTargetIframe = lticore.PresentationTargetIframe
	PresentationTargetWindow = lticore.PresentationTargetWindow
	PresentationTargetEmbed  = lticore.PresentationTargetEmbed
)
