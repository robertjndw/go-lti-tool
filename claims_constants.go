package lti

// LTI claim namespace prefixes.
const (
	ClaimPrefix        = "https://purl.imsglobal.org/spec/lti/claim/"
	ClaimPrefixAGS     = "https://purl.imsglobal.org/spec/lti-ags/claim/"
	ClaimPrefixNRPS    = "https://purl.imsglobal.org/spec/lti-nrps/claim/"
	ClaimPrefixDL      = "https://purl.imsglobal.org/spec/lti-dl/claim/"
)

// LTI message types.
const (
	MessageTypeResourceLink      = "LtiResourceLinkRequest"
	MessageTypeDeepLinking       = "LtiDeepLinkingRequest"
	MessageTypeSubmissionReview  = "LtiSubmissionReviewRequest"
)

// LTI version.
const LTIVersion = "1.3.0"

// Context types.
const (
	ContextTypeCourseTemplate = "http://purl.imsglobal.org/vocab/lis/v2/course#CourseTemplate"
	ContextTypeCourseOffering = "http://purl.imsglobal.org/vocab/lis/v2/course#CourseOffering"
	ContextTypeCourseSection  = "http://purl.imsglobal.org/vocab/lis/v2/course#CourseSection"
	ContextTypeGroup          = "http://purl.imsglobal.org/vocab/lis/v2/course#Group"
)

// System roles.
const (
	RoleSystemAdministrator = "http://purl.imsglobal.org/vocab/lis/v2/system/person#Administrator"
	RoleSystemNone          = "http://purl.imsglobal.org/vocab/lis/v2/system/person#None"
	RoleSystemAccountAdmin  = "http://purl.imsglobal.org/vocab/lis/v2/system/person#AccountAdmin"
	RoleSystemCreator       = "http://purl.imsglobal.org/vocab/lis/v2/system/person#Creator"
	RoleSystemSysAdmin      = "http://purl.imsglobal.org/vocab/lis/v2/system/person#SysAdmin"
	RoleSystemSysSupport    = "http://purl.imsglobal.org/vocab/lis/v2/system/person#SysSupport"
	RoleSystemUser          = "http://purl.imsglobal.org/vocab/lis/v2/system/person#User"
)

// Institution roles.
const (
	RoleInstitutionAdministrator = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator"
	RoleInstitutionFaculty       = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Faculty"
	RoleInstitutionGuest         = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Guest"
	RoleInstitutionNone          = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#None"
	RoleInstitutionOther         = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Other"
	RoleInstitutionStaff         = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Staff"
	RoleInstitutionStudent       = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student"
	RoleInstitutionAlumni        = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Alumni"
	RoleInstitutionInstructor    = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Instructor"
	RoleInstitutionLearner       = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Learner"
	RoleInstitutionMember        = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Member"
	RoleInstitutionMentor        = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Mentor"
	RoleInstitutionObserver      = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Observer"
	RoleInstitutionProspectiveStudent = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#ProspectiveStudent"
)

// Membership (context) roles.
const (
	RoleAdministrator   = "http://purl.imsglobal.org/vocab/lis/v2/membership#Administrator"
	RoleContentDeveloper = "http://purl.imsglobal.org/vocab/lis/v2/membership#ContentDeveloper"
	RoleInstructor      = "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"
	RoleLearner         = "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"
	RoleMentor          = "http://purl.imsglobal.org/vocab/lis/v2/membership#Mentor"
	RoleManager         = "http://purl.imsglobal.org/vocab/lis/v2/membership#Manager"
	RoleMember          = "http://purl.imsglobal.org/vocab/lis/v2/membership#Member"
	RoleOfficer         = "http://purl.imsglobal.org/vocab/lis/v2/membership#Officer"
)

// OAuth2 scopes for LTI Advantage services.
const (
	ScopeAGSLineitem         = "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem"
	ScopeAGSLineitemReadonly = "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly"
	ScopeAGSScore            = "https://purl.imsglobal.org/spec/lti-ags/scope/score"
	ScopeAGSResultReadonly   = "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"
	ScopeNRPS                = "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"
)

// Deep link content item types.
const (
	DeepLinkTypeLink           = "link"
	DeepLinkTypeLTIResourceLink = "ltiResourceLink"
	DeepLinkTypeFile           = "file"
	DeepLinkTypeHTML           = "html"
	DeepLinkTypeImage          = "image"
)

// Presentation document targets.
const (
	PresentationTargetIframe  = "iframe"
	PresentationTargetWindow  = "window"
	PresentationTargetEmbed   = "embed"
)
