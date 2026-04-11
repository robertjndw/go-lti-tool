package nrps

// Member represents a course roster entry returned by the NRPS service.
type Member struct {
	// Status is the membership status. Active members have "Active".
	Status string `json:"status"`

	// UserID is the platform's unique identifier for this user.
	UserID string `json:"user_id"`

	// Roles are the LTI membership roles assigned to this user.
	Roles []string `json:"roles"`

	// Name is the user's full name (may be absent if not permitted).
	Name string `json:"name,omitempty"`

	// GivenName is the user's given (first) name.
	GivenName string `json:"given_name,omitempty"`

	// FamilyName is the user's family (last) name.
	FamilyName string `json:"family_name,omitempty"`

	// Email is the user's email address.
	Email string `json:"email,omitempty"`

	// Picture is a URL to the user's profile picture.
	Picture string `json:"picture,omitempty"`

	// LISPersonSourcedID is the LIS person identifier.
	LISPersonSourcedID string `json:"lis_person_sourcedid,omitempty"`

	// Message contains additional LTI launch message data for this member.
	Message []map[string]any `json:"message,omitempty"`
}

// MemberStatus constants.
const (
	MemberStatusActive   = "Active"
	MemberStatusInactive = "Inactive"
	MemberStatusDeleted  = "Deleted"
)
