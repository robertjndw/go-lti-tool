package ags

// Float returns a pointer to v, for filling optional score fields such as
// Score.ScoreGiven inline: ags.Score{ScoreGiven: ags.Float(85), ...}.
func Float(v float64) *float64 { return &v }

// Score is the payload sent to the platform to record a learner's grade.
// It maps to the LTI AGS Score schema.
type Score struct {
	// UserID is the platform user identifier (the "sub" claim from the launch JWT).
	UserID string `json:"userId"`

	// ScoreGiven is the achieved score. Nil means no score is being reported
	// (which is different from a score of 0). Use ags.Float to set it inline.
	// When set, ScoreMaximum must also be set (AGS spec).
	ScoreGiven *float64 `json:"scoreGiven,omitempty"`

	// ScoreMaximum is the maximum possible score. Required whenever ScoreGiven
	// is present; must be a positive number.
	ScoreMaximum *float64 `json:"scoreMaximum,omitempty"`

	// Comment is an optional human-readable comment about the score.
	Comment string `json:"comment,omitempty"`

	// ActivityProgress describes the learner's completion state.
	ActivityProgress string `json:"activityProgress"`

	// GradingProgress describes the grading state.
	GradingProgress string `json:"gradingProgress"`

	// Timestamp is the ISO 8601 datetime when the score was recorded.
	Timestamp string `json:"timestamp"`
}

// ActivityProgress constants (LTI AGS spec §3.1).
const (
	ActivityProgressInitialized = "Initialized"
	ActivityProgressStarted     = "Started"
	ActivityProgressInProgress  = "InProgress"
	ActivityProgressSubmitted   = "Submitted"
	ActivityProgressCompleted   = "Completed"
)

// GradingProgress constants (LTI AGS spec §3.2).
const (
	GradingProgressFullyGraded   = "FullyGraded"
	GradingProgressPending       = "Pending"
	GradingProgressPendingManual = "PendingManual"
	GradingProgressFailed        = "Failed"
	GradingProgressNotReady      = "NotReady"
)

// Result represents a grading result returned by the platform.
type Result struct {
	// ID is the platform-assigned result URL.
	ID string `json:"id"`

	// UserID is the platform user identifier.
	UserID string `json:"userId"`

	// ResultScore is the achieved score. Nil means the platform reported no
	// score (as opposed to a score of 0).
	ResultScore *float64 `json:"resultScore,omitempty"`

	// ResultMaximum is the maximum possible score.
	ResultMaximum *float64 `json:"resultMaximum,omitempty"`

	// Comment is an optional comment.
	Comment string `json:"comment,omitempty"`

	// ScoreOf is the URL of the line item this result belongs to.
	ScoreOf string `json:"scoreOf,omitempty"`
}
