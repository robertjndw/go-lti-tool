package ags

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// iso8601Pattern matches an ISO 8601 datetime with a REQUIRED
// fractional-seconds component and a Z or numeric UTC offset (with or
// without a colon/minutes, e.g. Z, +00:00, +00). AGS §3.4.9 governs Score
// timestamp and submission.startedAt/submittedAt; every valid example in
// §3.4.9.1 carries a fractional-seconds component (e.g.
// "2017-04-16T18:54:36.736+00:00"), so it is required here — this is
// distinct from the more lenient LineItem startDateTime/endDateTime (§3.2),
// which this package does not format-validate.
var iso8601Pattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(Z|[+-]\d{2}(:?\d{2})?)$`)

// parseISO8601Time parses an AGS ISO 8601 timestamp, returning an error that
// names the offending value when it is not well-formed.
func parseISO8601Time(s string) (time.Time, error) {
	if !iso8601Pattern.MatchString(s) {
		return time.Time{}, fmt.Errorf("ags: %q is not a valid ISO 8601 datetime", s)
	}
	normalized := s
	if !strings.HasSuffix(s, "Z") {
		if idx := strings.LastIndexAny(s, "+-"); idx > 0 && len(s)-idx == 3 {
			// Bare 2-digit offset (e.g. "+00"): add the minutes Go's RFC3339
			// layout requires for parsing.
			normalized = s + ":00"
		}
	}
	t, err := time.Parse(time.RFC3339Nano, normalized)
	if err != nil {
		return time.Time{}, fmt.Errorf("ags: %q is not a valid ISO 8601 datetime: %w", s, err)
	}
	return t, nil
}

// parseISO8601 validates s as an AGS ISO 8601 timestamp.
func parseISO8601(s string) error {
	_, err := parseISO8601Time(s)
	return err
}

// validActivityProgress and validGradingProgress are the AGS spec's closed
// vocabularies for Score.ActivityProgress and Score.GradingProgress.
var (
	validActivityProgress = []string{
		ActivityProgressInitialized,
		ActivityProgressStarted,
		ActivityProgressInProgress,
		ActivityProgressSubmitted,
		ActivityProgressCompleted,
	}
	validGradingProgress = []string{
		GradingProgressFullyGraded,
		GradingProgressPending,
		GradingProgressPendingManual,
		GradingProgressFailed,
		GradingProgressNotReady,
	}
)

// validateScore checks Score against the AGS schema before it is ever sent
// over the network: required fields, non-negative/positive numeric
// constraints, ISO 8601 timestamps, submission ordering, and the closed
// activityProgress/gradingProgress vocabularies.
func validateScore(score Score) error {
	if score.UserID == "" {
		return fmt.Errorf("ags: SubmitScore: UserID is required")
	}
	if !slices.Contains(validActivityProgress, score.ActivityProgress) {
		return fmt.Errorf("ags: SubmitScore: ActivityProgress must be one of %v, got %q", validActivityProgress, score.ActivityProgress)
	}
	if !slices.Contains(validGradingProgress, score.GradingProgress) {
		return fmt.Errorf("ags: SubmitScore: GradingProgress must be one of %v, got %q", validGradingProgress, score.GradingProgress)
	}
	if score.Timestamp == "" {
		return fmt.Errorf("ags: SubmitScore: Timestamp is required (ISO 8601)")
	}
	if err := parseISO8601(score.Timestamp); err != nil {
		return fmt.Errorf("ags: SubmitScore: Timestamp: %w", err)
	}
	if score.ScoreGiven != nil && *score.ScoreGiven < 0 {
		return fmt.Errorf("ags: SubmitScore: ScoreGiven must not be negative")
	}
	// AGS spec: scoreMaximum is required whenever scoreGiven is present, and
	// must be positive whenever it is supplied at all.
	if score.ScoreGiven != nil && score.ScoreMaximum == nil {
		return fmt.Errorf("ags: SubmitScore: ScoreMaximum is required when ScoreGiven is set")
	}
	if score.ScoreMaximum != nil && *score.ScoreMaximum <= 0 {
		return fmt.Errorf("ags: SubmitScore: ScoreMaximum must be a positive number")
	}
	if score.Submission != nil {
		var started, submitted time.Time
		var err error
		if score.Submission.StartedAt != "" {
			if started, err = parseISO8601Time(score.Submission.StartedAt); err != nil {
				return fmt.Errorf("ags: SubmitScore: Submission.StartedAt: %w", err)
			}
		}
		if score.Submission.SubmittedAt != "" {
			if submitted, err = parseISO8601Time(score.Submission.SubmittedAt); err != nil {
				return fmt.Errorf("ags: SubmitScore: Submission.SubmittedAt: %w", err)
			}
		}
		if score.Submission.StartedAt != "" && score.Submission.SubmittedAt != "" && started.After(submitted) {
			return fmt.Errorf("ags: SubmitScore: Submission.StartedAt must not be after Submission.SubmittedAt")
		}
	}
	return nil
}

// validateLineitem checks Lineitem against the AGS schema before it is sent
// over the network: a non-blank label and a positive score maximum.
func validateLineitem(li Lineitem) error {
	if strings.TrimSpace(li.Label) == "" {
		return fmt.Errorf("ags: Lineitem.Label must not be blank")
	}
	if li.ScoreMaximum <= 0 {
		return fmt.Errorf("ags: Lineitem.ScoreMaximum must be a positive number")
	}
	return nil
}
