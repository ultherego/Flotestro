package campaigns

import (
	"errors"
	"fmt"
)

// A retry is a new campaign that runs the same order again on the hosts of a
// finished campaign that did not reach the desired state.

// The codes a refused retry answers with.
const (
	// CodeCampaignNotFinished: the campaign still runs, waits or is
	// paused, so the set of hosts that failed is not final yet.
	CodeCampaignNotFinished = "campaign_not_finished"
	// CodeNothingToRetry: no host of the campaign failed - or ended
	// unknown, when the order asked for those too.
	CodeNothingToRetry = "nothing_to_retry"
)

// RetryError is a refusal of a retry order: a stable code and the reason
// in words.
type RetryError struct {
	Code   string
	Reason string
}

func (e *RetryError) Error() string { return e.Reason }

// RetryCode returns the code of a refused retry, or an empty string for
// any other error.
func RetryCode(err error) string {
	var refusal *RetryError
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

// RetryTargets picks the hosts a retry of the campaign runs on.
func RetryTargets(original Campaign, targets []Target, includeUnknown bool) ([]Target, error) {
	if !original.State.Terminal() {
		return nil, &RetryError{
			Code: CodeCampaignNotFinished,
			Reason: fmt.Sprintf("the campaign %s is %s; only a finished campaign "+
				"has a settled set of failed hosts to retry", original.Name, original.State),
		}
	}
	picked := []Target{}
	for _, target := range targets {
		if target.State == TargetFailed || (includeUnknown && target.State == TargetUnknown) {
			picked = append(picked, target)
		}
	}
	if len(picked) == 0 {
		what := "failed"
		if includeUnknown {
			what = "failed or ended unknown"
		}
		return nil, &RetryError{
			Code:   CodeNothingToRetry,
			Reason: fmt.Sprintf("no host of the campaign %s %s; there is nothing to retry", original.Name, what),
		}
	}
	return picked, nil
}

// RetryName is the name a retry is ordered under: the original's name
// with the word after it, so the list reads the pair as a pair.
func RetryName(original string) string {
	return original + " (retry)"
}
