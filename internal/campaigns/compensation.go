package campaigns

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/opspec"
)

// A compensation is a new campaign that runs the declared reverse of a
// finished one on the hosts it changed. The document calls the way back
// for most operations exactly that: not an undo of the record, but a new
// plan and a new approval that neutralise the effect while the history
// stays. The rules below say when such a campaign may be ordered; the
// engine then writes a compensate step on the original's targets as the
// reverse change runs on their hosts.

// The codes a refused compensation answers with. A refusal without a code
// is a sentence the panel cannot act on; a code without a sentence is a
// riddle for the operator.
const (
	// CodeCompensatedCampaignNotSettled: the original still runs, waits or
	// is paused, so the set of hosts it changed is not final yet.
	CodeCompensatedCampaignNotSettled = "compensated_campaign_not_settled"
	// CodeNotReverseOperation: the operation ordered is not the declared
	// reverse of the original's operation.
	CodeNotReverseOperation = "not_reverse_operation"
	// CodeNothingToCompensate: no host of the original changed.
	CodeNothingToCompensate = "nothing_to_compensate"
	// CodeCompensationTargetUnchanged: the order names a host that was not
	// changed by the original.
	CodeCompensationTargetUnchanged = "compensation_target_unchanged"
)

// CompensationError is a refusal of a compensation order: a stable code
// and the reason in words.
type CompensationError struct {
	Code   string
	Reason string
}

func (e *CompensationError) Error() string { return e.Reason }

// CompensationCode returns the code of a refused compensation, or an empty
// string for any other error.
func CompensationCode(err error) string {
	var refusal *CompensationError
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

// CheckCompensation says whether a campaign running the given operation on
// the given hosts may be ordered as the compensation of the original.
//
// The original has to be settled: completed, failed or canceled. A paused
// campaign can be resumed and a running one is still changing hosts, so
// the set of changed hosts is not final - a compensation ordered against
// it would race the change it undoes. A canceled campaign counts: the
// hosts it changed before the stop stay changed, and that is exactly what
// the operator wants back.
//
// The operation has to be the declared reverse of the original's, from
// the registry's table: a campaign that "compensates" a file write with a
// service restart is not a compensation, whatever its name says.
//
// Every host of the order has to be one the original changed. A host that
// did not change - skipped, ineligible, refused by its plan, or one whose
// change never landed - has nothing to compensate, and running the reverse
// on it would change it for the first time.
func CheckCompensation(original Campaign, action opspec.ActionType, changed []Target, hosts []string) error {
	if !original.State.Terminal() {
		return &CompensationError{
			Code: CodeCompensatedCampaignNotSettled,
			Reason: fmt.Sprintf("the campaign %s is %s; only a completed, failed or canceled campaign "+
				"has a settled set of changed hosts to compensate", original.Name, original.State),
		}
	}
	reverse, ok := opspec.ReverseAction(opspec.ActionType(original.ActionType))
	if !ok {
		return &CompensationError{
			Code: CodeNotReverseOperation,
			Reason: fmt.Sprintf("the operation %s of the campaign %s declares no reverse the panel runs in bulk",
				original.ActionType, original.Name),
		}
	}
	if action != reverse {
		return &CompensationError{
			Code:   CodeNotReverseOperation,
			Reason: fmt.Sprintf("the reverse of %s is %s, not %s", original.ActionType, reverse, action),
		}
	}
	if len(changed) == 0 {
		return &CompensationError{
			Code:   CodeNothingToCompensate,
			Reason: fmt.Sprintf("no host of the campaign %s changed; there is nothing to compensate", original.Name),
		}
	}
	changedHosts := map[string]bool{}
	for _, target := range changed {
		changedHosts[target.HostID] = true
	}
	var unchanged []string
	for _, host := range hosts {
		if !changedHosts[host] {
			unchanged = append(unchanged, host)
		}
	}
	if len(unchanged) > 0 {
		sort.Strings(unchanged)
		return &CompensationError{
			Code: CodeCompensationTargetUnchanged,
			Reason: fmt.Sprintf("%d hosts were not changed by the campaign %s and have nothing to compensate: %s",
				len(unchanged), original.Name, strings.Join(unchanged, ", ")),
		}
	}
	return nil
}

// ChangedTargets returns the targets of a campaign whose change landed on
// the host: the ones that succeeded, and the ones that failed only after
// the change - in the reboot or the verification - which the execute step
// records as succeeded. A host whose change failed, or whose session broke
// mid-task, is left out: what it holds is unknown, and unknown is not
// "unchanged" - it is a question for the operator on that host, not for a
// campaign. A host that reported no change is left out too: its change
// step ran to the end and changed nothing, so there is nothing to bring
// back. A target from before the step ledger existed has no execute row;
// its state alone decides.
func (s *Store) ChangedTargets(ctx context.Context, campaignID string) ([]Target, error) {
	const query = `
		select t.id, t.campaign_id, t.host_id, coalesce(h.hostname, ''), t.wave, t.position,
		       t.state, t.job_id, t.plan_job_id, t.reboot_job_id, t.health_job_id,
		       coalesce(t.boot_id_before, ''),
		       coalesce(t.error_code, ''), coalesce(t.message, ''), t.started_at, t.finished_at
		  from campaign_targets t
		  left join hosts h on h.id = t.host_id
		 where t.campaign_id = $1 and ` + changedTargetCondition + `
		 order by t.wave, t.position`
	rows, err := s.pool.Query(ctx, query, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	targets := []Target{}
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.CampaignID, &t.HostID, &t.Hostname, &t.Wave, &t.Position,
			&t.State, &t.JobID, &t.PlanJobID, &t.RebootJobID, &t.HealthJobID, &t.BootIDBefore,
			&t.ErrorCode, &t.Message, &t.StartedAt, &t.FinishedAt); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// compensatedTarget finds the target of the original campaign for the
// host, on the caller's connection: the compensate step is written next
// to the compensating target's transition, in the same transaction. The
// second result is false when the original has no target for the host -
// the order was checked against the original's snapshot, so that means the
// host row is gone, not that the check was skipped.
func (s *Store) compensatedTarget(ctx context.Context, q stepQuerier, campaignID, hostID string) (Target, bool, error) {
	const query = `
		select id, campaign_id, host_id, wave, position, state
		  from campaign_targets
		 where campaign_id = $1 and host_id = $2`
	var target Target
	err := q.QueryRow(ctx, query, campaignID, hostID).Scan(&target.ID, &target.CampaignID,
		&target.HostID, &target.Wave, &target.Position, &target.State)
	if errors.Is(err, pgx.ErrNoRows) {
		return Target{}, false, nil
	}
	if err != nil {
		return Target{}, false, err
	}
	return target, true, nil
}

// compensationOutcome maps the end of the compensating target onto the
// compensate step of the original's target. Only a change that succeeded
// compensates; everything else leaves the original host as it was, and the
// step says why. The reason is never empty for a step that did not
// succeed - the table refuses one, and rightly: a compensation that
// silently did not happen is worse than none.
func compensationOutcome(state TargetState, code, message string) (StepState, string) {
	reason := stepReason(code, message)
	switch state {
	case TargetSucceeded:
		return StepSucceeded, reason
	case TargetNoChange:
		// The reverse found nothing to do: the host already holds the state
		// the compensation was to bring back, and the original is compensated.
		return StepSucceeded, orReason(reason, "the host already held the state the compensation brings back")
	case TargetSkipped, TargetIneligible, TargetExcluded:
		return StepSkipped, orReason(reason, "the compensating host was "+string(state))
	case TargetCanceled:
		return StepCanceled, orReason(reason, "the compensating campaign was canceled")
	default:
		return StepFailed, orReason(reason, "the compensating change ended "+string(state))
	}
}

func orReason(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}
