package campaigns

import (
	"context"
	"encoding/json"

	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// takeCapacity asks the budgets whether the fleet can carry one more change.
//
// A campaign's concurrency limit and a budget answer two different questions.
// The first says how many hosts are to start at once within this one change;
// the second - how many changes the fleet, the site and the channel can
// carry. Ten campaigns of five hosts each fit within every campaign limit and
// are still fifty simultaneous mutations nobody decided on.
//
// It returns false when there is no capacity. That is not an error: the host
// goes back to the queue with a state that names the blocking budget - and
// will try again on the next pass.
func (o *Orchestrator) takeCapacity(ctx context.Context, campaign Campaign,
	target *Target, host *hosts.Host) (bool, error) {
	if o.budgets == nil {
		return true, nil
	}
	action := opspec.ActionType(campaign.ActionType)
	// A backup repository is a shared resource: a site budget knows nothing
	// about the backend half the fleet writes to at once.
	repository := campaignRepository(campaign)
	// The claimant is the campaign rather than the host: fairness divides the
	// tokens between changes, not between machines. Otherwise a campaign on a
	// thousand hosts would have a thousand times the share of a campaign on
	// one.
	refusal, err := o.budgets.Acquire(ctx, target.ID, "campaign:"+campaign.ID,
		budgets.ClassMaintenance, budgets.Needs(action, host.Site, repository))
	if err != nil {
		return false, err
	}
	if refusal.Empty() {
		return true, nil
	}

	// Silence is the worst answer here: a host standing still for no reason
	// looks like a forgotten host. The state and the message name the budget
	// and how much of it is taken.
	if target.State != TargetAwaitingBudget || target.ErrorCode != budgetCode(refusal) {
		if err := o.store.UpdateTarget(ctx, target.ID, TargetAwaitingBudget,
			budgetCode(refusal), refusal.Describe()); err != nil {
			return false, err
		}
	}
	target.State = TargetAwaitingBudget
	target.ErrorCode = budgetCode(refusal)
	return false, nil
}

// budgetCode names the obstacle with a code that can be filtered on.
func budgetCode(refusal budgets.Refusal) string {
	return "budget_" + refusal.Reason
}

// releaseCapacity gives the host's tokens back.
//
// A failure to release does not stop the campaign: the lease expires by
// itself anyway. Staying silent about it is not allowed, though - capacity
// held longer than necessary slows down the whole fleet.
func (o *Orchestrator) releaseCapacity(ctx context.Context, target *Target) {
	if o.budgets == nil {
		return
	}
	if err := o.budgets.Release(ctx, target.ID); err != nil {
		o.log.Error("the capacity of a campaign target was not released",
			"host_id", target.HostID, "err", err)
	}
}

// renewCapacity extends the leases of the hosts that are still working.
//
// A package transaction can take a quarter of an hour, and a lease is short:
// without renewal the capacity would come back to the pool halfway through
// the work and the system would start more than it can really carry.
func (o *Orchestrator) renewCapacity(ctx context.Context, targets []Target) {
	if o.budgets == nil {
		return
	}
	working := make([]string, 0, len(targets))
	for _, target := range targets {
		if !target.State.Finished() && !target.State.Waiting() {
			working = append(working, target.ID)
		}
	}
	if len(working) == 0 {
		return
	}
	if err := o.budgets.Renew(ctx, working); err != nil {
		o.log.Error("the capacity of a campaign was not renewed", "err", err)
	}
}

// campaignRepository takes the address of the backup repository out of the
// request.
//
// Empty means a campaign that does not touch a backend - not an unknown
// backend: operations outside the backup module have nothing to look for
// here.
func campaignRepository(campaign Campaign) string {
	if len(campaign.Payload) == 0 {
		return ""
	}
	var payload opspec.Payload
	if err := json.Unmarshal(campaign.Payload, &payload); err != nil {
		return ""
	}
	if payload.Backup == nil {
		return ""
	}
	return payload.Backup.Repository
}
