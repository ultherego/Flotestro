package campaigns

import (
	"context"
	"encoding/json"

	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// takeCapacity asks the budgets whether the fleet can carry one more change. A
// campaign's concurrency limit and a budget answer two different questions.
func (o *Orchestrator) takeCapacity(ctx context.Context, campaign Campaign,
	target *Target, host *hosts.Host) (bool, error) {
	if o.budgets == nil {
		return true, nil
	}
	action := opspec.ActionType(campaign.ActionType)
	// A backup repository is a shared resource: a site budget knows nothing
	// about the backend half the fleet writes to at once.
	repository := campaignRepository(campaign)
	// The host's place in the fleet names the budgets beyond the fleet's own:
	// site and failure domain come from the panel, the gateway from the session.
	gateway, err := o.budgets.SessionGateway(ctx, host.ID)
	if err != nil {
		return false, err
	}
	where := budgets.Topology{Site: host.Site, FailureDomain: host.FailureDomain, Gateway: gateway}
	// The claimant is the campaign rather than the host: fairness divides the
	// tokens between changes, not between machines.
	refusal, err := o.budgets.AcquireFenced(ctx, target.ID, "campaign:"+campaign.ID,
		budgets.ClassMaintenance, budgets.Needs(action, where, repository), target.ClaimToken)
	if err != nil {
		return false, err
	}
	if refusal.Empty() {
		return true, nil
	}

	// Silence is the worst answer here: a host standing still for no reason looks
	// like a forgotten host.
	if target.State != TargetAwaitingBudget || target.ErrorCode != budgetCode(refusal) {
		if err := o.store.UpdateTarget(ctx, target, TargetAwaitingBudget,
			budgetCode(refusal), refusal.Describe()); err != nil {
			return false, err
		}
	}
	return false, nil
}

// budgetCode names the obstacle with a code that can be filtered on.
func budgetCode(refusal budgets.Refusal) string {
	return "budget_" + refusal.Reason
}

// releaseCapacity gives the host's tokens back. A failure to release does not
// stop the campaign: the lease expires by itself anyway.
func (o *Orchestrator) releaseCapacity(ctx context.Context, target *Target) {
	if o.budgets == nil {
		return
	}
	// The release names the claim token: a runner that lost the target to another
	// one releases nothing, because the tokens are the other runner's now.
	if err := o.budgets.ReleaseFenced(ctx, target.ID, target.ClaimToken); err != nil {
		o.log.Error("the capacity of a campaign target was not released",
			"host_id", target.HostID, "err", err)
	}
}

// renewCapacity extends the leases of the hosts that are still working.
func (o *Orchestrator) renewCapacity(ctx context.Context, targets []Target) {
	if o.budgets == nil {
		return
	}
	// Every renewal names the claim token the runner reads on the target;
	// a lease that moved to another runner is left alone.
	working := make([]budgets.Fenced, 0, len(targets))
	for _, target := range targets {
		if !target.State.Finished() && !target.State.Waiting() {
			working = append(working, budgets.Fenced{Owner: target.ID, Token: target.ClaimToken})
		}
	}
	if len(working) == 0 {
		return
	}
	if err := o.budgets.RenewFenced(ctx, working); err != nil {
		o.log.Error("the capacity of a campaign was not renewed", "err", err)
	}
}

// campaignRepository takes the address of the backup repository out of the
// request.
func campaignRepository(campaign Campaign) string {
	if len(campaign.Payload) == 0 {
		return ""
	}
	var payload opspec.Payload
	if err := json.Unmarshal(campaign.Payload, &payload); err != nil {
		return ""
	}
	return budgets.RepositoryOf(payload)
}
