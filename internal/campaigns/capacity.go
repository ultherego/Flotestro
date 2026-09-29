package campaigns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

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

// errCapacityUnproven says the tokens of the hosts at work could not be
// renewed although no other runner holds them. The fleet stops counting those
// hosts against the budgets, so a pass that reads this starts nobody new until
// their leases are live again.
var errCapacityUnproven = errors.New("the capacity leases of the hosts at work are not live")

// leaseRenewer is the part of the capacity budgets a pass renews. It is an
// interface so the answer to a lost lease can be pinned without a database.
type leaseRenewer interface {
	RenewFenced(ctx context.Context, leases []budgets.Fenced) error
}

// holdCapacity renews the tokens of the hosts at work and says whether this
// pass may still start new ones. It returns ErrLeaseLost when the tokens carry
// another runner's claim: from that moment the campaign is that runner's and
// this pass writes nothing more.
func (o *Orchestrator) holdCapacity(ctx context.Context, campaign Campaign, targets []Target) (bool, error) {
	if o.budgets == nil {
		return true, nil
	}
	return capacityHolds(ctx, o.budgets, campaign, targets, o.log)
}

func capacityHolds(ctx context.Context, renewer leaseRenewer, campaign Campaign,
	targets []Target, log *slog.Logger) (bool, error) {
	err := renewCapacity(ctx, renewer, targets)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, errCapacityUnproven):
		log.Warn("the capacity of the hosts at work was not renewed; the campaign starts nobody new this pass",
			"campaign_id", campaign.ID, "err", err)
		return false, nil
	default:
		return false, err
	}
}

// renewCapacity extends the leases of the hosts that are still working.
func renewCapacity(ctx context.Context, renewer leaseRenewer, targets []Target) error {
	// Every renewal names the claim token the runner reads on the target;
	// a lease that moved to another runner is left alone.
	working := make([]budgets.Fenced, 0, len(targets))
	for _, target := range targets {
		if !target.State.Finished() && !target.State.Waiting() {
			working = append(working, budgets.Fenced{Owner: target.ID, Token: target.ClaimToken})
		}
	}
	if len(working) == 0 {
		return nil
	}
	err := renewer.RenewFenced(ctx, working)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, budgets.ErrFenceStale):
		// The tokens of these hosts carry another runner's claim, which only the
		// runner that adopted them could have written: this instance lost the
		// campaign and must not touch it again.
		return fmt.Errorf("%w: %w", ErrLeaseLost, err)
	default:
		// Nobody took the hosts, but their grants are not live and the fleet no
		// longer counts them, so no further host may be started over them.
		return fmt.Errorf("%w: %w", errCapacityUnproven, err)
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
