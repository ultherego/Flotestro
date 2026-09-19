package scheduler

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Budgets is the part of the capacity budgets the scheduler asks.
type Budgets interface {
	Acquire(ctx context.Context, owner, claimant string, class budgets.Class,
		needs []budgets.Need) (budgets.Refusal, error)
	Release(ctx context.Context, owner string) error
	Renew(ctx context.Context, owners []string) error
}

// WaitRecorder writes down why a queued task was not taken.
type WaitRecorder interface {
	SetWaitReason(ctx context.Context, jobID, reason string) error
}

// Topology tells where the hosts of the queued tasks stand: the failure domain
// the budgets are keyed by, which the queue does not carry.
type Topology interface {
	FailureDomains(ctx context.Context, hostIDs []string) (map[string]string, error)
}

// admission decides, task by task, whether the fleet has room for it. A
// campaign asks the same question for every one of its hosts.
type admission struct {
	budgets  Budgets
	topology Topology
	waits    WaitRecorder
	log      *slog.Logger
	gateway  string
}

// failureDomains reads the domains of the hosts behind the candidates that
// will be asked about, once per pass.
func (a admission) failureDomains(ctx context.Context, candidates []jobs.Candidate) (map[string]string, error) {
	if a.topology == nil || a.budgets == nil {
		return map[string]string{}, nil
	}
	hostIDs := make([]string, 0, len(candidates))
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if candidate.Job.CampaignID != nil || candidate.Job.FanoutID != nil || seen[candidate.Job.HostID] {
			continue
		}
		seen[candidate.Job.HostID] = true
		hostIDs = append(hostIDs, candidate.Job.HostID)
	}
	if len(hostIDs) == 0 {
		return map[string]string{}, nil
	}
	return a.topology.FailureDomains(ctx, hostIDs)
}

// admit asks the budgets whether the task can start now.
func (a admission) admit(ctx context.Context, candidate jobs.Candidate, domain string) (bool, error) {
	job := candidate.Job
	// A campaign's task and a fan-out's task already hold their tokens: the
	// orchestrator took them for the target before it created the job, and the
	// fan-out took its reads before it ordered them.
	if job.CampaignID != nil || job.FanoutID != nil || a.budgets == nil {
		return true, nil
	}

	action := opspec.ActionType(job.ActionType)
	where := budgets.Topology{Site: candidate.Site, FailureDomain: domain, Gateway: a.gateway}
	needs := budgets.Needs(action, where, repositoryOf(job.Payload))
	class := budgets.JobClass(action, job.CreatedBy, budgets.Class(job.BudgetClass))
	// The owner is the job, so an attempt that comes back to the queue and asks
	// again replaces its own grant rather than adding to it.
	refusal, err := a.budgets.Acquire(ctx, budgets.JobOwner(job.ID),
		budgets.JobClaimant(job.CreatedBy), class, needs)
	if err != nil {
		return false, err
	}
	if refusal.Empty() {
		return true, nil
	}

	// Silence is the worst answer here: a task standing in the queue with nothing
	// said looks like a forgotten task.
	reason := budgets.WaitReason(refusal)
	if job.WaitReason != reason {
		if err := a.waits.SetWaitReason(ctx, job.ID, reason); err != nil {
			return false, err
		}
		metrics.JobDispatch.Inc("awaiting_budget", a.gateway)
		a.log.Info("the task waits for capacity",
			"job_id", job.ID, "host_id", job.HostID, "action", job.ActionType,
			"class", string(class), "budget", refusal.Key, "reason", refusal.Describe())
	}
	return false, nil
}

// release gives the task's tokens back.
func (a admission) release(ctx context.Context, jobID string) {
	if a.budgets == nil {
		return
	}
	if err := a.budgets.Release(ctx, budgets.JobOwner(jobID)); err != nil {
		a.log.Error("the capacity of a task was not released", "job_id", jobID, "err", err)
	}
}

// untaken lists the admitted tasks that the lease did not reach: taken by
// another gateway, canceled or expired between the decision and the lease.
func untaken(admitted []string, leased []jobs.LeasedJob) []string {
	taken := make(map[string]bool, len(leased))
	for _, item := range leased {
		taken[item.Job.ID] = true
	}
	var missing []string
	for _, id := range admitted {
		if !taken[id] {
			missing = append(missing, id)
		}
	}
	return missing
}

// repositoryOf reads the backup repository named in a task's payload.
func repositoryOf(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var payload opspec.Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	return budgets.RepositoryOf(payload)
}
