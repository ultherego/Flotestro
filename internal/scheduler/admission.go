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
//
// An interface rather than the store itself: the decision is to be checked
// without a database, and the scheduler needs the answer, not the tables.
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

// admission decides, task by task, whether the fleet has room for it.
//
// A campaign asks the same question for every one of its hosts. A task
// ordered by hand used to walk past it: fifty restarts clicked host by host
// were fifty mutations nobody admitted, and the limit the fleet decided on
// held only for those who went through a campaign.
type admission struct {
	budgets Budgets
	waits   WaitRecorder
	log     *slog.Logger
	gateway string
}

// admit asks the budgets whether the task can start now.
//
// False is not an error: the task stays in the queue as it was, with the
// budget that had no room written next to it, and asks again on the next
// pass. The wait itself does the rest - the budgets promote a claimant by
// how long it has waited, so a task refused for its fair share stops being
// bound by the share after the promotion age of its class.
func (a admission) admit(ctx context.Context, candidate jobs.Candidate) (bool, error) {
	job := candidate.Job
	// A campaign's task and a fan-out's task already hold their tokens: the
	// orchestrator took them for the target before it created the job, and
	// the fan-out took its reads before it ordered them. Asking once more
	// here would count the same work twice.
	if job.CampaignID != nil || job.FanoutID != nil || a.budgets == nil {
		return true, nil
	}

	action := opspec.ActionType(job.ActionType)
	needs := budgets.Needs(action, candidate.Site, repositoryOf(job.Payload))
	class := budgets.JobClass(action, job.CreatedBy, budgets.Class(job.BudgetClass))
	// The owner is the job, so an attempt that comes back to the queue and
	// asks again replaces its own grant rather than adding to it. The
	// claimant is the one who ordered the work: that is what the fair share
	// is divided between.
	refusal, err := a.budgets.Acquire(ctx, budgets.JobOwner(job.ID),
		budgets.JobClaimant(job.CreatedBy), class, needs)
	if err != nil {
		return false, err
	}
	if refusal.Empty() {
		return true, nil
	}

	// Silence is the worst answer here: a task standing in the queue with
	// nothing said looks like a forgotten task. The reason is written once
	// per change, not once per pass.
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

// release gives the task's tokens back. A failure here does not stop
// anything - the lease expires by itself - but it is not kept quiet either:
// capacity held longer than needed slows the whole fleet down.
func (a admission) release(ctx context.Context, jobID string) {
	if a.budgets == nil {
		return
	}
	if err := a.budgets.Release(ctx, budgets.JobOwner(jobID)); err != nil {
		a.log.Error("the capacity of a task was not released", "job_id", jobID, "err", err)
	}
}

// untaken lists the admitted tasks that the lease did not reach: taken by
// another gateway, canceled or expired between the decision and the
// lease. Their tokens have to go back, because nothing will run under them.
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

// repositoryOf reads the backup repository named in a task's payload. An
// unreadable payload names no repository; the envelope builder refuses the
// task for the same reason a moment later.
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
