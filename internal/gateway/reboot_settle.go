package gateway

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ultherego/flotestro/internal/audit"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The settlement of a restart, and the record of every verification.
//
// A reboot is the operation whose verifier the host cannot run: the
// process that would read the host after the change goes down with the
// machine (opspec.Verifier.PanelSettled). The exit code of the scheduling
// says only that logind accepted the order - a host that never comes back
// produced exactly that exit code. So the agent withholds the result and
// the job stays open with its attempt; what settles it is what the panel
// sees with its own eyes: a session with a boot identifier other than the
// one the order ran under. A host that does not come back within the wait
// ends reboot_not_observed, written by the pass that reclaims the leases
// (jobs.RebootReturnGrace) rather than here - nothing arrives to settle it.
//
// The campaign's reboot step waits for the same proof on the host record
// (internal/campaigns/progress.go) and settles the target, never the job:
// the two read the same fact and neither writes the other's row, so one
// return cannot settle one job twice.

// settleReboot closes the jobs of a restart of the host once it is back.
func (s *AgentService) settleReboot(ctx context.Context, hostID, bootID string, fence jobs.Fence) {
	open, err := s.jobs.OpenTasksOfAction(ctx, hostID, string(opspec.ActionSystemReboot))
	if err != nil {
		s.log.Error("the jobs of the restart were not read", "host_id", hostID, "err", err)
		return
	}
	for _, job := range open {
		// A job without an attempt never reached the host: it waits in its
		// campaign wave or for its approval, and this return says nothing
		// about it. The reboot it orders is still to come.
		if job.AttemptID == "" {
			continue
		}
		verdict := rebootReturn(job.SessionBootID, bootID)
		if !verdict.Returned {
			s.log.Debug("the host is back on the boot the restart was ordered under",
				"host_id", hostID, "job_id", job.JobID, "boot_id", bootID)
			continue
		}
		s.closeReboot(ctx, hostID, job, verdict, fence)
	}
}

// rebootVerdict is what the panel can say about a restart from the boot
// identifier a session brought: whether the host really came back from it,
// and the observation that goes on the attempt.
type rebootVerdict struct {
	Returned bool
	Expected string
	Observed string
}

// rebootReturn compares the boot the order ran under with the boot the
// host is on now.
//
// Only a different, non-empty identifier proves a restart. An agent that
// reconnected without one - a crashed agent, a restarted service, a
// session dropped by the network - is on the same boot and proves
// nothing; an order whose boot the panel never recorded proves nothing
// either, and unknown is not a success. Both keep waiting, and the wait
// ends in reboot_not_observed rather than in a job that says the host
// restarted because it said hello.
func rebootReturn(orderedUnder, now string) rebootVerdict {
	ordered, current := bootIdentifier(orderedUnder), bootIdentifier(now)
	verdict := rebootVerdict{
		Expected: "a boot identifier other than " + orDash(orderedUnder),
		Observed: orDash(now),
	}
	if ordered == "" || current == "" || ordered == current {
		return verdict
	}
	verdict.Returned = true
	return verdict
}

// bootIdentifier reduces a boot identifier to what two of them are
// compared by: the journal writes it without dashes and the kernel with
// them, and the same boot must not read as two.
func bootIdentifier(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
}

// orDash names a value that may be missing without leaving an empty word
// in the operator's sentence.
func orDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

// closeReboot writes the result of a restart that was observed: the job
// succeeds, and the verification on the attempt says what proved it.
func (s *AgentService) closeReboot(ctx context.Context, hostID string,
	job jobs.OpenTask, verdict rebootVerdict, fence jobs.Fence) {
	message := "the host came back with boot identifier " + verdict.Observed
	accepted, err := s.jobs.RecordResult(ctx, job.JobID, job.AttemptID, jobs.Result{
		Status: "succeeded", Message: message,
		Verification: verificationJSON(&agentv1.Verification{
			Verifier: string(opspec.VerifierReboot), Verified: true,
			Expected: verdict.Expected, Observed: verdict.Observed,
		}),
	}, jobs.StateSucceeded, fence)
	if err != nil {
		s.log.Error("the result of the restart was not written",
			"host_id", hostID, "job_id", job.JobID, "err", err)
		return
	}
	// The job was settled before this return - the wait ran out, an
	// operator canceled it - and the settlement stands. The attempt keeps
	// the record; nothing is claimed here that was not written.
	if !accepted {
		s.log.Info("the restart was settled before the host came back",
			"host_id", hostID, "job_id", job.JobID, "boot_id", verdict.Observed)
		return
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "system.reboot", TargetType: "job", TargetID: job.JobID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"state": string(jobs.StateSucceeded), "message": message,
			"boot_id": verdict.Observed, "previous_boot_id": job.SessionBootID,
		},
	})
	s.log.Info("the restart was settled by the return of the host",
		"host_id", hostID, "job_id", job.JobID, "boot_id", verdict.Observed)
}

// verificationJSON writes the host's reading of itself after a change the
// way it arrived. The observation carries a state word, a digest or a
// version - never the content of a file and never a secret - so it is
// stored as it comes; an operation that reported none stores none, which
// is not the same as one that verified nothing.
func verificationJSON(verification *agentv1.Verification) json.RawMessage {
	if verification == nil {
		return nil
	}
	encoded, err := json.Marshal(map[string]any{
		"verifier": verification.GetVerifier(),
		"verified": verification.GetVerified(),
		"expected": verification.GetExpected(),
		"observed": verification.GetObserved(),
		"reason":   verification.GetReason(),
	})
	if err != nil {
		return nil
	}
	return encoded
}
