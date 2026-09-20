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

// settleReboot closes the jobs of a restart of the host once it is back.
func (s *AgentService) settleReboot(ctx context.Context, hostID, bootID string, fence jobs.Fence) {
	open, err := s.jobs.OpenTasksOfAction(ctx, hostID, string(opspec.ActionSystemReboot))
	if err != nil {
		s.log.Error("the jobs of the restart were not read", "host_id", hostID, "err", err)
		return
	}
	for _, job := range open {
		// A job without an attempt never reached the host: it waits in its campaign
		// wave or for its approval, and this return says nothing about it.
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
// identifier a session brought: whether the host really came back from it, and
// the observation that goes on the attempt.
type rebootVerdict struct {
	Returned bool
	Expected string
	Observed string
}

// rebootReturn compares the boot the order ran under with the boot the host is
// on now.
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

// bootIdentifier reduces a boot identifier to what two of them are compared
// by: the journal writes it without dashes and the kernel with them, and the
// same boot must not read as two.
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
	// The job was settled before this return - the wait ran out, an operator
	// canceled it - and the settlement stands.
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

// verificationExpected says whether this operation's result has to carry the
// host's own reading. An operation with no verifier has nothing to read, and
// the two the panel settles - a restart, an agent upgrade - are confirmed by
// the host coming back rather than by anything in the result.
func verificationExpected(action opspec.ActionType) bool {
	verifier := action.Verifier()
	return verifier != opspec.VerifierNone && !verifier.PanelSettled()
}

// verificationJSON writes the host's reading of itself after a change the way
// it arrived.
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
