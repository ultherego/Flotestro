package gateway

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// settleAgentUpgrade closes the jobs of an agent replacement once the agent is
// back.
func (s *AgentService) settleAgentUpgrade(ctx context.Context,
	hostID, version string, fence jobs.Fence) {
	jobsOpen, err := s.jobs.OpenTasksOfAction(ctx, hostID, string(opspec.ActionAgentUpgrade))
	if err != nil {
		s.log.Error("the jobs of the agent replacement were not read", "host_id", hostID, "err", err)
		return
	}
	for _, job := range jobsOpen {
		target := targetVersion(job.Payload)
		if target == "" {
			continue
		}
		// A job without an attempt never reached the host: it waits in its campaign
		// wave, or for its approval.
		if job.AttemptID == "" {
			continue
		}
		if target != version {
			// The host is back, but not in this version: the transaction went through
			// and the host works, only not the way it was ordered.
			s.closeUpgrade(ctx, hostID, job, jobs.StateFailed, "agent_version_mismatch",
				fmt.Sprintf("the host came back in version %s, expected %s", version, target), fence)
			continue
		}
		s.closeUpgrade(ctx, hostID, job, jobs.StateSucceeded, "",
			"the agent came back in version "+version, fence)
		// The replacement is confirmed, so the host may drop what it kept for
		// a return. Until this order runs, the way back stays.
		s.releaseKeptArtefact(ctx, hostID, version, job.JobID)
	}
}

// releaseKeptArtefact orders the host to drop the package file it kept so that
// it could go back. Nothing is installed and nothing is fetched.
func (s *AgentService) releaseKeptArtefact(ctx context.Context, hostID, version, jobID string) {
	tx, err := s.jobs.Pool().Begin(ctx)
	if err != nil {
		s.log.Error("the release of the kept artefact was not ordered",
			"host_id", hostID, "job_id", jobID, "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := s.jobs.Create(ctx, tx, jobs.Spec{
		HostID: hostID,
		Action: opspec.ActionAgentUpgrade,
		Payload: opspec.Payload{AgentUpgrade: &opspec.AgentUpgradePayload{
			TargetVersion: version, ReleaseRollback: true,
		}},
		// The key binds the order to the replacement it closes: a second pass of
		// the settlement does not create a second task.
		IdempotencyKey: "agent-upgrade-release:" + jobID,
		CreatedBy:      "system",
	}); err != nil {
		s.log.Error("the release of the kept artefact was not ordered",
			"host_id", hostID, "job_id", jobID, "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.log.Error("the release of the kept artefact was not ordered",
			"host_id", hostID, "job_id", jobID, "err", err)
	}
}

// closeUpgrade writes the result of a job of an agent replacement.
func (s *AgentService) closeUpgrade(ctx context.Context, hostID string,
	job jobs.OpenTask, state jobs.State, code, message string, fence jobs.Fence) {
	status := "succeeded"
	if state != jobs.StateSucceeded {
		status = "failed"
	}
	if _, err := s.jobs.RecordResult(ctx, job.JobID, job.AttemptID, jobs.Result{
		Status: status, ErrorCode: code, Message: message,
	}, state, fence); err != nil {
		s.log.Error("the result of the agent replacement was not written",
			"host_id", hostID, "job_id", job.JobID, "err", err)
		return
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "agent.upgrade", TargetType: "job", TargetID: job.JobID,
		Outcome: audit.OutcomeSuccess,
		Detail:  map[string]any{"state": string(state), "message": message},
	})
	s.log.Info("the agent replacement was settled",
		"host_id", hostID, "job_id", job.JobID, "state", state, "message", message)
}

// targetVersion reads the version from the payload of a job.
func targetVersion(payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	var content opspec.Payload
	if err := json.Unmarshal(payload, &content); err != nil {
		return ""
	}
	if content.AgentUpgrade == nil {
		return ""
	}
	return content.AgentUpgrade.TargetVersion
}
