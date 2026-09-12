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
//
// An agent that replaces itself has no way of sending a result back: the
// process that carried the job out was replaced halfway. What settles the
// matter is therefore what the panel sees with its own eyes - the version
// reported at the new connection. The exit code of the package manager could
// be zero also when the host never came back.
func (s *AgentService) settleAgentUpgrade(ctx context.Context,
	hostID, version string) {
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
		if target != version {
			// The host is back, but not in this version: the transaction went
			// through and the host works, only not the way it was ordered.
			// That is a failure of the job rather than a failure of the
			// host.
			s.closeUpgrade(ctx, hostID, job, jobs.StateFailed, "agent_version_mismatch",
				fmt.Sprintf("the host came back in version %s, expected %s", version, target))
			continue
		}
		s.closeUpgrade(ctx, hostID, job, jobs.StateSucceeded, "",
			"the agent came back in version "+version)
	}
}

// closeUpgrade writes the result of a job of an agent replacement.
func (s *AgentService) closeUpgrade(ctx context.Context, hostID string,
	job jobs.OpenTask, state jobs.State, code, message string) {
	status := "succeeded"
	if state != jobs.StateSucceeded {
		status = "failed"
	}
	if _, err := s.jobs.RecordResult(ctx, job.JobID, job.AttemptID, jobs.Result{
		Status: status, ErrorCode: code, Message: message,
	}, state); err != nil {
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
