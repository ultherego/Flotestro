package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/opspec"
)

// BackupState describes the backup tools visible on the host.
//
// This is everything that can be said about backups without credentials:
// whether the host has anything to make them with. The state of the repository
// - when the last copy succeeded and how much room it takes - needs a password,
// so it is an operation and not inventory.
type BackupState struct {
	Tools []BackupTool `json:"tools"`
	// Runbooks lists the scripts the administrator of the host made available to
	// the panel.
	Runbooks []string `json:"runbooks,omitempty"`
	// RunbooksKnown says whether the runbook directory could be read at all.
	RunbooksKnown bool   `json:"runbooks_known"`
	ObservedAt    string `json:"observed_at"`
}

// BackupTool describes one tool on the host.
type BackupTool struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
}

// CollectBackup reads what the host can make copies with.
func CollectBackup(ctx context.Context) BackupState {
	state := BackupState{ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, name := range []string{backup.ToolRestic, backup.ToolBorg} {
		adapter, err := backup.Select(name)
		if err != nil {
			continue
		}
		description := BackupTool{Name: name, Available: adapter.Available()}
		if description.Available {
			description.Version = adapter.Version(ctx)
		}
		state.Tools = append(state.Tools, description)
	}
	runbooks, known := backup.ListRunbooks()
	state.Runbooks = runbooks
	state.RunbooksKnown = known
	state.Tools = append(state.Tools, BackupTool{
		Name: backup.ToolRunbook, Available: len(runbooks) > 0,
	})
	return state
}

// applyBackup performs a backup operation.
func (e *TaskExecutor) applyBackup(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.BackupPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the backup payload is missing")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	operation := helperv1.BackupRequest_OPERATION_PLAN
	switch action {
	case opspec.ActionBackupRun:
		operation = helperv1.BackupRequest_OPERATION_RUN
	case opspec.ActionBackupVerify:
		operation = helperv1.BackupRequest_OPERATION_VERIFY
	case opspec.ActionBackupRestore:
		operation = helperv1.BackupRequest_OPERATION_RESTORE
	}

	request := &helperv1.BackupRequest{
		Operation: operation,
		Id:        payload.ID, Tool: payload.Tool, Repository: payload.Repository,
		Paths: payload.Paths, Excludes: payload.Excludes, Tags: payload.Tags,
		KeepLast: int32(payload.KeepLast), KeepDaily: int32(payload.KeepDaily),
		KeepWeekly: int32(payload.KeepWeekly), KeepMonthly: int32(payload.KeepMonthly),
		Prune: payload.Prune, Runbook: payload.Runbook,
		Initialize: payload.Initialize, ReadData: payload.ReadData,
		SnapshotId: payload.SnapshotID, Target: payload.Target,
		Include: payload.Include, Overwrite: payload.Overwrite,
		Plan: payload.Plan, PlanHash: payload.PlanHash,
	}

	// The credentials are fetched only now, right before the operation. They
	// live for a moment in the memory of the agent and of the helper - they are
	// not in the envelope of the task, in the journal or in the result.
	if !payload.PasswordSecret.Empty() {
		value, refusal := e.fetchSecret(callCtx, task, *payload.PasswordSecret)
		if refusal != nil {
			return refusal
		}
		request.Password = value
	}
	if len(payload.EnvSecrets) > 0 {
		request.Env = map[string][]byte{}
		for name, reference := range payload.EnvSecrets {
			value, refusal := e.fetchSecret(callCtx, task, reference)
			if refusal != nil {
				return refusal
			}
			request.Env[name] = value
		}
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		WantProgress:   action == opspec.ActionBackupRun,
		Action:         &helperv1.HelperRequest_Backup{Backup: request},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetBackupResult()
	details := &agentv1.BackupResult{
		State:    result.GetState(),
		Outcome:  result.GetOutcome(),
		Message:  result.GetMessage(),
		Plan:     result.GetPlan(),
		Verified: result.GetVerified(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.BackupResult = details
		return refused
	}
	return &agentv1.TaskResult{
		TaskId:       task.GetTaskId(),
		Status:       agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:      result.GetMessage(),
		BackupResult: details,
	}
}

// fetchSecret fetches the value from the store right before the operation.
func (e *TaskExecutor) fetchSecret(ctx context.Context, task *agentv1.TaskEnvelope,
	reference opspec.SecretRef) ([]byte, *agentv1.TaskResult) {
	if e.secrets == nil {
		return nil, rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError,
			"the agent has no connection through which a secret could be fetched")
	}
	value, err := e.secrets(ctx, task.GetTaskId(), reference.Name, reference.Version)
	if err != nil {
		// The reason for the refusal is the content of the result; the value is
		// not in it.
		return nil, rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPrecondition,
			"the secret "+reference.Name+" was not fetched: "+err.Error())
	}
	return value, nil
}

// backupJSON decodes the state of the repository from the result of the task.
func backupJSON(data []byte) (backup.State, bool) {
	var state backup.State
	if len(data) == 0 {
		return state, false
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, false
	}
	return state, true
}
