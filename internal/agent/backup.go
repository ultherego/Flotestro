package agent

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/opspec"
)

// BackupState describes the backup tools visible on the host.
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

	// The credentials are fetched only now, right before the operation.
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

	response, err := e.callHelper(callCtx, &helperv1.HelperRequest{
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
		// What the helper counted under the restore target travels with the result:
		// the agent itself cannot read a directory root wrote, and the verifier
		// below needs an answer rather than a refusal.
		TargetEntries: result.GetTargetEntries(),
		TargetRead:    result.GetTargetRead(),
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

// fetchSecret fetches the value from the store right before the operation. The
// receipt comes with it; a caller that writes the bytes into a file has to hand
// it to the helper.
func (e *TaskExecutor) fetchSecret(ctx context.Context, task *agentv1.TaskEnvelope,
	reference opspec.SecretRef) ([]byte, *agentv1.TaskResult) {
	value, _, result := e.fetchSecretWithReceipt(ctx, task, reference)
	return value, result
}

// fetchSecretWithReceipt is the same fetch for the caller that needs the
// receipt as well.
func (e *TaskExecutor) fetchSecretWithReceipt(ctx context.Context, task *agentv1.TaskEnvelope,
	reference opspec.SecretRef) ([]byte, *helperv1.SecretReceipt, *agentv1.TaskResult) {
	if e.secrets == nil {
		return nil, nil, rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError,
			"the agent has no connection through which a secret could be fetched")
	}
	// The panel issues one lease per task and redeems it once: a task that reads
	// the repository before the change, writes it and reads it again to verify
	// asks for the same secret three times, and the second ask would be refused.
	if held, found := e.taskSecret(task.GetTaskId(), reference); found {
		return held.value, held.receipt, nil
	}
	value, receipt, err := e.secrets(ctx, task.GetTaskId(), reference.Name, reference.Version)
	if err != nil {
		// The reason for the refusal is the content of the result; the value is
		// not in it.
		return nil, nil, rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPrecondition,
			"the secret "+reference.Name+" was not fetched: "+err.Error())
	}
	e.keepTaskSecret(task.GetTaskId(), reference, fetchedSecret{value: value, receipt: receipt})
	return value, receipt, nil
}

// taskReceipts are the receipts of every secret this task has fetched, in a
// stable order. The helper refuses the bytes of a secret that no receipt
// vouches for, and a task that fetched none sends none.
func (e *TaskExecutor) taskReceipts(taskID string) []*helperv1.SecretReceipt {
	e.secretsMu.Lock()
	defer e.secretsMu.Unlock()
	prefix := taskID + "\x00"
	var receipts []*helperv1.SecretReceipt
	for key, held := range e.taskSecrets {
		if strings.HasPrefix(key, prefix) && held.receipt != nil {
			receipts = append(receipts, held.receipt)
		}
	}
	sort.Slice(receipts, func(i, j int) bool {
		return receipts[i].GetSecretName() < receipts[j].GetSecretName()
	})
	return receipts
}

// callHelper sends a request with those receipts attached. Every consumer of a
// secret goes through here rather than remembering to carry them: the file
// write was the only one that did, and the repository password of a backup, its
// environment, a certificate's key and the password of a package repository
// each handed the helper bytes nobody had vouched for.
func (e *TaskExecutor) callHelper(ctx context.Context, request *helperv1.HelperRequest,
	timeout time.Duration) (*helperv1.HelperResponse, error) {
	request.SecretReceipts = e.taskReceipts(request.GetTaskId())
	return e.callHelper(ctx, request, timeout)
}

// secretKey names one secret of one task: the same name and version asked
// for twice within a task is the same lease.
func secretKey(taskID string, reference opspec.SecretRef) string {
	return taskID + "\x00" + reference.Name + "\x00" + strconv.Itoa(int(reference.Version))
}

// taskSecret answers a value already fetched for this task.
func (e *TaskExecutor) taskSecret(taskID string, reference opspec.SecretRef) (fetchedSecret, bool) {
	e.secretsMu.Lock()
	defer e.secretsMu.Unlock()
	held, found := e.taskSecrets[secretKey(taskID, reference)]
	return held, found
}

// keepTaskSecret remembers a value for the life of the task.
func (e *TaskExecutor) keepTaskSecret(taskID string, reference opspec.SecretRef, held fetchedSecret) {
	e.secretsMu.Lock()
	defer e.secretsMu.Unlock()
	if e.taskSecrets == nil {
		e.taskSecrets = map[string]fetchedSecret{}
	}
	e.taskSecrets[secretKey(taskID, reference)] = held
}

// forgetTaskSecrets drops what a finished task fetched.
func (e *TaskExecutor) forgetTaskSecrets(taskID string) {
	e.secretsMu.Lock()
	defer e.secretsMu.Unlock()
	prefix := taskID + "\x00"
	for key, held := range e.taskSecrets {
		if strings.HasPrefix(key, prefix) {
			for i := range held.value {
				held.value[i] = 0
			}
			delete(e.taskSecrets, key)
		}
	}
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
