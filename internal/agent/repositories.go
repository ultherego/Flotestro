package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// CollectRepositories reads the package sources visible on the host. Without
// root: the source files are public.
func CollectRepositories(manager string) packages.RepositoryImage {
	return packages.ReadRepositories(manager)
}

// applyRepository performs the write of a package source.
func (e *TaskExecutor) applyRepository(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.RepositoryPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the package source payload is missing")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	request := &helperv1.RepositoryRequest{
		Id: payload.ID, Name: payload.Name, Url: payload.URL,
		Suites: payload.Suites, Components: payload.Components,
		Architectures: payload.Architectures, Enabled: payload.Enabled,
		Priority: int32(payload.Priority), GpgKey: payload.GPGKey,
		AllowUnsigned: payload.AllowUnsigned, Username: payload.Username,
		Remove: payload.Remove,
	}
	// The password is fetched only now, right before the write, and through the
	// fetch that keeps the receipt: the helper refuses bytes no receipt vouches
	// for, and asking the store directly discarded the receipt.
	if !payload.PasswordSecret.Empty() && !payload.Remove {
		value, _, refusal := e.fetchSecretWithReceipt(callCtx, task, *payload.PasswordSecret)
		if refusal != nil {
			return refusal
		}
		request.Password = value
		request.SecretName = payload.PasswordSecret.Name
	}

	response, err := e.callHelper(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_Repository{Repository: request},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetRepositoryResult()
	details := &agentv1.RepositoryResult{
		Snapshot:          result.GetSnapshot(),
		Message:           result.GetMessage(),
		GpgKeyFingerprint: result.GetGpgKeyFingerprint(),
		RolledBack:        result.GetRolledBack(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.RepositoryResult = details
		return refused
	}

	// The picture of the sources after the change is assembled by the helper,
	// because only it sees the files it gave root-only permissions itself.
	if len(details.Snapshot) == 0 {
		snapshot := CollectRepositories(e.packageManager())
		if encoded, err := json.Marshal(snapshot); err == nil {
			details.Snapshot = encoded
		}
	}
	return &agentv1.TaskResult{
		TaskId:           task.GetTaskId(),
		Status:           agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:          result.GetMessage(),
		RepositoryResult: details,
	}
}

// packageManager returns the name of the manager of the host or an empty
// string.
func (e *TaskExecutor) packageManager() string {
	manager, err := packages.Detect()
	if err != nil {
		return ""
	}
	return manager.Name()
}
