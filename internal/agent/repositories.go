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

// CollectRepositories reads the package sources visible on the host.
//
// Without root: the source files are public. The exception is a source with a
// password, which the panel itself gave root-only permissions - such a source
// stays on the list with a reason instead of disappearing from it.
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
	// The password is fetched only now, right before the write. The value lives
	// for a moment in the memory of the agent and of the helper - it is not in
	// the envelope of the task, in the journal or in the result. Only the name of
	// the secret stays in the source file.
	if !payload.PasswordSecret.Empty() && !payload.Remove {
		if e.secrets == nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError,
				"the agent has no connection through which a secret could be fetched")
		}
		value, err := e.secrets(callCtx, task.GetTaskId(),
			payload.PasswordSecret.Name, payload.PasswordSecret.Version)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPrecondition,
				"the secret "+payload.PasswordSecret.Name+" was not fetched: "+err.Error())
		}
		request.Password = value
		request.SecretName = payload.PasswordSecret.Name
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
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
