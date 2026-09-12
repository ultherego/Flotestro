package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/opspec"
)

// fileProbe reads the state of the files managed by the panel.
var fileProbe func(context.Context) (files.Snapshot, error)

// SetFileProbe points at the function that reads the state of the files.
func SetFileProbe(probe func(context.Context) (files.Snapshot, error)) {
	fileProbe = probe
}

// ProbeFiles reads the state of the managed files on the host.
func (e *TaskExecutor) ProbeFiles(ctx context.Context) (files.Snapshot, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_File{
			File: &helperv1.FileRequest{Operation: helperv1.FileRequest_OPERATION_LIST},
		},
	}, time.Minute)
	if err != nil {
		return files.Snapshot{}, err
	}
	var snapshot files.Snapshot
	data := response.GetFileResult().GetSnapshot()
	if len(data) == 0 {
		return snapshot, nil
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return files.Snapshot{}, err
	}
	return snapshot, nil
}

// applyFile performs the operations of the file module.
func (e *TaskExecutor) applyFile(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.FilePayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "the file payload is missing")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	operation := helperv1.FileRequest_OPERATION_LIST
	switch action {
	case opspec.ActionFileRead:
		operation = helperv1.FileRequest_OPERATION_READ
	case opspec.ActionFileEnsure, opspec.ActionFileRollback:
		operation = helperv1.FileRequest_OPERATION_ENSURE
	case opspec.ActionFileRemove:
		operation = helperv1.FileRequest_OPERATION_REMOVE
	case opspec.ActionFilePlan:
		// A plan without a path is a read of the state of all the panel files:
		// that is how the host tab works and how it is to keep working. A plan
		// with a path computes the difference for that one file.
		if strings.TrimSpace(payload.Path) != "" {
			operation = helperv1.FileRequest_OPERATION_PLAN
		}
	}

	// The content from the store is fetched only now, right before the write.
	// The value lives for a moment in the memory of the agent and of the helper
	// - it is not in the envelope of the task, in the journal or in the result.
	content := []byte(payload.Content)
	if !payload.ContentSecret.Empty() {
		if e.secrets == nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError,
				"the agent has no connection through which a secret could be fetched")
		}
		value, err := e.secrets(callCtx, task.GetTaskId(),
			payload.ContentSecret.Name, payload.ContentSecret.Version)
		if err != nil {
			// The reason for the refusal is the content of the result; the value
			// is not in it.
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPrecondition,
				"the secret "+payload.ContentSecret.Name+" was not fetched: "+err.Error())
		}
		content = value
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_File{
			File: &helperv1.FileRequest{
				Operation:      operation,
				Path:           payload.Path,
				Content:        content,
				Mode:           payload.Mode,
				Owner:          payload.Owner,
				Group:          payload.Group,
				ExpectedSha256: payload.ExpectedSHA256,
				Validator:      payload.Validator,
				FromSecret:     !payload.ContentSecret.Empty(),
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetFileResult()
	details := &agentv1.FileResult{
		Snapshot:        result.GetSnapshot(),
		Message:         result.GetMessage(),
		Content:         result.GetContent(),
		Sha256:          result.GetSha256(),
		Truncated:       result.GetTruncated(),
		ValidatorOutput: result.GetValidatorOutput(),
		Plan:            result.GetPlan(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.FileResult = details
		return refused
	}
	message := result.GetMessage()
	if message == "" && action == opspec.ActionFileRead {
		message = "the file was read"
		if result.GetTruncated() {
			// Truncated content without a marker would look like the whole file
			// and would go back to the host the same way at the next write.
			message = "the file was read, the content was cut at the module boundary"
		}
	}
	return &agentv1.TaskResult{
		TaskId:     task.GetTaskId(),
		Status:     agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:    message,
		FileResult: details,
	}
}
