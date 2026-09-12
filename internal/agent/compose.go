package agent

import (
	"context"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// applyCompose asks the helper for a plan or a deployment of a Compose project.
//
// The agent has access neither to the Docker socket nor to the manifest
// directory: both belong to root, and the agent runs without privileges.
func (e *TaskExecutor) applyCompose(ctx context.Context, task *agentv1.TaskEnvelope,
	action *agentv1.ComposeAction) *agentv1.TaskResult {
	timeout := time.Duration(task.GetLimits().GetTimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	operation := helperv1.ComposeRequest_OPERATION_PLAN
	if action.GetOperation() == agentv1.ComposeAction_OPERATION_DEPLOY {
		operation = helperv1.ComposeRequest_OPERATION_DEPLOY
	}

	response, err := e.helper.Call(actionCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Compose{
			Compose: &helperv1.ComposeRequest{
				Operation:  operation,
				Project:    action.GetProject(),
				Manifest:   action.GetManifest(),
				PlanDigest: action.GetPlanDigest(),
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	details := &agentv1.ComposeResult{
		Payload:           response.GetComposeResult().GetPayload(),
		UnavailableReason: response.GetComposeResult().GetUnavailableReason(),
	}
	if !response.GetAccepted() {
		result := rejected(agentv1.TaskResult_STATUS_FAILED,
			response.GetErrorCode(), response.GetMessage())
		result.TaskId = task.GetTaskId()
		result.ComposeResult = details
		return result
	}
	return &agentv1.TaskResult{
		TaskId:        task.GetTaskId(),
		Status:        agentv1.TaskResult_STATUS_SUCCEEDED,
		ComposeResult: details,
	}
}
