package agent

import (
	"context"
	"encoding/json"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/power"
	"github.com/ultherego/flotestro/internal/opspec"
)

// shutdownHost powers the host off through the helper.
//
// The result is sent back before the host disappears: the delay on the helper
// side leaves time for that. Unlike with a restart, the panel will not see this
// host come back - and that is the whole difference between the two
// operations.
func (e *TaskExecutor) shutdownHost(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.PowerPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "the power payload is missing")
	}
	timeout := timeoutOf(task, opspec.ActionSystemShutdown)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	delay := payload.DelaySeconds
	if delay == 0 {
		delay = 15
	}
	mode := payload.Mode
	if mode == "" {
		mode = power.TrybWylaczyc
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		MaxOutputBytes: task.GetLimits().GetMaxOutputBytes(),
		Action: &helperv1.HelperRequest_Shutdown{
			Shutdown: &helperv1.ShutdownRequest{
				DelaySeconds:     delay,
				Reason:           payload.Reason,
				Mode:             mode,
				IgnoreInhibitors: payload.IgnoreInhibitors,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetPowerResult()
	details := &agentv1.PowerResult{
		Snapshot:    result.GetSnapshot(),
		Message:     result.GetMessage(),
		Inhibitors:  result.GetInhibitors(),
		ScheduledAt: result.GetScheduledAt(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.PowerResult = details
		return refused
	}

	// The boot state is collected right before the host goes down: it is the
	// last picture the panel will have until somebody powers that machine on.
	snapshot := CollectPower(ctx, e.facts().BootID, e.facts().RebootRequired)
	if encoded, err := json.Marshal(snapshot); err == nil {
		details.Snapshot = encoded
	}
	return &agentv1.TaskResult{
		TaskId:      task.GetTaskId(),
		Status:      agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode:    0,
		Message:     result.GetMessage(),
		PowerResult: details,
	}
}
