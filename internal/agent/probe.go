package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/modules/monitoring"
	"github.com/ultherego/flotestro/internal/opspec"
)

// applyProbe runs a probe from the host.
//
// A probe changes nothing and needs no root, so it does not go through the
// helper: every trip through root has to be justified. The result belongs to
// the task and not to the inventory - it is an answer from one moment, about a
// service that may answer differently a minute later.
func (e *TaskExecutor) applyProbe(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.MonitoringPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the probe payload is missing")
	}
	timeout := timeoutOf(task, action)
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result := monitoring.Wykonaj(probeCtx, monitoring.Zlecenie{
		Kind: payload.Kind, Target: payload.Target,
		ExpectStatus: payload.ExpectStatus, ExpectBody: payload.ExpectBody,
		TimeoutSeconds: payload.TimeoutSeconds,
	})
	encoded, err := json.Marshal(result)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}

	// A probe that did not reach the service is a successful operation with the
	// answer "it does not work". A failed task would mean the panel did not do
	// something - and it did exactly what was asked.
	message := "the service answers"
	switch {
	case !result.Reachable:
		message = "the service does not answer: " + result.Error
	case !result.Passed:
		message = "the service answers, but not as expected: " + result.Error
	}
	message += " (" + time.Duration(result.DurationMillis*int64(time.Millisecond)).String() + ")"

	return &agentv1.TaskResult{
		TaskId:  task.GetTaskId(),
		Status:  agentv1.TaskResult_STATUS_SUCCEEDED,
		Message: message,
		MonitoringResult: &agentv1.MonitoringResult{
			Probe: encoded, Message: message,
		},
	}
}
