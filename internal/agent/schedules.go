package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/schedules"
	"github.com/ultherego/flotestro/internal/opspec"
)

// scheduleProbe reads the schedules of the host through the helper. The
// /etc/cron.d directory belongs to root, so the agent cannot read it itself.
var scheduleProbe func(context.Context) (schedules.Snapshot, error)

// SetScheduleProbe points at the function that reads the schedules.
func SetScheduleProbe(probe func(context.Context) (schedules.Snapshot, error)) {
	scheduleProbe = probe
}

// ProbeSchedules reads the schedules of the host.
func (e *TaskExecutor) ProbeSchedules(ctx context.Context) (schedules.Snapshot, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Schedule{
			Schedule: &helperv1.ScheduleRequest{
				Operation: helperv1.ScheduleRequest_OPERATION_READ,
			},
		},
	}, time.Minute)
	if err != nil {
		return schedules.Snapshot{}, err
	}
	return dekodujHarmonogramy(response.GetScheduleResult())
}

// applySchedule zleca helperowi operacje na zadaniu cyklicznym.
func (e *TaskExecutor) applySchedule(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.SchedulePayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the schedule payload is missing")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	operation := helperv1.ScheduleRequest_OPERATION_ENSURE
	switch action {
	case opspec.ActionScheduleDisable:
		operation = helperv1.ScheduleRequest_OPERATION_DISABLE
	case opspec.ActionScheduleRemove:
		operation = helperv1.ScheduleRequest_OPERATION_REMOVE
	case opspec.ActionScheduleRunNow:
		operation = helperv1.ScheduleRequest_OPERATION_RUN_NOW
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Schedule{
			Schedule: &helperv1.ScheduleRequest{
				Operation:  operation,
				Id:         payload.ID,
				Expression: payload.Expression,
				Command:    payload.Command,
				User:       payload.User,
				Comment:    payload.Comment,
				Enabled:    payload.Enabled,
				Adopt:      payload.Adopt,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetScheduleResult()
	details := &agentv1.ScheduleResult{
		Snapshot: result.GetSnapshot(),
		Message:  result.GetMessage(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.ScheduleResult = details
		return refused
	}
	return &agentv1.TaskResult{
		TaskId:         task.GetTaskId(),
		Status:         agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:        result.GetMessage(),
		ScheduleResult: details,
	}
}

func dekodujHarmonogramy(result *helperv1.ScheduleResult) (schedules.Snapshot, error) {
	if result == nil || len(result.GetSnapshot()) == 0 {
		return schedules.Snapshot{}, nil
	}
	var snapshot schedules.Snapshot
	if err := json.Unmarshal(result.GetSnapshot(), &snapshot); err != nil {
		return schedules.Snapshot{}, err
	}
	return snapshot, nil
}
