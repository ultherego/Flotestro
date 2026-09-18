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

// applySchedule asks the helper for an operation on a recurring job.
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
				Kind:       payload.Kind,
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

// previewSchedule computes the coming runs of an expression on the host.
//
// The read needs no helper: the evaluator is the one the panel checks the
// expression with, and the zone is the host's own - which is the point of
// asking the host rather than computing the dates in the browser. The
// answer travels in the typed preview field and, as JSON, on stdout, the
// channel every result reaches the panel through unchanged. It is not a
// snapshot: the state of the host's schedules did not change.
func (e *TaskExecutor) previewSchedule(task *agentv1.TaskEnvelope,
	payload *opspec.SchedulePayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the schedule payload is missing")
	}
	preview := schedules.PreviewExpression(payload.Expression, time.Now(), schedules.HostTimezone())
	// A timer is two files, and the operator is to read them before they
	// are on the host: the preview carries the plan of what would be
	// written, with the calendar expression the cron line becomes. The
	// files are not read here - the agent may not read the unit directory,
	// and this is what would be written, not what is there.
	if payload.Kind == schedules.KindTimer && preview.Error == "" {
		preview.Kind = schedules.KindTimer
		calendar, err := schedules.CalendarFromCron(payload.Expression)
		if err != nil {
			// An expression that has no calendar form is said plainly: the
			// runs are still the runs of the cron expression, and the
			// operator reads why the timer would not be written.
			preview.Error = err.Error()
		} else {
			preview.Calendar = calendar
		}
		// The units are shown once the order is complete enough to render
		// them. A form still being filled in has no account and no name
		// yet, and the calendar above is already the answer to what was
		// asked.
		if preview.Error == "" && payload.ID != "" && payload.User != "" {
			plan, err := schedules.RenderTimer(schedules.SystemdUnitDir, schedules.Schedule{
				ID:         payload.ID,
				Expression: payload.Expression,
				Command:    payload.Command,
				User:       payload.User,
				Comment:    payload.Comment,
			})
			if err != nil {
				preview.Error = err.Error()
			} else {
				preview.Units = plan.Files
			}
		}
	}
	encoded, err := json.Marshal(preview)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	return &agentv1.TaskResult{
		TaskId:         task.GetTaskId(),
		Status:         agentv1.TaskResult_STATUS_SUCCEEDED,
		Stdout:         encoded,
		ScheduleResult: &agentv1.ScheduleResult{Preview: encoded},
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
