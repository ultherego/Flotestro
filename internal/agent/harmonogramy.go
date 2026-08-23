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

// scheduleProbe czyta harmonogramy hosta przez helpera. Katalog /etc/cron.d
// nalezy do roota, wiec agent nie odczyta go samodzielnie.
var scheduleProbe func(context.Context) (schedules.Snapshot, error)

// SetScheduleProbe wskazuje funkcje odczytujaca harmonogramy.
func SetScheduleProbe(probe func(context.Context) (schedules.Snapshot, error)) {
	scheduleProbe = probe
}

// ProbeSchedules odczytuje harmonogramy hosta.
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
			"brak payloadu harmonogramu")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	operacja := helperv1.ScheduleRequest_OPERATION_ENSURE
	switch action {
	case opspec.ActionScheduleDisable:
		operacja = helperv1.ScheduleRequest_OPERATION_DISABLE
	case opspec.ActionScheduleRemove:
		operacja = helperv1.ScheduleRequest_OPERATION_REMOVE
	case opspec.ActionScheduleRunNow:
		operacja = helperv1.ScheduleRequest_OPERATION_RUN_NOW
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Schedule{
			Schedule: &helperv1.ScheduleRequest{
				Operation:  operacja,
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

	wynik := response.GetScheduleResult()
	szczegoly := &agentv1.ScheduleResult{
		Snapshot: wynik.GetSnapshot(),
		Message:  wynik.GetMessage(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.ScheduleResult = szczegoly
		return odrzucone
	}
	return &agentv1.TaskResult{
		TaskId:         task.GetTaskId(),
		Status:         agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:        wynik.GetMessage(),
		ScheduleResult: szczegoly,
	}
}

func dekodujHarmonogramy(wynik *helperv1.ScheduleResult) (schedules.Snapshot, error) {
	if wynik == nil || len(wynik.GetSnapshot()) == 0 {
		return schedules.Snapshot{}, nil
	}
	var snapshot schedules.Snapshot
	if err := json.Unmarshal(wynik.GetSnapshot(), &snapshot); err != nil {
		return schedules.Snapshot{}, err
	}
	return snapshot, nil
}
