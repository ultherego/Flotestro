package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/processes"
	"github.com/ultherego/flotestro/internal/opspec"
)

// listProcesses czyta procesy hosta.
//
// Odczyt idzie wprost z /proc i nie wymaga roota: panel pokazuje to, co widzi
// kazdy uzytkownik hosta. Dopiero wyslanie sygnalu wymaga uprawnien.
func (e *TaskExecutor) listProcesses(_ context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.ProcessListPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"brak payloadu listy procesow")
	}
	snapshot := processes.Collect("/proc", payload.SortBy, int(payload.Limit))
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	return &agentv1.TaskResult{
		TaskId:            task.GetTaskId(),
		Status:            agentv1.TaskResult_STATUS_SUCCEEDED,
		ProcessListResult: &agentv1.ProcessListResult{Snapshot: encoded},
	}
}

// signalProcess wysyla sygnal przez helpera.
func (e *TaskExecutor) signalProcess(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.ProcessSignalPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"brak payloadu sygnalu")
	}
	timeout := timeoutOf(task, opspec.ActionProcessSignal)
	callCtx, cancel := context.WithTimeout(ctx, timeout+15*time.Second)
	defer cancel()

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_ProcessSignal{
			ProcessSignal: &helperv1.ProcessSignalRequest{
				Pid:                payload.PID,
				ExpectedStartTicks: payload.ExpectedStart,
				Signal:             payload.Signal,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	if !response.GetAccepted() {
		wynik := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		wynik.TaskId = task.GetTaskId()
		return wynik
	}
	// Polecenie zapisane w chwili wyslania: audyt ma pokazac, co zostalo
	// ubite, a nie sam numer, ktory zaraz przestanie cokolwiek znaczyc.
	return &agentv1.TaskResult{
		TaskId: task.GetTaskId(),
		Status: agentv1.TaskResult_STATUS_SUCCEEDED,
		ProcessSignalResult: &agentv1.ProcessSignalResult{
			Pid:     payload.PID,
			Signal:  payload.Signal,
			Command: payload.Command,
		},
	}
}
