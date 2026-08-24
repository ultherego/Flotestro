package agent

import (
	"context"
	"encoding/json"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/power"
	"github.com/ultherego/flotestro/internal/opspec"
)

// shutdownHost wylacza hosta przez helpera.
//
// Wynik jest odsylany, zanim host zniknie: opoznienie po stronie helpera daje
// na to czas. Inaczej niz przy restarcie, panel nie zobaczy juz powrotu tego
// hosta - i to jest cala roznica miedzy tymi dwiema operacjami.
func (e *TaskExecutor) shutdownHost(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.PowerPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "brak payloadu power")
	}
	timeout := timeoutOf(task, opspec.ActionSystemShutdown)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	delay := payload.DelaySeconds
	if delay == 0 {
		delay = 15
	}
	tryb := payload.Mode
	if tryb == "" {
		tryb = power.TrybWylaczyc
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
				Mode:             tryb,
				IgnoreInhibitors: payload.IgnoreInhibitors,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetPowerResult()
	szczegoly := &agentv1.PowerResult{
		Snapshot:    wynik.GetSnapshot(),
		Message:     wynik.GetMessage(),
		Inhibitors:  wynik.GetInhibitors(),
		ScheduledAt: wynik.GetScheduledAt(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.PowerResult = szczegoly
		return odrzucone
	}

	// Stan startu zbieramy tuz przed zejsciem hosta: to ostatni obraz, jaki
	// panel bedzie mial, dopoki ktos tej maszyny nie wlaczy.
	snapshot := ZbierzZasilanie(ctx, e.facts().BootID, e.facts().RebootRequired)
	if zakodowany, err := json.Marshal(snapshot); err == nil {
		szczegoly.Snapshot = zakodowany
	}
	return &agentv1.TaskResult{
		TaskId:      task.GetTaskId(),
		Status:      agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode:    0,
		Message:     wynik.GetMessage(),
		PowerResult: szczegoly,
	}
}
