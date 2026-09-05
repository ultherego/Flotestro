package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/modules/monitoring"
	"github.com/ultherego/flotestro/internal/opspec"
)

// applyProbe wykonuje sonde z hosta.
//
// Sonda niczego nie zmienia i nie potrzebuje roota, wiec nie idzie przez
// helpera: kazde przejscie przez roota trzeba uzasadnic. Wynik nalezy do
// zadania, a nie do inwentarza - to odpowiedz z jednej chwili, wobec uslugi,
// ktora za minute moze odpowiadac inaczej.
func (e *TaskExecutor) applyProbe(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.MonitoringPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"brak payloadu sondy")
	}
	timeout := timeoutOf(task, action)
	sondaCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	wynik := monitoring.Wykonaj(sondaCtx, monitoring.Zlecenie{
		Kind: payload.Kind, Target: payload.Target,
		ExpectStatus: payload.ExpectStatus, ExpectBody: payload.ExpectBody,
		TimeoutSeconds: payload.TimeoutSeconds,
	})
	zakodowany, err := json.Marshal(wynik)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}

	// Sonda, ktora nie doszla do uslugi, jest udana operacja z odpowiedzia
	// "nie dziala". Zadanie nieudane oznaczaloby, ze to panel czegos nie
	// zrobil - a zrobil dokladnie to, o co proszono.
	komunikat := "usluga odpowiada"
	switch {
	case !wynik.Reachable:
		komunikat = "usluga nie odpowiada: " + wynik.Error
	case !wynik.Passed:
		komunikat = "usluga odpowiada, ale nie tak, jak oczekiwano: " + wynik.Error
	}
	komunikat += " (" + time.Duration(wynik.DurationMillis*int64(time.Millisecond)).String() + ")"

	return &agentv1.TaskResult{
		TaskId:  task.GetTaskId(),
		Status:  agentv1.TaskResult_STATUS_SUCCEEDED,
		Message: komunikat,
		MonitoringResult: &agentv1.MonitoringResult{
			Probe: zakodowany, Message: komunikat,
		},
	}
}
