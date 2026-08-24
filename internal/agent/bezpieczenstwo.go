package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/security"
	"github.com/ultherego/flotestro/internal/opspec"
)

// securityProbe czyta stan ochronny hosta przez helpera: profile AppArmora,
// reguly audytu, zmienne EFI i wlascicieli gniazd widzi tylko root.
var securityProbe func(context.Context) (security.Snapshot, error)

// SetSecurityProbe wskazuje funkcje odczytujaca stan ochronny.
func SetSecurityProbe(probe func(context.Context) (security.Snapshot, error)) {
	securityProbe = probe
}

// ProbeSecurity odczytuje stan ochronny hosta.
func (e *TaskExecutor) ProbeSecurity(ctx context.Context) (security.Snapshot, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Security{
			Security: &helperv1.SecurityRequest{Operation: helperv1.SecurityRequest_OPERATION_READ},
		},
	}, time.Minute)
	if err != nil {
		return security.Snapshot{}, err
	}
	var snapshot security.Snapshot
	dane := response.GetSecurityResult().GetSnapshot()
	if len(dane) == 0 {
		return snapshot, nil
	}
	if err := json.Unmarshal(dane, &snapshot); err != nil {
		return security.Snapshot{}, err
	}
	return snapshot, nil
}

// applySecurity wykonuje operacje modulu bezpieczenstwa.
func (e *TaskExecutor) applySecurity(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.SecurityPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+15*time.Second)
	defer cancel()

	zadanie := &helperv1.SecurityRequest{Operation: helperv1.SecurityRequest_OPERATION_READ}
	if action == opspec.ActionSELinuxModeSet {
		zadanie.Operation = helperv1.SecurityRequest_OPERATION_SELINUX_MODE
		if payload != nil {
			zadanie.Mode = payload.Mode
		}
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_Security{Security: zadanie},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetSecurityResult()
	szczegoly := &agentv1.SecurityResult{
		Snapshot: wynik.GetSnapshot(),
		Message:  wynik.GetMessage(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.SecurityResult = szczegoly
		return odrzucone
	}
	komunikat := wynik.GetMessage()
	if komunikat == "" {
		komunikat = "stan ochronny odczytany"
	}
	return &agentv1.TaskResult{
		TaskId:         task.GetTaskId(),
		Status:         agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:        komunikat,
		SecurityResult: szczegoly,
	}
}
