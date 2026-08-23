package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/kernel"
	"github.com/ultherego/flotestro/internal/opspec"
)

// kernelProbe czyta ustawienia jadra przez helpera.
var kernelProbe func(context.Context) (kernel.Snapshot, error)

// SetKernelProbe wskazuje funkcje odczytujaca ustawienia jadra.
func SetKernelProbe(probe func(context.Context) (kernel.Snapshot, error)) {
	kernelProbe = probe
}

// ProbeKernel odczytuje ustawienia jadra hosta.
func (e *TaskExecutor) ProbeKernel(ctx context.Context) (kernel.Snapshot, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Kernel{
			Kernel: &helperv1.KernelRequest{Operation: helperv1.KernelRequest_OPERATION_READ},
		},
	}, time.Minute)
	if err != nil {
		return kernel.Snapshot{}, err
	}
	var snapshot kernel.Snapshot
	dane := response.GetKernelResult().GetSnapshot()
	if len(dane) == 0 {
		return snapshot, nil
	}
	if err := json.Unmarshal(dane, &snapshot); err != nil {
		return kernel.Snapshot{}, err
	}
	return snapshot, nil
}

// applyKernel wykonuje operacje modulu jadra.
func (e *TaskExecutor) applyKernel(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.KernelPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	operacja := helperv1.KernelRequest_OPERATION_READ
	switch action {
	case opspec.ActionSysctlEnsure:
		operacja = helperv1.KernelRequest_OPERATION_SYSCTL_ENSURE
	case opspec.ActionKernelModuleLoad:
		operacja = helperv1.KernelRequest_OPERATION_MODULE_LOAD
	case opspec.ActionKernelModuleBlacklist:
		operacja = helperv1.KernelRequest_OPERATION_MODULE_BLACKLIST
	}
	zadanie := &helperv1.KernelRequest{Operation: operacja}
	if payload != nil {
		zadanie.Settings = payload.Settings
		zadanie.Keys = payload.Keys
		zadanie.Module = payload.Module
		zadanie.Blacklist = payload.Blacklist
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_Kernel{Kernel: zadanie},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetKernelResult()
	szczegoly := &agentv1.KernelResult{
		Snapshot:       wynik.GetSnapshot(),
		Message:        wynik.GetMessage(),
		PendingReboot:  wynik.GetPendingReboot(),
		AppliedRuntime: wynik.GetAppliedRuntime(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.KernelResult = szczegoly
		return odrzucone
	}
	return &agentv1.TaskResult{
		TaskId:       task.GetTaskId(),
		Status:       agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:      wynik.GetMessage(),
		KernelResult: szczegoly,
	}
}
