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

// kernelProbe reads the kernel settings through the helper.
var kernelProbe func(context.Context) (kernel.Snapshot, error)

// SetKernelProbe wskazuje funkcje odczytujaca ustawienia jadra.
func SetKernelProbe(probe func(context.Context) (kernel.Snapshot, error)) {
	kernelProbe = probe
}

// ProbeKernel reads the kernel settings of the host.
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
	data := response.GetKernelResult().GetSnapshot()
	if len(data) == 0 {
		return snapshot, nil
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return kernel.Snapshot{}, err
	}
	return snapshot, nil
}

// applyKernel performs the operations of the kernel module.
func (e *TaskExecutor) applyKernel(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.KernelPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	operation := helperv1.KernelRequest_OPERATION_READ
	switch action {
	case opspec.ActionSysctlEnsure:
		operation = helperv1.KernelRequest_OPERATION_SYSCTL_ENSURE
	case opspec.ActionKernelModuleLoad:
		operation = helperv1.KernelRequest_OPERATION_MODULE_LOAD
	case opspec.ActionKernelModuleBlacklist:
		operation = helperv1.KernelRequest_OPERATION_MODULE_BLACKLIST
	case opspec.ActionKernelModulePlan:
		operation = helperv1.KernelRequest_OPERATION_MODULE_PLAN
	}
	request := &helperv1.KernelRequest{Operation: operation}
	if payload != nil {
		request.Settings = payload.Settings
		request.Keys = payload.Keys
		request.Module = payload.Module
		request.Blacklist = payload.Blacklist
		request.PlanHash = payload.PlanHash
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_Kernel{Kernel: request},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetKernelResult()
	details := &agentv1.KernelResult{
		Snapshot:       result.GetSnapshot(),
		Message:        result.GetMessage(),
		PendingReboot:  result.GetPendingReboot(),
		AppliedRuntime: result.GetAppliedRuntime(),
		Plan:           result.GetPlan(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.KernelResult = details
		return refused
	}
	return &agentv1.TaskResult{
		TaskId:       task.GetTaskId(),
		Status:       agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:      result.GetMessage(),
		KernelResult: details,
	}
}
