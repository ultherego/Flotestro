package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	sshmodul "github.com/ultherego/flotestro/internal/modules/ssh"
	"github.com/ultherego/flotestro/internal/opspec"
)

// sshProbe reads the sshd configuration through the helper: "sshd -T" needs
// root, because it also reads the host keys.
var sshProbe func(context.Context) (sshmodul.Snapshot, error)

// SetSSHProbe wskazuje funkcje odczytujaca konfiguracje sshd.
func SetSSHProbe(probe func(context.Context) (sshmodul.Snapshot, error)) {
	sshProbe = probe
}

// ProbeSSH odczytuje konfiguracje serwera sshd.
func (e *TaskExecutor) ProbeSSH(ctx context.Context) (sshmodul.Snapshot, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Ssh{
			Ssh: &helperv1.SshRequest{Operation: helperv1.SshRequest_OPERATION_READ},
		},
	}, time.Minute)
	if err != nil {
		return sshmodul.Snapshot{}, err
	}
	var snapshot sshmodul.Snapshot
	data := response.GetSshResult().GetSnapshot()
	if len(data) == 0 {
		return snapshot, nil
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return sshmodul.Snapshot{}, err
	}
	return snapshot, nil
}

// applySSH performs the operations of the sshd module.
func (e *TaskExecutor) applySSH(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.SSHPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	operation := helperv1.SshRequest_OPERATION_READ
	switch action {
	case opspec.ActionSSHConfigPlan:
		// A plan without settings is a read of the state; with settings it
		// computes the difference against them, without touching the server.
		if payload != nil && payload.DescribesChange() {
			operation = helperv1.SshRequest_OPERATION_PLAN
		}
	case opspec.ActionSSHConfigApply:
		operation = helperv1.SshRequest_OPERATION_APPLY
	case opspec.ActionSSHHostKeyRotate:
		operation = helperv1.SshRequest_OPERATION_ROTATE_HOSTKEY
	}
	request := &helperv1.SshRequest{Operation: operation}
	if payload != nil {
		request.Port = payload.Port
		request.PermitRootLogin = payload.PermitRootLogin
		request.PasswordAuthentication = payload.PasswordAuthentication
		request.PubkeyAuthentication = payload.PubkeyAuthentication
		request.KbdInteractiveAuthentication = payload.KbdInteractive
		request.MaxAuthTries = payload.MaxAuthTries
		request.AllowUsers = payload.AllowUsers
		request.AllowGroups = payload.AllowGroups
		request.DenyUsers = payload.DenyUsers
		request.AllowLockout = payload.AllowLockout
		request.KeyType = payload.KeyType
		request.PlanHash = payload.PlanHash
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_Ssh{Ssh: request},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetSshResult()
	details := &agentv1.SshResult{
		Snapshot:   result.GetSnapshot(),
		Message:    result.GetMessage(),
		Mismatches: result.GetMismatches(),
		Plan:       result.GetPlan(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.SshResult = details
		return refused
	}

	// A setting that did not take effect is a negative result despite a
	// successful write: the operator asked for a change and the server applies
	// something else.
	if len(result.GetMismatches()) > 0 {
		return &agentv1.TaskResult{
			TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
			ErrorCode: RejectPrecondition, Message: result.GetMessage(),
			SshResult: details,
		}
	}
	return &agentv1.TaskResult{
		TaskId:    task.GetTaskId(),
		Status:    agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:   result.GetMessage(),
		SshResult: details,
	}
}
