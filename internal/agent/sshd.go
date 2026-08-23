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

// sshProbe czyta konfiguracje sshd przez helpera: "sshd -T" wymaga roota,
// bo czyta takze klucze hosta.
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
	dane := response.GetSshResult().GetSnapshot()
	if len(dane) == 0 {
		return snapshot, nil
	}
	if err := json.Unmarshal(dane, &snapshot); err != nil {
		return sshmodul.Snapshot{}, err
	}
	return snapshot, nil
}

// applySSH wykonuje operacje modulu sshd.
func (e *TaskExecutor) applySSH(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.SSHPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	operacja := helperv1.SshRequest_OPERATION_READ
	switch action {
	case opspec.ActionSSHConfigApply:
		operacja = helperv1.SshRequest_OPERATION_APPLY
	case opspec.ActionSSHHostKeyRotate:
		operacja = helperv1.SshRequest_OPERATION_ROTATE_HOSTKEY
	}
	zadanie := &helperv1.SshRequest{Operation: operacja}
	if payload != nil {
		zadanie.Port = payload.Port
		zadanie.PermitRootLogin = payload.PermitRootLogin
		zadanie.PasswordAuthentication = payload.PasswordAuthentication
		zadanie.PubkeyAuthentication = payload.PubkeyAuthentication
		zadanie.KbdInteractiveAuthentication = payload.KbdInteractive
		zadanie.MaxAuthTries = payload.MaxAuthTries
		zadanie.AllowUsers = payload.AllowUsers
		zadanie.AllowGroups = payload.AllowGroups
		zadanie.DenyUsers = payload.DenyUsers
		zadanie.AllowLockout = payload.AllowLockout
		zadanie.KeyType = payload.KeyType
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_Ssh{Ssh: zadanie},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetSshResult()
	szczegoly := &agentv1.SshResult{
		Snapshot:   wynik.GetSnapshot(),
		Message:    wynik.GetMessage(),
		Mismatches: wynik.GetMismatches(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.SshResult = szczegoly
		return odrzucone
	}

	// Ustawienie, ktore nie doszlo do skutku, jest wynikiem negatywnym mimo
	// udanego zapisu: operator prosil o zmiane, a serwer stosuje co innego.
	if len(wynik.GetMismatches()) > 0 {
		return &agentv1.TaskResult{
			TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
			ErrorCode: RejectPrecondition, Message: wynik.GetMessage(),
			SshResult: szczegoly,
		}
	}
	return &agentv1.TaskResult{
		TaskId:    task.GetTaskId(),
		Status:    agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:   wynik.GetMessage(),
		SshResult: szczegoly,
	}
}
