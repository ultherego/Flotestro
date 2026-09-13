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

// securityProbe assembles the protection state of the host. Most of the facts
// the agent reads itself; the helper gets only those that cannot be seen
// without root.
var securityProbe func(context.Context) (security.Snapshot, error)

// SetSecurityProbe points at the function that assembles the protection state.
func SetSecurityProbe(probe func(context.Context) (security.Snapshot, error)) {
	securityProbe = probe
}

// helperFactCodes translates the fact names of the module into the enumeration
// of the protocol.
var helperFactCodes = map[string]helperv1.SecurityRequest_Fact{
	security.FactAppArmorProfiles: helperv1.SecurityRequest_FACT_APPARMOR_PROFILES,
	security.FactAuditRules:       helperv1.SecurityRequest_FACT_AUDIT_RULES,
	security.FactSecureBoot:       helperv1.SecurityRequest_FACT_SECURE_BOOT,
	security.FactSocketOwners:     helperv1.SecurityRequest_FACT_SOCKET_OWNERS,
}

// CollectSecurity reads the protection state of the host.
//
// First what can be seen without root - the SELinux mode, the AppArmor switch,
// FIPS, lockdown, the state of the audit unit and the list of sockets. Only the
// missing facts are ordered from the helper, by name and one at a time: the
// module does not go through root as a whole just because part of its picture
// needs it.
func (e *TaskExecutor) CollectSecurity(ctx context.Context) security.Snapshot {
	snapshot := security.Collect(ctx, commandOutput)
	missing := snapshot.MissingFacts()
	if len(missing) == 0 {
		return snapshot
	}

	requested := make([]helperv1.SecurityRequest_Fact, 0, len(missing))
	for _, name := range missing {
		if fakt, znany := helperFactCodes[name]; znany {
			requested = append(requested, fakt)
		}
	}
	if len(requested) == 0 {
		return snapshot
	}

	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Security{
			Security: &helperv1.SecurityRequest{
				Operation: helperv1.SecurityRequest_OPERATION_FACTS,
				Facts:     requested,
			},
		},
	}, time.Minute)
	if err != nil {
		// A missing helper does not invalidate what is already known: the picture
		// stays incomplete, and the reasons for the gaps say what is not in it.
		for _, name := range missing {
			snapshot.Missing[name] = "helper: " + err.Error()
		}
		return snapshot
	}
	if !response.GetAccepted() {
		for _, name := range missing {
			snapshot.Missing[name] = "helper: " + response.GetMessage()
		}
		return snapshot
	}

	var supplement security.Supplement
	data := response.GetSecurityResult().GetFacts()
	if len(data) > 0 {
		if err := json.Unmarshal(data, &supplement); err != nil {
			for _, name := range missing {
				snapshot.Missing[name] = "helper: " + err.Error()
			}
			return snapshot
		}
	}
	return snapshot.Supplemented(supplement)
}

// ProbeSecurity reads the protection state of the host for the inventory.
func (e *TaskExecutor) ProbeSecurity(ctx context.Context) (security.Snapshot, error) {
	return e.CollectSecurity(ctx), nil
}

// applySecurity performs the operations of the security module.
func (e *TaskExecutor) applySecurity(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.SecurityPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+15*time.Second)
	defer cancel()

	message := "protective state read"
	if action == opspec.ActionSELinuxModeSet || action == opspec.ActionAuditRulesReload {
		request := &helperv1.SecurityRequest{
			Operation: helperv1.SecurityRequest_OPERATION_AUDIT_RELOAD,
		}
		if action == opspec.ActionSELinuxModeSet {
			request.Operation = helperv1.SecurityRequest_OPERATION_SELINUX_MODE
			if payload != nil {
				request.Mode = payload.Mode
			}
		}
		response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
			TaskId:         task.GetTaskId(),
			ExpiresAt:      task.GetExpiresAt(),
			TimeoutSeconds: uint32(timeout.Seconds()),
			Action:         &helperv1.HelperRequest_Security{Security: request},
		}, timeout)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
		}
		if !response.GetAccepted() {
			refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
				response.GetErrorCode(), response.GetMessage())
			refused.TaskId = task.GetTaskId()
			return refused
		}
		message = response.GetSecurityResult().GetMessage()
	}

	// The picture after the operation is assembled by the agent, exactly as with
	// an ordinary read.
	snapshot := e.CollectSecurity(callCtx)
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	return &agentv1.TaskResult{
		TaskId:         task.GetTaskId(),
		Status:         agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:        message,
		SecurityResult: &agentv1.SecurityResult{Snapshot: encoded, Message: message},
	}
}
