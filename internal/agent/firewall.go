package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/firewall"
	"github.com/ultherego/flotestro/internal/opspec"
)

// firewallProbe reads the state of the firewall through the helper: the
// nftables tables are visible only to root.
var firewallProbe func(context.Context) (firewall.Snapshot, error)

// SetFirewallProbe points at the function that reads the state of the
// firewall.
func SetFirewallProbe(probe func(context.Context) (firewall.Snapshot, error)) {
	firewallProbe = probe
}

// ProbeFirewall reads the state of the firewall of the host.
func (e *TaskExecutor) ProbeFirewall(ctx context.Context) (firewall.Snapshot, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Firewall{
			Firewall: &helperv1.FirewallRequest{
				Operation: helperv1.FirewallRequest_OPERATION_READ,
			},
		},
	}, time.Minute)
	if err != nil {
		return firewall.Snapshot{}, err
	}
	var snapshot firewall.Snapshot
	data := response.GetFirewallResult().GetSnapshot()
	if len(data) == 0 {
		return snapshot, nil
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return firewall.Snapshot{}, err
	}
	return snapshot, nil
}

// applyFirewall changes the firewall and confirms that the host still talks to
// the panel.
func (e *TaskExecutor) applyFirewall(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.FirewallPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "the firewall payload is missing")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	operation := helperv1.FirewallRequest_OPERATION_RULE_ENSURE
	switch action {
	case opspec.ActionFirewallPlan:
		// A plan without a rule is a read of the set: that is how the host tab
		// works. A plan with a rule computes the difference for that one rule -
		// that is the planning phase of a campaign.
		operation = helperv1.FirewallRequest_OPERATION_READ
		if strings.TrimSpace(payload.RuleID) != "" || strings.TrimSpace(payload.Zone) != "" {
			operation = helperv1.FirewallRequest_OPERATION_PLAN
		}
	case opspec.ActionFirewallRuleRemove:
		operation = helperv1.FirewallRequest_OPERATION_RULE_REMOVE
	case opspec.ActionFirewallZonePort:
		operation = helperv1.FirewallRequest_OPERATION_ZONE_PORT
	case opspec.ActionFirewallZoneService:
		operation = helperv1.FirewallRequest_OPERATION_ZONE_SERVICE
	case opspec.ActionFirewallRulesetRestore:
		operation = helperv1.FirewallRequest_OPERATION_RESTORE
	}

	// The address and the port of the management channel are a fact known to the
	// agent and not to the panel: it is the agent that knows which way it really
	// talks.
	address, port := managementChannel()

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Firewall{
			Firewall: &helperv1.FirewallRequest{
				Operation:         operation,
				RuleId:            payload.RuleID,
				Chain:             payload.Chain,
				Action:            payload.Action,
				Protocol:          payload.Protocol,
				Ports:             payload.Ports,
				Sources:           payload.Sources,
				Interface:         payload.Interface,
				Comment:           payload.Comment,
				Zone:              payload.Zone,
				Service:           payload.Service,
				Enable:            payload.Enable,
				ManagementAddress: address,
				ManagementPort:    uint32(port),
				BreakGlass:        payload.BreakGlass,
				RollbackSeconds:   payload.RollbackSeconds,
				RollbackId:        payload.RollbackID,
				ExpectedHash:      payload.ExpectedHash,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetFirewallResult()
	details := &agentv1.FirewallResult{
		Snapshot:         result.GetSnapshot(),
		Message:          result.GetMessage(),
		RollbackId:       result.GetRollbackId(),
		RollbackDeadline: result.GetRollbackDeadline(),
		Plan:             result.GetPlan(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.FirewallResult = details
		return refused
	}

	if result.GetRollbackId() == "" {
		return &agentv1.TaskResult{
			TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_SUCCEEDED,
			Message: result.GetMessage(), FirewallResult: details,
		}
	}

	deadline := rollbackDeadline(result.GetRollbackDeadline())
	if !waitForPanel(ctx, panelAddressOf, deadline.Add(-confirmationMargin)) {
		return &agentv1.TaskResult{
			TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
			ErrorCode:      RejectNetworkUnreachable,
			Message:        "after the firewall change the host does not reach the panel; rollback at " + result.GetRollbackDeadline(),
			FirewallResult: details,
		}
	}

	confirmation, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TaskId: task.GetTaskId(), TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Firewall{
			Firewall: &helperv1.FirewallRequest{
				Operation:  helperv1.FirewallRequest_OPERATION_CONFIRM,
				RollbackId: result.GetRollbackId(),
			},
		},
	}, time.Minute)
	if err != nil || !confirmation.GetAccepted() {
		return &agentv1.TaskResult{
			TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
			ErrorCode: RejectHelperFailed, Message: "the rollback was not disarmed",
			FirewallResult: details,
		}
	}
	details.Snapshot = confirmation.GetFirewallResult().GetSnapshot()
	details.Confirmed = true
	return &agentv1.TaskResult{
		TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:        result.GetMessage() + "; connectivity confirmed, the rollback was disarmed",
		FirewallResult: details,
	}
}

// managementChannel returns the address and the port the host talks to the
// panel with.
//
// It is the agent that knows which way the traffic really goes: the panel sees
// only the address the connection came from, and the helper does not see it at
// all.
func managementChannel() (string, int) {
	parsed, err := url.Parse(panelAddressOf)
	if err != nil || parsed.Hostname() == "" {
		return "", 0
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	number, err := net.LookupPort("tcp", port)
	if err != nil {
		return parsed.Hostname(), 0
	}
	return parsed.Hostname(), number
}
