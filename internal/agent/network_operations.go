package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// confirmationMargin is the time left for the rollback timer. A confirmation
// sent in the last second could pass the timer, and the host would go back to
// the old configuration despite a successful change.
const confirmationMargin = 20 * time.Second

// connectivityProbeInterval says how often the agent checks the route to the
// panel.
const connectivityProbeInterval = 3 * time.Second

// applyNetwork changes the network configuration and confirms that the host
// still talks to the panel.
//
// The order is the whole content of the operation: the helper arms the
// rollback, changes the configuration, and only then does the agent check
// whether the route to the panel still exists. A confirmation sent without that
// check would disarm the rescue timer exactly when it is needed.
func (e *TaskExecutor) applyNetwork(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.NetworkPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the network payload is missing")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	operation := helperv1.NetworkRequest_OPERATION_APPLY_PROFILE
	switch action {
	case opspec.ActionNetworkPlan:
		// A plan without a description of the change is a read of the profiles;
		// with one it computes the difference against it, without touching the
		// host.
		operation = helperv1.NetworkRequest_OPERATION_READ
		if payload.DescribesChange() {
			operation = helperv1.NetworkRequest_OPERATION_PLAN
		}
	case opspec.ActionNetworkMTUSet:
		operation = helperv1.NetworkRequest_OPERATION_SET_MTU
	case opspec.ActionNetworkRouteEnsure:
		operation = helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES
	case opspec.ActionNetworkRollback:
		operation = helperv1.NetworkRequest_OPERATION_ROLLBACK
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Network{
			Network: &helperv1.NetworkRequest{
				Operation:       operation,
				Interface:       payload.Interface,
				Mtu:             payload.MTU,
				Routes:          payload.Routes,
				Method:          payload.Method,
				Addresses:       payload.Addresses,
				Gateway:         payload.Gateway,
				Dns:             payload.DNS,
				RollbackSeconds: payload.RollbackSeconds,
				RollbackId:      payload.RollbackID,
				PlanHash:        payload.PlanHash,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetNetworkResult()
	details := &agentv1.NetworkResult{
		Profiles:         result.GetProfiles(),
		Message:          result.GetMessage(),
		RollbackId:       result.GetRollbackId(),
		RollbackDeadline: result.GetRollbackDeadline(),
		Confirmed:        result.GetConfirmed(),
		Plan:             result.GetPlan(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.NetworkResult = details
		return refused
	}

	// An operation without an armed rollback changed nothing in the network.
	if result.GetRollbackId() == "" {
		return &agentv1.TaskResult{
			TaskId:        task.GetTaskId(),
			Status:        agentv1.TaskResult_STATUS_SUCCEEDED,
			Message:       result.GetMessage(),
			NetworkResult: details,
		}
	}

	deadline := rollbackDeadline(result.GetRollbackDeadline())
	if !waitForPanel(ctx, panelAddressOf, deadline.Add(-confirmationMargin)) {
		// No confirmation is sent. The host goes back on its own to the
		// configuration from before the change, and the operator is to learn
		// about it right away rather than from silence.
		details.Confirmed = false
		return &agentv1.TaskResult{
			TaskId:        task.GetTaskId(),
			Status:        agentv1.TaskResult_STATUS_FAILED,
			Message:       fmt.Sprintf("after the change the host does not reach the panel; rollback at %s", result.GetRollbackDeadline()),
			ErrorCode:     RejectNetworkUnreachable,
			NetworkResult: details,
		}
	}

	confirmation, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Network{
			Network: &helperv1.NetworkRequest{
				Operation:  helperv1.NetworkRequest_OPERATION_CONFIRM,
				RollbackId: result.GetRollbackId(),
			},
		},
	}, time.Minute)
	if err != nil || !confirmation.GetAccepted() {
		// The change succeeded, but the timer stayed armed: in a moment it will
		// roll back a change that works. The operator is to know about it.
		message := "the rollback was not disarmed"
		if err != nil {
			message += ": " + err.Error()
		} else {
			message += ": " + confirmation.GetMessage()
		}
		details.Confirmed = false
		return &agentv1.TaskResult{
			TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
			ErrorCode: RejectHelperFailed, Message: message, NetworkResult: details,
		}
	}

	details.Profiles = confirmation.GetNetworkResult().GetProfiles()
	details.Confirmed = true
	return &agentv1.TaskResult{
		TaskId:        task.GetTaskId(),
		Status:        agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:       result.GetMessage() + "; connectivity confirmed, the rollback was disarmed",
		NetworkResult: details,
	}
}

// panelAddressOf holds the address of the control plane for the connectivity
// check after a network change.
var panelAddressOf string

// SetGatewayURL remembers the address of the control plane.
func SetGatewayURL(gatewayURL string) { panelAddressOf = gatewayURL }

// waitForPanel checks whether the host still reaches the panel.
//
// A TCP connection is checked and not the session of the agent: the session can
// still live on an old socket the kernel keeps despite an address change, and
// it would tell us everything works when a new connection would no longer get
// through.
func waitForPanel(ctx context.Context, gatewayURL string, until time.Time) bool {
	address := socketAddress(gatewayURL)
	if address == "" {
		// Without a known panel address the connectivity cannot be checked, and
		// guessing "it probably works" disarms the rescue timer.
		return false
	}
	for {
		conn, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err == nil {
			_ = conn.Close()
			return true
		}
		if time.Now().After(until) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(connectivityProbeInterval):
		}
	}
}

func socketAddress(gatewayURL string) string {
	parsed, err := url.Parse(gatewayURL)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(parsed.Hostname(), port)
}

func rollbackDeadline(value string) time.Time {
	deadline, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Now().Add(2 * time.Minute)
	}
	return deadline
}

// NetworkProfiles reads the NetworkManager profiles through the helper.
func (e *TaskExecutor) NetworkProfiles(ctx context.Context) (json.RawMessage, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Network{
			Network: &helperv1.NetworkRequest{Operation: helperv1.NetworkRequest_OPERATION_READ},
		},
	}, time.Minute)
	if err != nil {
		return nil, err
	}
	if !response.GetAccepted() {
		return nil, fmt.Errorf("%s: %s", response.GetErrorCode(), response.GetMessage())
	}
	return response.GetNetworkResult().GetProfiles(), nil
}
