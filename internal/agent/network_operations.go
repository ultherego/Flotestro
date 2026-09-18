package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/ultherego/flotestro/internal/agentconfig"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/network"
	"github.com/ultherego/flotestro/internal/opspec"
)

// confirmationMargin is the time left for the rollback timer. A confirmation
// sent in the last second could pass the timer, and the host would go back to
// the old configuration despite a successful change.
const confirmationMargin = 20 * time.Second

// connectivityProbeInterval says how often the agent checks the route to the
// panel.
const connectivityProbeInterval = 3 * time.Second

// applyNetwork changes the network configuration and proves that the host
// still talks to the panel.
//
// The order is the whole content of the operation: the helper arms the
// rollback, changes the configuration, and only then does the host prove the
// management channel - as itself, with a control call the panel acknowledges.
// A confirmation sent without that proof would disarm the rescue timer
// exactly when it is needed.
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
	case opspec.ActionNetworkLinkApply:
		operation = helperv1.NetworkRequest_OPERATION_APPLY_LINK
	case opspec.ActionNetworkLinkRemove:
		operation = helperv1.NetworkRequest_OPERATION_REMOVE_LINK
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
				Method6:         payload.Method6,
				Addresses6:      payload.Addresses6,
				Gateway6:        payload.Gateway6,
				AcceptRa:        payload.AcceptRA,
				Privacy:         payload.Privacy,
				Link:            networkLinkRequest(payload.Link),
				LinkRemove:      payload.LinkRemove,
				// The address the host reaches the panel from. The helper
				// has no way to know it and must not guess: it is what
				// marks the management interface, and a layer built over
				// that interface takes the host off the network before it
				// is finished.
				ManagementAddress: panelAddress(panelAddressOf),
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
	proof := proveManagementChannel(ctx, panelAddressOf, deadline.Add(-confirmationMargin))
	if !proof.Proved {
		// No confirmation is sent. The host goes back on its own to the
		// configuration from before the change, and the operator is to learn
		// about it right away rather than from silence.
		details.Confirmed = false
		return &agentv1.TaskResult{
			TaskId:        task.GetTaskId(),
			Status:        agentv1.TaskResult_STATUS_FAILED,
			Message:       fmt.Sprintf("after the change %s; rollback at %s", proof.summary(), result.GetRollbackDeadline()),
			ErrorCode:     RejectManagementUnproved,
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
		Message:       result.GetMessage() + "; " + proof.summary() + ", the rollback was disarmed",
		NetworkResult: details,
	}
}

// panelAddressOf holds the address of the control plane the host proves its
// management channel against after a change.
var panelAddressOf string

// SetGatewayURL remembers the address of the control plane.
func SetGatewayURL(gatewayURL string) { panelAddressOf = gatewayURL }

// RejectManagementUnproved marks a change after which the host could not
// prove it still talks to the panel as itself. The code lives next to the
// proof rather than with the other refusals of the executor, because it is
// the proof that decides whether it is given.
const RejectManagementUnproved = "management_channel_unproved"

// managementProofTimeout bounds one attempt at the proof. It is the limit the
// connectivity check has always had: a call to the panel that takes longer
// than this is not a channel an operator could work through either.
const managementProofTimeout = 5 * time.Second

// panelAck is what the panel answered the proof with.
//
// An empty answer is not an acknowledgement. A channel that opens and says
// nothing is exactly the state the proof exists to catch, so the fields are
// read rather than assumed from the absence of an error.
type panelAck struct {
	GatewayID  string
	ServerTime time.Time
}

// acknowledged says whether the panel really answered the control call.
func (a panelAck) acknowledged() bool { return a.GatewayID != "" || !a.ServerTime.IsZero() }

// managementProof is what the host has to show before a rescue plan is
// disarmed, and what the result of the task carries afterwards.
type managementProof struct {
	Proved     bool
	GatewayID  string
	ServerTime time.Time
	// Attempts counts the calls made. A proof that took several tries is not
	// the same fact as one that went through at once, and the operator reading
	// the result is to see the difference.
	Attempts int
	// Reason names why the proof was not produced. It is never empty on a
	// proof that failed: an unknown reason is not "the channel works".
	Reason string
}

// summary renders the proof for the message of the result. The operator reads
// the result of the task rather than the journal of the host, so the proof
// has to travel in it.
func (p managementProof) summary() string {
	if !p.Proved {
		return "the management channel was not proved: " + p.Reason
	}
	who := "the panel"
	if p.GatewayID != "" {
		who = "gateway " + p.GatewayID
	}
	attempts := "attempts"
	if p.Attempts == 1 {
		attempts = "attempt"
	}
	return fmt.Sprintf("the management channel was proved: %s acknowledged a control call over mTLS in %d %s",
		who, p.Attempts, attempts)
}

// askPanel makes one acknowledged control call to the panel.
//
// It is a variable so that the proof can be held against a channel that
// refuses, one that acknowledges, and one that opens but never answers - the
// last being the case a bare TCP handshake used to call a success.
var askPanel = pingPanel

// pingPanel proves the channel the way the session uses it: a new mTLS
// connection with the host's own certificate, a control call, and the
// panel's answer read back.
//
// The new connection is the whole point. The session of the agent may live on
// for minutes on a socket the kernel keeps outside the new rules, and a rule
// that admits a handshake but kills the session - one that drops long-lived
// connections, or blocks the protocol they run on - leaves the host reachable
// for exactly as long as nobody reconnects. A TCP handshake to the gateway
// proved none of that.
func pingPanel(ctx context.Context, gatewayURL string) (panelAck, error) {
	identity, err := managementIdentity()
	if err != nil {
		return panelAck{}, err
	}
	client := newHTTP2Client(identity)
	// Every attempt opens its own connection; an idle one left behind would
	// be the old socket all over again.
	defer client.CloseIdleConnections()
	response, err := agentv1connect.NewAgentServiceClient(client, gatewayURL).
		Ping(ctx, connect.NewRequest(&agentv1.PingRequest{}))
	if err != nil {
		return panelAck{}, err
	}
	ack := panelAck{GatewayID: response.Msg.GetGatewayId()}
	if stamp := response.Msg.GetServerTime(); stamp != nil {
		ack.ServerTime = stamp.AsTime()
	}
	return ack, nil
}

// proveManagementChannel repeats the proof until the panel acknowledges or
// the moment the rescue plan has to keep for itself.
func proveManagementChannel(ctx context.Context, gatewayURL string, until time.Time) managementProof {
	var proof managementProof
	if strings.TrimSpace(gatewayURL) == "" {
		// Without a known address of the panel there is nothing to prove the
		// channel against, and guessing "it probably works" disarms the rescue.
		proof.Reason = "the agent does not know the address of the panel"
		return proof
	}
	for {
		attempt, cancel := context.WithTimeout(ctx, managementProofTimeout)
		ack, err := askPanel(attempt, gatewayURL)
		cancel()
		proof.Attempts++
		switch {
		case err != nil:
			proof.Reason = err.Error()
		case !ack.acknowledged():
			proof.Reason = "the panel answered the control call without acknowledging it"
		default:
			proof.Proved = true
			proof.GatewayID = ack.GatewayID
			proof.ServerTime = ack.ServerTime
			proof.Reason = ""
			return proof
		}
		if !time.Now().Before(until) {
			return proof
		}
		select {
		case <-ctx.Done():
			proof.Reason = "the task ended before the panel acknowledged: " + proof.Reason
			return proof
		case <-time.After(connectivityProbeInterval):
		}
	}
}

// waitForPanel says whether the host proved it still reaches the panel. The
// modules that only need the answer keep asking this question.
func waitForPanel(ctx context.Context, gatewayURL string, until time.Time) bool {
	return proveManagementChannel(ctx, gatewayURL, until).Proved
}

// The identity the proof goes out with. It is shared with the session, which
// replaces it in place when the certificate is renewed, so the proof always
// goes out with the certificate the host holds now.
var (
	managementIdentityMu    sync.RWMutex
	managementIdentityValue *Identity
)

// SetManagementIdentity hands the proof the identity the host talks to the
// panel with. The proof is made as the host itself: a call anybody could make
// would say nothing about this host's place in the fleet.
func SetManagementIdentity(identity *Identity) {
	managementIdentityMu.Lock()
	defer managementIdentityMu.Unlock()
	managementIdentityValue = identity
}

// managementIdentity returns the identity the proof goes out with.
//
// The daemon hands it over at start. A process that did not - a tool run by
// hand on the host - reads the same files the daemon connects with. A host
// that has no identity at all cannot prove anything and says so: the rescue
// plan then stays armed, which is the point of it.
func managementIdentity() (*Identity, error) {
	managementIdentityMu.RLock()
	identity := managementIdentityValue
	managementIdentityMu.RUnlock()
	if identity != nil {
		return identity, nil
	}
	loaded, ok := agentconfig.Current()
	if !ok {
		return nil, errors.New("the agent has no identity to prove the management channel with")
	}
	cfg, err := agentconfig.Load(loaded.Path)
	if err != nil {
		return nil, fmt.Errorf("the identity of the host was not read: %w", err)
	}
	identity, err = LoadIdentity(cfg.Agent.StateDir)
	if err != nil {
		return nil, fmt.Errorf("the identity of the host was not read: %w", err)
	}
	return identity, nil
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

// networkLinkRequest carries the layered order to the helper. A layer is
// described field by field rather than as an opaque blob, because the
// helper checks the shape again before it writes anything and an
// unrecognised field would be a setting nobody verified.
func networkLinkRequest(spec *network.LinkSpec) *helperv1.NetworkLink {
	if spec == nil {
		return nil
	}
	return &helperv1.NetworkLink{
		Name: spec.Name, Kind: spec.Kind, Members: spec.Members,
		Mode: spec.Mode, MiimonMs: uint32(spec.MIIMonMS),
		Primary: spec.Primary, LacpRate: spec.LACPRate,
		Stp: spec.STP, VlanFiltering: spec.VLANFiltering,
		Parent: spec.Parent, VlanId: uint32(spec.VLANID),
		Protocol: spec.Protocol, Mtu: spec.MTU,
	}
}

// networkLinkPayload reads the layered order back out of the envelope.
//
// It is the exact mirror of what the panel put in. A field read back as
// something else would give a payload digest the panel never signed, and
// the host would refuse a change nobody had altered.
func networkLinkPayload(link *agentv1.NetworkLink) *network.LinkSpec {
	if link == nil {
		return nil
	}
	return &network.LinkSpec{
		Name: link.GetName(), Kind: link.GetKind(), Members: link.GetMembers(),
		Mode: link.GetMode(), MIIMonMS: int(link.GetMiimonMs()),
		Primary: link.GetPrimary(), LACPRate: link.GetLacpRate(),
		STP: link.GetStp(), VLANFiltering: link.GetVlanFiltering(),
		Parent: link.GetParent(), VLANID: int(link.GetVlanId()),
		Protocol: link.GetProtocol(), MTU: link.GetMtu(),
	}
}
