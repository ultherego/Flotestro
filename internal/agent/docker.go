package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/docker"
	"github.com/ultherego/flotestro/internal/opspec"
)

// dockerProbe reads the state of the container engine through the helper.
var dockerProbe func(context.Context, bool) (docker.Snapshot, error)

// SetDockerProbe points at the function that reads the state of the containers.
func SetDockerProbe(probe func(context.Context, bool) (docker.Snapshot, error)) {
	dockerProbe = probe
}

// ProbeDocker reads the state of the container engine through the helper. full
// decides whether the answer carries the complete lists or only the summary.
func (e *TaskExecutor) ProbeDocker(ctx context.Context, full bool) (docker.Snapshot, error) {
	scope := helperv1.DockerReadRequest_SCOPE_SUMMARY
	timeout := 30 * time.Second
	if full {
		scope = helperv1.DockerReadRequest_SCOPE_FULL
		timeout = 2 * time.Minute
	}

	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_DockerRead{
			DockerRead: &helperv1.DockerReadRequest{Scope: scope},
		},
	}, timeout)
	if err != nil {
		return docker.Snapshot{}, err
	}
	result := response.GetDockerResult()
	if result == nil {
		return docker.Snapshot{}, errors.New("the helper did not send back the state of the containers")
	}
	if len(result.GetSnapshot()) == 0 {
		return docker.Snapshot{
			Summary: docker.Summary{UnavailableReason: result.GetUnavailableReason()},
		}, nil
	}

	var snapshot docker.Snapshot
	if err := json.Unmarshal(result.GetSnapshot(), &snapshot); err != nil {
		return docker.Snapshot{}, err
	}
	return snapshot, nil
}

// readDocker performs the read of the state of the containers.
func (e *TaskExecutor) readDocker(ctx context.Context, task *agentv1.TaskEnvelope) *agentv1.TaskResult {
	snapshot, err := e.ProbeDocker(ctx, true)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	// An unavailable engine is not an error of the operation: the read succeeded,
	// and its content is the information that the engine does not answer.
	return &agentv1.TaskResult{
		TaskId: task.GetTaskId(),
		Status: agentv1.TaskResult_STATUS_SUCCEEDED,
		DockerResult: &agentv1.DockerReadResult{
			Snapshot:          encoded,
			UnavailableReason: snapshot.Summary.UnavailableReason,
		},
	}
}

// readDockerEvents reads the event journal of the engine within a closed
// window.
func (e *TaskExecutor) readDockerEvents(ctx context.Context,
	task *agentv1.TaskEnvelope) *agentv1.TaskResult {
	order := task.GetReadDockerEvents()
	// The helper limit covers the follow window with room for the read itself.
	timeout := time.Duration(order.GetFollowSeconds())*time.Second + 90*time.Second

	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_DockerEvents{
			DockerEvents: &helperv1.DockerEventsRequest{
				SinceSeconds:  order.GetSinceSeconds(),
				FollowSeconds: order.GetFollowSeconds(),
				Types:         order.GetTypes(),
				MaxEvents:     order.GetMaxEvents(),
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	result := response.GetDockerEventsResult()
	if result == nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed,
			"the helper did not send back the event journal")
	}

	// An unavailable engine is not an error of the operation: the read succeeded,
	// and its content is the information that the engine does not answer.
	return &agentv1.TaskResult{
		TaskId: task.GetTaskId(),
		Status: agentv1.TaskResult_STATUS_SUCCEEDED,
		DockerEventsResult: &agentv1.DockerEventsResult{
			Events:            result.GetEvents(),
			Truncated:         result.GetTruncated(),
			TruncatedReason:   result.GetTruncatedReason(),
			UnavailableReason: result.GetUnavailableReason(),
		},
	}
}

// applyDocker performs an operation on the containers through the helper.
func (e *TaskExecutor) applyDocker(ctx context.Context, task *agentv1.TaskEnvelope,
	action *agentv1.DockerAction) *agentv1.TaskResult {
	timeout := time.Duration(task.GetLimits().GetTimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	response, err := e.helper.Call(actionCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_DockerAction{
			DockerAction: &helperv1.DockerActionRequest{
				Operation:      helperDockerOperation(action.GetOperation()),
				ContainerId:    action.GetContainerId(),
				TimeoutSeconds: action.GetTimeoutSeconds(),
				RemoveVolumes:  action.GetRemoveVolumes(),
				ImageReference: action.GetImageReference(),
				ImageIds:       action.GetImageIds(),
				VolumeNames:    action.GetVolumeNames(),
				NetworkIds:     action.GetNetworkIds(),
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	// The state before and after goes into the result on failure as well: the
	// administrator has to know whether the change managed to take hold before
	// the operation broke down.
	details := dockerResultToProto(response.GetDockerActionResult())
	if !response.GetAccepted() {
		result := rejected(agentv1.TaskResult_STATUS_FAILED,
			response.GetErrorCode(), response.GetMessage())
		result.TaskId = task.GetTaskId()
		result.DockerActionResult = details
		return result
	}
	return &agentv1.TaskResult{
		TaskId:             task.GetTaskId(),
		Status:             agentv1.TaskResult_STATUS_SUCCEEDED,
		DockerActionResult: details,
	}
}

// applyDockerEnsure computes the plan of a declared object, or carries it out,
// through the helper.
func (e *TaskExecutor) applyDockerEnsure(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.DockerEnsurePayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the declaration payload is missing")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	request := &helperv1.DockerEnsureRequest{
		Operation:  helperDockerEnsureOperation(action),
		Kind:       payload.ObjectKind(),
		Name:       payload.ObjectName(),
		PlanDigest: payload.PlanDigest,
		Force:      payload.Force,
	}
	// The description is written out of the payload the payload hash was checked
	// against, not copied out of the envelope: what the helper reads is then
	// exactly what this agent accepted, field for field.
	spec, err := declaredObject(payload)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, err.Error())
	}
	request.Spec = spec
	if len(payload.EnvSecrets) > 0 {
		request.EnvValues = map[string][]byte{}
		for name, reference := range payload.EnvSecrets {
			value, refusal := e.fetchSecret(callCtx, task, reference)
			if refusal != nil {
				return refusal
			}
			request.EnvValues[name] = value
		}
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_DockerEnsure{DockerEnsure: request},
	}, timeout+time.Minute)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	// The plan or the outcome travels back on a refusal as well: a replacement
	// that was refused because the plan moved is worth nothing to the operator
	// without the plan the host computed instead.
	details := &agentv1.DockerEnsureResult{
		Payload:           response.GetDockerEnsureResult().GetPayload(),
		UnavailableReason: response.GetDockerEnsureResult().GetUnavailableReason(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_FAILED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.DockerEnsureResult = details
		return refused
	}
	return &agentv1.TaskResult{
		TaskId:             task.GetTaskId(),
		Status:             agentv1.TaskResult_STATUS_SUCCEEDED,
		DockerEnsureResult: details,
	}
}

// declaredObject writes the description out of the payload.
func declaredObject(payload *opspec.DockerEnsurePayload) ([]byte, error) {
	var described any
	switch {
	case payload.Container != nil:
		// The references are written into the description here, on the way to the
		// host: the order keeps them typed beside it, and the host needs them
		// inside, because the digest of the description is what turns a rotated.
		order := *payload.Container
		order.EnvSecrets = nil
		if len(payload.EnvSecrets) > 0 {
			order.EnvSecrets = make(map[string]string, len(payload.EnvSecrets))
			for name, reference := range payload.EnvSecrets {
				order.EnvSecrets[name] = reference.String()
			}
		}
		described = &order
	case payload.Network != nil:
		described = payload.Network
	case payload.Volume != nil:
		described = payload.Volume
	default:
		return nil, nil
	}
	encoded, err := json.Marshal(described)
	if err != nil {
		return nil, fmt.Errorf("the description of %s: %w", payload.ObjectName(), err)
	}
	return encoded, nil
}

func helperDockerEnsureOperation(action opspec.ActionType) helperv1.DockerEnsureRequest_Operation {
	switch action {
	case opspec.ActionDockerPlan:
		return helperv1.DockerEnsureRequest_OPERATION_PLAN
	case opspec.ActionDockerContainerEnsure:
		return helperv1.DockerEnsureRequest_OPERATION_CONTAINER_ENSURE
	case opspec.ActionDockerNetworkEnsure:
		return helperv1.DockerEnsureRequest_OPERATION_NETWORK_ENSURE
	case opspec.ActionDockerNetworkRemove:
		return helperv1.DockerEnsureRequest_OPERATION_NETWORK_REMOVE
	case opspec.ActionDockerVolumeEnsure:
		return helperv1.DockerEnsureRequest_OPERATION_VOLUME_ENSURE
	case opspec.ActionDockerVolumeRemove:
		return helperv1.DockerEnsureRequest_OPERATION_VOLUME_REMOVE
	}
	return helperv1.DockerEnsureRequest_OPERATION_UNSPECIFIED
}

func helperDockerOperation(operation agentv1.DockerAction_Operation) helperv1.DockerActionRequest_Operation {
	switch operation {
	case agentv1.DockerAction_OPERATION_START:
		return helperv1.DockerActionRequest_OPERATION_START
	case agentv1.DockerAction_OPERATION_STOP:
		return helperv1.DockerActionRequest_OPERATION_STOP
	case agentv1.DockerAction_OPERATION_RESTART:
		return helperv1.DockerActionRequest_OPERATION_RESTART
	case agentv1.DockerAction_OPERATION_REMOVE:
		return helperv1.DockerActionRequest_OPERATION_REMOVE
	case agentv1.DockerAction_OPERATION_PULL_IMAGE:
		return helperv1.DockerActionRequest_OPERATION_PULL_IMAGE
	case agentv1.DockerAction_OPERATION_PRUNE:
		return helperv1.DockerActionRequest_OPERATION_PRUNE
	}
	return helperv1.DockerActionRequest_OPERATION_UNSPECIFIED
}

func dockerResultToProto(result *helperv1.DockerActionResult) *agentv1.DockerActionResult {
	if result == nil {
		return nil
	}
	return &agentv1.DockerActionResult{
		Before:         result.GetBefore(),
		After:          result.GetAfter(),
		Removed:        result.GetRemoved(),
		ReclaimedBytes: result.ReclaimedBytes,
		ImageDigest:    result.GetImageDigest(),
	}
}

// readDockerLogs reads the tail of one container's log through the helper.
func (e *TaskExecutor) readDockerLogs(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.DockerLogsPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the container log payload is missing")
	}
	timeout := timeoutOf(task, opspec.ActionDockerLogs)
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	response, err := e.helper.Call(readCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		MaxOutputBytes: task.GetLimits().GetMaxOutputBytes(),
		Action: &helperv1.HelperRequest_DockerLogs{
			DockerLogs: &helperv1.DockerLogsRequest{
				ContainerId: payload.ContainerID,
				Lines:       payload.Lines,
				Since:       payload.Since,
				Timestamps:  payload.Timestamps,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_FAILED, response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		return refused
	}
	result := response.GetDockerLogsResult()
	if result == nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed,
			"the helper did not send back the container log")
	}
	return &agentv1.TaskResult{
		TaskId: task.GetTaskId(),
		Status: agentv1.TaskResult_STATUS_SUCCEEDED,
		DockerLogsResult: &agentv1.DockerLogsResult{
			ContainerId:       result.GetContainerId(),
			ContainerName:     result.GetContainerName(),
			Lines:             result.GetLines(),
			Truncated:         result.GetTruncated(),
			TruncatedReason:   result.GetTruncatedReason(),
			UnavailableReason: result.GetUnavailableReason(),
		},
	}
}
