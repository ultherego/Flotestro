package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/docker"
)

// dockerProbe reads the state of the container engine through the helper. The
// agent has no access to the Docker socket and must not have one: membership in
// the docker group is equivalent to root.
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
//
// The read is complete: the operator opened the tab and wants to see the
// containers, the images, the networks and the volumes. The inventory cycle
// fetches only the summary, so these two paths do not load the host with the
// same thing.
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
//
// The task ends on its own, because the window is closed on both sides. A read
// without an end would stay on the host forever - also when the panel stopped
// listening to it long ago.
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
