package agent

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/storage"
	"github.com/ultherego/flotestro/internal/opspec"
)

// ProbeLVM reads the LVM groups and volumes through the helper.
func (e *TaskExecutor) ProbeLVM(ctx context.Context) (storage.Snapshot, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Storage{
			Storage: &helperv1.StorageRequest{
				Operation: helperv1.StorageRequest_OPERATION_READ_LVM,
			},
		},
	}, time.Minute)
	if err != nil {
		return storage.Snapshot{}, err
	}
	return decodeStorage(response.GetStorageResult().GetSnapshot())
}

// applyStorage performs the operations of the disk space module.
func (e *TaskExecutor) applyStorage(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.StoragePayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)

	// Reading the topology needs no root beyond the LVM part, so it is assembled
	// by the agent: every trip through root has to be justified. A plan with a
	// target is something else: it computes the difference for one mount and
	// resolves the source to a UUID - that is done by the helper, because it is
	// the one that mounts afterwards.
	if action == opspec.ActionStoragePlan && (payload == nil ||
		(strings.TrimSpace(payload.Target) == "" && payload.Plan == "")) {
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		snapshot := CollectStorage(callCtx)
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
		}
		return &agentv1.TaskResult{
			TaskId:  task.GetTaskId(),
			Status:  agentv1.TaskResult_STATUS_SUCCEEDED,
			Message: storageSummary(snapshot),
			StorageResult: &agentv1.StorageResult{
				Snapshot: encoded,
			},
		}
	}

	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the disk space payload is missing")
	}
	operation := helperv1.StorageRequest_OPERATION_MOUNT_ENSURE
	switch action {
	case opspec.ActionStoragePlan:
		operation = helperv1.StorageRequest_OPERATION_MOUNT_PLAN
		if payload.Plan != "" {
			operation = helperv1.StorageRequest_OPERATION_DEVICE_PLAN
		}
	case opspec.ActionMountRemove:
		operation = helperv1.StorageRequest_OPERATION_MOUNT_REMOVE
	case opspec.ActionFilesystemCheck:
		operation = helperv1.StorageRequest_OPERATION_FS_CHECK
	case opspec.ActionLVMExtend:
		operation = helperv1.StorageRequest_OPERATION_LVM_EXTEND
	case opspec.ActionFilesystemResize:
		operation = helperv1.StorageRequest_OPERATION_FS_RESIZE
	case opspec.ActionFilesystemCreate:
		operation = helperv1.StorageRequest_OPERATION_FS_CREATE
	case opspec.ActionDiskWipe:
		operation = helperv1.StorageRequest_OPERATION_DISK_WIPE
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()
	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Storage{
			Storage: &helperv1.StorageRequest{
				Operation:         operation,
				Source:            payload.Source,
				Target:            payload.Target,
				FsType:            payload.FSType,
				Options:           payload.Options,
				Persist:           payload.Persist,
				Device:            payload.Device,
				ExpectedUuid:      payload.ExpectedUUID,
				Repair:            payload.Repair,
				ExpectedSerial:    payload.ExpectedSerial,
				ExpectedSizeBytes: payload.ExpectedSizeBytes,
				Size:              payload.Size,
				Plan:              payload.Plan,
				PlanHash:          payload.PlanHash,
				Label:             payload.Label,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetStorageResult()
	details := &agentv1.StorageResult{
		Snapshot: result.GetSnapshot(),
		Message:  result.GetMessage(),
		Output:   result.GetOutput(),
		Plan:     result.GetPlan(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.StorageResult = details
		return refused
	}

	// After the change the full picture of the space is sent back: the tab is to
	// show the state after the operation and not the one from before the
	// inventory cycle.
	snapshot := CollectStorage(ctx)
	if encoded, err := json.Marshal(snapshot); err == nil {
		details.Snapshot = encoded
	}
	return &agentv1.TaskResult{
		TaskId:        task.GetTaskId(),
		Status:        agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:       result.GetMessage(),
		StorageResult: details,
	}
}

func decodeStorage(data []byte) (storage.Snapshot, error) {
	var snapshot storage.Snapshot
	if len(data) == 0 {
		return snapshot, nil
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return storage.Snapshot{}, err
	}
	return snapshot, nil
}

// storageSummary describes the result of the read in one sentence.
func storageSummary(snapshot storage.Snapshot) string {
	mounted := 0
	for _, mount := range snapshot.Mounts {
		if mount.Mounted {
			mounted++
		}
	}
	return "devices: " + strconv.Itoa(len(snapshot.Devices)) +
		", mounted filesystems: " + strconv.Itoa(mounted)
}
