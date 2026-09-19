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

// ProbeLVM reads the volume manager and the software arrays through the
// helper.
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
	snapshot, err := decodeStorage(response.GetStorageResult().GetSnapshot())
	if err != nil {
		return storage.Snapshot{}, err
	}
	arrays, err := e.probeRAID(ctx)
	if err != nil {
		// The volume manager was read and the arrays were not.
		snapshot.RAIDUnavailableReason = "helper: " + err.Error()
		return snapshot, nil
	}
	snapshot.Arrays = arrays.Arrays
	snapshot.RAIDUnavailableReason = arrays.RAIDUnavailableReason
	return snapshot, nil
}

// probeRAID reads the software arrays through the helper: the superblock
// needs root, and the UUID in it is the only name an operation binds to.
func (e *TaskExecutor) probeRAID(ctx context.Context) (storage.Snapshot, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Storage{
			Storage: &helperv1.StorageRequest{
				Operation: helperv1.StorageRequest_OPERATION_READ_RAID,
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
	// by the agent: every trip through root has to be justified.
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
	case opspec.ActionRAIDMemberFail:
		operation = helperv1.StorageRequest_OPERATION_RAID_MEMBER_FAIL
	case opspec.ActionRAIDMemberRemove:
		operation = helperv1.StorageRequest_OPERATION_RAID_MEMBER_REMOVE
	case opspec.ActionRAIDMemberAdd:
		operation = helperv1.StorageRequest_OPERATION_RAID_MEMBER_ADD
	case opspec.ActionLVMVolumeCreate:
		operation = helperv1.StorageRequest_OPERATION_LVM_LV_CREATE
	case opspec.ActionLVMVolumeRemove:
		operation = helperv1.StorageRequest_OPERATION_LVM_LV_REMOVE
	case opspec.ActionLVMGroupExtend:
		operation = helperv1.StorageRequest_OPERATION_LVM_VG_EXTEND
	case opspec.ActionLVMSnapshotCreate:
		operation = helperv1.StorageRequest_OPERATION_LVM_SNAPSHOT_CREATE
	case opspec.ActionLVMSnapshotRemove:
		operation = helperv1.StorageRequest_OPERATION_LVM_SNAPSHOT_REMOVE
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
				ExpectedById:      payload.ExpectedByID,
				ExpectedWwn:       payload.ExpectedWWN,
				Size:              payload.Size,
				Plan:              payload.Plan,
				PlanHash:          payload.PlanHash,
				Label:             payload.Label,
				// The identities of the layers above a bare disk.
				Array:              payload.Array,
				ExpectedArrayUuid:  payload.ExpectedArrayUUID,
				Group:              payload.Group,
				ExpectedGroupUuid:  payload.ExpectedGroupUUID,
				Volume:             payload.Volume,
				ExpectedVolumeUuid: payload.ExpectedVolumeUUID,
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
	summary := "devices: " + strconv.Itoa(len(snapshot.Devices)) +
		", mounted filesystems: " + strconv.Itoa(mounted)
	if degraded := snapshot.DegradedArrays(); len(degraded) > 0 {
		names := make([]string, 0, len(degraded))
		for _, array := range degraded {
			names = append(names, array.Path)
		}
		summary += ", degraded arrays: " + strings.Join(names, ", ")
	}
	return summary
}

// readSmart asks the helper about the SMART state of one device. The tool
// needs root to talk to the device, so the read goes through the helper.
func (e *TaskExecutor) readSmart(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.StoragePayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the disk space payload is missing")
	}
	timeout := timeoutOf(task, opspec.ActionStorageSmartRead)
	callCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()
	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Storage{
			Storage: &helperv1.StorageRequest{
				Operation: helperv1.StorageRequest_OPERATION_SMART_READ,
				Device:    payload.Device,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED, response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		return refused
	}
	result := response.GetSmartResult()
	if result == nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed,
			"the helper did not send back the SMART report")
	}
	return &agentv1.TaskResult{
		TaskId:      task.GetTaskId(),
		Status:      agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:     smartSummary(result),
		SmartResult: smartResultToAgent(result),
	}
}

// smartSummary describes the report in one sentence.
func smartSummary(result *helperv1.SmartResult) string {
	if result.GetUnsupported() {
		return result.GetDevice() + ": SMART unsupported (" + result.GetUnsupportedReason() + ")"
	}
	summary := result.GetDevice() + ": health " + result.GetHealth()
	if reason := result.GetHealthReason(); reason != "" {
		summary += " (" + reason + ")"
	}
	return summary
}

func smartResultToAgent(result *helperv1.SmartResult) *agentv1.SmartResult {
	converted := &agentv1.SmartResult{
		Device:             result.GetDevice(),
		Model:              result.GetModel(),
		Serial:             result.GetSerial(),
		Health:             result.GetHealth(),
		HealthReason:       result.GetHealthReason(),
		TemperatureC:       result.TemperatureC,
		PowerOnHours:       result.PowerOnHours,
		ReallocatedSectors: result.ReallocatedSectors,
		PendingSectors:     result.PendingSectors,
		WearPercent:        result.WearPercent,
		Unsupported:        result.GetUnsupported(),
		UnsupportedReason:  result.GetUnsupportedReason(),
		Output:             result.GetOutput(),
	}
	for _, attribute := range result.GetAttributes() {
		converted.Attributes = append(converted.Attributes, &agentv1.SmartAttribute{
			Id:        attribute.GetId(),
			Name:      attribute.GetName(),
			Value:     attribute.GetValue(),
			Worst:     attribute.GetWorst(),
			Threshold: attribute.GetThreshold(),
			Raw:       attribute.GetRaw(),
			RawString: attribute.GetRawString(),
			Failing:   attribute.GetFailing(),
		})
	}
	return converted
}
