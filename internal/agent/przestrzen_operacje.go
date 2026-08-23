package agent

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/storage"
	"github.com/ultherego/flotestro/internal/opspec"
)

// ProbeLVM odczytuje grupy i wolumeny LVM przez helpera.
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
	return dekodujPrzestrzen(response.GetStorageResult().GetSnapshot())
}

// applyStorage wykonuje operacje modulu przestrzeni dyskowej.
func (e *TaskExecutor) applyStorage(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.StoragePayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)

	// Odczyt topologii nie wymaga roota poza czescia LVM, wiec sklada go
	// agent: kazde przejscie przez roota trzeba uzasadnic.
	if action == opspec.ActionStoragePlan {
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		snapshot := ZbierzPrzestrzen(callCtx)
		zakodowane, err := json.Marshal(snapshot)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
		}
		return &agentv1.TaskResult{
			TaskId:  task.GetTaskId(),
			Status:  agentv1.TaskResult_STATUS_SUCCEEDED,
			Message: podsumowaniePrzestrzeni(snapshot),
			StorageResult: &agentv1.StorageResult{
				Snapshot: zakodowane,
			},
		}
	}

	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"brak payloadu przestrzeni dyskowej")
	}
	operacja := helperv1.StorageRequest_OPERATION_MOUNT_ENSURE
	switch action {
	case opspec.ActionMountRemove:
		operacja = helperv1.StorageRequest_OPERATION_MOUNT_REMOVE
	case opspec.ActionFilesystemCheck:
		operacja = helperv1.StorageRequest_OPERATION_FS_CHECK
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()
	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Storage{
			Storage: &helperv1.StorageRequest{
				Operation:    operacja,
				Source:       payload.Source,
				Target:       payload.Target,
				FsType:       payload.FSType,
				Options:      payload.Options,
				Persist:      payload.Persist,
				Device:       payload.Device,
				ExpectedUuid: payload.ExpectedUUID,
				Repair:       payload.Repair,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetStorageResult()
	szczegoly := &agentv1.StorageResult{
		Snapshot: wynik.GetSnapshot(),
		Message:  wynik.GetMessage(),
		Output:   wynik.GetOutput(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.StorageResult = szczegoly
		return odrzucone
	}

	// Po zmianie odsylamy pelny obraz przestrzeni: zakladka ma pokazac stan
	// po operacji, a nie ten sprzed cyklu inwentarza.
	snapshot := ZbierzPrzestrzen(ctx)
	if zakodowane, err := json.Marshal(snapshot); err == nil {
		szczegoly.Snapshot = zakodowane
	}
	return &agentv1.TaskResult{
		TaskId:        task.GetTaskId(),
		Status:        agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:       wynik.GetMessage(),
		StorageResult: szczegoly,
	}
}

func dekodujPrzestrzen(dane []byte) (storage.Snapshot, error) {
	var snapshot storage.Snapshot
	if len(dane) == 0 {
		return snapshot, nil
	}
	if err := json.Unmarshal(dane, &snapshot); err != nil {
		return storage.Snapshot{}, err
	}
	return snapshot, nil
}

// podsumowaniePrzestrzeni opisuje wynik odczytu jednym zdaniem.
func podsumowaniePrzestrzeni(snapshot storage.Snapshot) string {
	zamontowane := 0
	for _, montowanie := range snapshot.Mounts {
		if montowanie.Mounted {
			zamontowane++
		}
	}
	return "urzadzen: " + strconv.Itoa(len(snapshot.Devices)) +
		", zamontowanych filesystemow: " + strconv.Itoa(zamontowane)
}
