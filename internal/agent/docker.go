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

// dockerProbe czyta stan silnika kontenerow przez helpera. Agent nie ma
// dostepu do gniazda Dockera i nie moze go miec: czlonkostwo w grupie docker
// jest rownowazne rootowi.
var dockerProbe func(context.Context, bool) (docker.Snapshot, error)

// SetDockerProbe wskazuje funkcje odczytujaca stan kontenerow.
func SetDockerProbe(probe func(context.Context, bool) (docker.Snapshot, error)) {
	dockerProbe = probe
}

// ProbeDocker odczytuje stan silnika kontenerow przez helpera.
// full decyduje, czy odpowiedz niesie pelne listy, czy samo podsumowanie.
func (e *TaskExecutor) ProbeDocker(ctx context.Context, full bool) (docker.Snapshot, error) {
	zakres := helperv1.DockerReadRequest_SCOPE_SUMMARY
	timeout := 30 * time.Second
	if full {
		zakres = helperv1.DockerReadRequest_SCOPE_FULL
		timeout = 2 * time.Minute
	}

	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_DockerRead{
			DockerRead: &helperv1.DockerReadRequest{Scope: zakres},
		},
	}, timeout)
	if err != nil {
		return docker.Snapshot{}, err
	}
	wynik := response.GetDockerResult()
	if wynik == nil {
		return docker.Snapshot{}, errors.New("helper nie odeslal stanu kontenerow")
	}
	if len(wynik.GetSnapshot()) == 0 {
		return docker.Snapshot{
			Summary: docker.Summary{UnavailableReason: wynik.GetUnavailableReason()},
		}, nil
	}

	var snapshot docker.Snapshot
	if err := json.Unmarshal(wynik.GetSnapshot(), &snapshot); err != nil {
		return docker.Snapshot{}, err
	}
	return snapshot, nil
}

// readDocker wykonuje operacje odczytu stanu kontenerow.
//
// Odczyt jest pelny: operator otworzyl zakladke i chce zobaczyc kontenery,
// obrazy, sieci i wolumeny. Cykl inwentarza pobiera samo podsumowanie, wiec
// te dwie sciezki nie obciazaja hosta tym samym.
func (e *TaskExecutor) readDocker(ctx context.Context, task *agentv1.TaskEnvelope) *agentv1.TaskResult {
	snapshot, err := e.ProbeDocker(ctx, true)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	// Niedostepny silnik nie jest bledem operacji: odczyt sie udal, a jego
	// trescia jest informacja, ze silnik nie odpowiada.
	return &agentv1.TaskResult{
		TaskId: task.GetTaskId(),
		Status: agentv1.TaskResult_STATUS_SUCCEEDED,
		DockerResult: &agentv1.DockerReadResult{
			Snapshot:          encoded,
			UnavailableReason: snapshot.Summary.UnavailableReason,
		},
	}
}

// applyDocker wykonuje operacje na kontenerach przez helpera.
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
				Operation:      operacjaDoHelpera(action.GetOperation()),
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

	// Stan przed i po trafia do wyniku takze przy bledzie: administrator musi
	// wiedziec, czy zmiana zdazyla wejsc w zycie, zanim operacja padla.
	szczegoly := wynikDockeraDoProto(response.GetDockerActionResult())
	if !response.GetAccepted() {
		wynik := rejected(agentv1.TaskResult_STATUS_FAILED,
			response.GetErrorCode(), response.GetMessage())
		wynik.TaskId = task.GetTaskId()
		wynik.DockerActionResult = szczegoly
		return wynik
	}
	return &agentv1.TaskResult{
		TaskId:             task.GetTaskId(),
		Status:             agentv1.TaskResult_STATUS_SUCCEEDED,
		DockerActionResult: szczegoly,
	}
}

func operacjaDoHelpera(operacja agentv1.DockerAction_Operation) helperv1.DockerActionRequest_Operation {
	switch operacja {
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

func wynikDockeraDoProto(wynik *helperv1.DockerActionResult) *agentv1.DockerActionResult {
	if wynik == nil {
		return nil
	}
	return &agentv1.DockerActionResult{
		Before:         wynik.GetBefore(),
		After:          wynik.GetAfter(),
		Removed:        wynik.GetRemoved(),
		ReclaimedBytes: wynik.ReclaimedBytes,
		ImageDigest:    wynik.GetImageDigest(),
	}
}
