package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/opspec"
)

// fileProbe czyta stan plikow zarzadzanych przez panel.
var fileProbe func(context.Context) (files.Snapshot, error)

// SetFileProbe wskazuje funkcje odczytujaca stan plikow.
func SetFileProbe(probe func(context.Context) (files.Snapshot, error)) {
	fileProbe = probe
}

// ProbeFiles odczytuje stan plikow zarzadzanych na hoscie.
func (e *TaskExecutor) ProbeFiles(ctx context.Context) (files.Snapshot, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_File{
			File: &helperv1.FileRequest{Operation: helperv1.FileRequest_OPERATION_LIST},
		},
	}, time.Minute)
	if err != nil {
		return files.Snapshot{}, err
	}
	var snapshot files.Snapshot
	dane := response.GetFileResult().GetSnapshot()
	if len(dane) == 0 {
		return snapshot, nil
	}
	if err := json.Unmarshal(dane, &snapshot); err != nil {
		return files.Snapshot{}, err
	}
	return snapshot, nil
}

// applyFile wykonuje operacje modulu plikow.
func (e *TaskExecutor) applyFile(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.FilePayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "brak payloadu pliku")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	operacja := helperv1.FileRequest_OPERATION_LIST
	switch action {
	case opspec.ActionFileRead:
		operacja = helperv1.FileRequest_OPERATION_READ
	case opspec.ActionFileEnsure, opspec.ActionFileRollback:
		operacja = helperv1.FileRequest_OPERATION_ENSURE
	case opspec.ActionFileRemove:
		operacja = helperv1.FileRequest_OPERATION_REMOVE
	}

	// Tresc z magazynu pobieramy dopiero teraz, tuz przed zapisem. Wartosc
	// zyje przez chwile w pamieci agenta i helpera - nie ma jej w kopercie
	// zadania, w dzienniku ani w wyniku.
	tresc := []byte(payload.Content)
	if !payload.ContentSecret.Pusty() {
		if e.sekrety == nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError,
				"agent nie ma polaczenia, przez ktore mozna pobrac sekret")
		}
		wartosc, err := e.sekrety(callCtx, task.GetTaskId(),
			payload.ContentSecret.Name, payload.ContentSecret.Version)
		if err != nil {
			// Powod odmowy jest tresci wyniku; wartosci w nim nie ma.
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPrecondition,
				"nie pobrano sekretu "+payload.ContentSecret.Name+": "+err.Error())
		}
		tresc = wartosc
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_File{
			File: &helperv1.FileRequest{
				Operation:      operacja,
				Path:           payload.Path,
				Content:        tresc,
				Mode:           payload.Mode,
				Owner:          payload.Owner,
				Group:          payload.Group,
				ExpectedSha256: payload.ExpectedSHA256,
				Validator:      payload.Validator,
				FromSecret:     !payload.ContentSecret.Pusty(),
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetFileResult()
	szczegoly := &agentv1.FileResult{
		Snapshot:        wynik.GetSnapshot(),
		Message:         wynik.GetMessage(),
		Content:         wynik.GetContent(),
		Sha256:          wynik.GetSha256(),
		Truncated:       wynik.GetTruncated(),
		ValidatorOutput: wynik.GetValidatorOutput(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.FileResult = szczegoly
		return odrzucone
	}
	komunikat := wynik.GetMessage()
	if komunikat == "" && action == opspec.ActionFileRead {
		komunikat = "plik odczytany"
		if wynik.GetTruncated() {
			// Urwana tresc bez oznaczenia wygladalaby jak caly plik i tak
			// samo wrocilaby na host przy nastepnym zapisie.
			komunikat = "plik odczytany, tresc urwana na granicy modulu"
		}
	}
	return &agentv1.TaskResult{
		TaskId:     task.GetTaskId(),
		Status:     agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:    komunikat,
		FileResult: szczegoly,
	}
}
