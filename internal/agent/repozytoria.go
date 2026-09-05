package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// ZbierzRepozytoria czyta zrodla pakietow widoczne na hoscie.
//
// Bez roota: pliki zrodel sa jawne. Wyjatkiem jest zrodlo z haslem, ktoremu
// panel sam nadal prawa roota - takie zostaje na liscie z powodem, zamiast
// z niej zniknac.
func ZbierzRepozytoria(menedzer string) packages.ObrazRepozytoriow {
	return packages.CzytajRepozytoria(menedzer)
}

// applyRepository wykonuje zapis zrodla pakietow.
func (e *TaskExecutor) applyRepository(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.RepositoryPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"brak payloadu zrodla pakietow")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	zadanie := &helperv1.RepositoryRequest{
		Id: payload.ID, Name: payload.Name, Url: payload.URL,
		Suites: payload.Suites, Components: payload.Components,
		Architectures: payload.Architectures, Enabled: payload.Enabled,
		Priority: int32(payload.Priority), GpgKey: payload.GPGKey,
		AllowUnsigned: payload.AllowUnsigned, Username: payload.Username,
		Remove: payload.Remove,
	}
	// Haslo pobieramy dopiero teraz, tuz przed zapisem. Wartosc zyje przez
	// chwile w pamieci agenta i helpera - nie ma jej w kopercie zadania,
	// w dzienniku ani w wyniku. W pliku zrodla zostaje sama nazwa sekretu.
	if !payload.PasswordSecret.Pusty() && !payload.Remove {
		if e.sekrety == nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError,
				"agent nie ma polaczenia, przez ktore mozna pobrac sekret")
		}
		wartosc, err := e.sekrety(callCtx, task.GetTaskId(),
			payload.PasswordSecret.Name, payload.PasswordSecret.Version)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPrecondition,
				"nie pobrano sekretu "+payload.PasswordSecret.Name+": "+err.Error())
		}
		zadanie.Password = wartosc
		zadanie.SecretName = payload.PasswordSecret.Name
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_Repository{Repository: zadanie},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetRepositoryResult()
	szczegoly := &agentv1.RepositoryResult{
		Snapshot:          wynik.GetSnapshot(),
		Message:           wynik.GetMessage(),
		GpgKeyFingerprint: wynik.GetGpgKeyFingerprint(),
		RolledBack:        wynik.GetRolledBack(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.RepositoryResult = szczegoly
		return odrzucone
	}

	// Obraz zrodel po zmianie sklada helper, bo tylko on widzi pliki, ktorym
	// sam nadal prawa roota.
	if len(szczegoly.Snapshot) == 0 {
		obraz := ZbierzRepozytoria(e.menedzerPakietow())
		if zakodowany, err := json.Marshal(obraz); err == nil {
			szczegoly.Snapshot = zakodowany
		}
	}
	return &agentv1.TaskResult{
		TaskId:           task.GetTaskId(),
		Status:           agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:          wynik.GetMessage(),
		RepositoryResult: szczegoly,
	}
}

// menedzerPakietow zwraca nazwe menedzera hosta albo pustke.
func (e *TaskExecutor) menedzerPakietow() string {
	menedzer, err := packages.Detect()
	if err != nil {
		return ""
	}
	return menedzer.Name()
}
