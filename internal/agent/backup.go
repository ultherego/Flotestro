package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/opspec"
)

// StanBackupu opisuje narzedzia backupu widoczne na hoscie.
//
// To jest wszystko, co da sie powiedziec o backupie bez poswiadczen:
// czy host ma czym go zrobic. Stan repozytorium - kiedy ostatnia kopia sie
// udala i ile zajmuje - wymaga hasla, wiec jest operacja, a nie inwentarzem.
type StanBackupu struct {
	Tools []NarzedzieBackupu `json:"tools"`
	// Runbooks wylicza skrypty, ktore administrator hosta udostepnil panelowi.
	Runbooks []string `json:"runbooks,omitempty"`
	// RunbooksKnown mowi, czy katalog runbookow w ogole dalo sie odczytac.
	RunbooksKnown bool   `json:"runbooks_known"`
	ObservedAt    string `json:"observed_at"`
}

// NarzedzieBackupu opisuje jedno narzedzie na hoscie.
type NarzedzieBackupu struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
}

// ZbierzBackup czyta, czym host moze zrobic kopie.
func ZbierzBackup(ctx context.Context) StanBackupu {
	stan := StanBackupu{ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, nazwa := range []string{backup.NarzedzieRestic, backup.NarzedzieBorg} {
		adapter, err := backup.Wybierz(nazwa)
		if err != nil {
			continue
		}
		opis := NarzedzieBackupu{Name: nazwa, Available: adapter.Dostepny()}
		if opis.Available {
			opis.Version = adapter.Wersja(ctx)
		}
		stan.Tools = append(stan.Tools, opis)
	}
	runbooki, znane := backup.WykazRunbookow()
	stan.Runbooks = runbooki
	stan.RunbooksKnown = znane
	stan.Tools = append(stan.Tools, NarzedzieBackupu{
		Name: backup.NarzedzieRunbook, Available: len(runbooki) > 0,
	})
	return stan
}

// applyBackup wykonuje operacje backupu.
func (e *TaskExecutor) applyBackup(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.BackupPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"brak payloadu backupu")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	operacja := helperv1.BackupRequest_OPERATION_PLAN
	switch action {
	case opspec.ActionBackupRun:
		operacja = helperv1.BackupRequest_OPERATION_RUN
	case opspec.ActionBackupVerify:
		operacja = helperv1.BackupRequest_OPERATION_VERIFY
	case opspec.ActionBackupRestore:
		operacja = helperv1.BackupRequest_OPERATION_RESTORE
	}

	zadanie := &helperv1.BackupRequest{
		Operation: operacja,
		Id:        payload.ID, Tool: payload.Tool, Repository: payload.Repository,
		Paths: payload.Paths, Excludes: payload.Excludes, Tags: payload.Tags,
		KeepLast: int32(payload.KeepLast), KeepDaily: int32(payload.KeepDaily),
		KeepWeekly: int32(payload.KeepWeekly), KeepMonthly: int32(payload.KeepMonthly),
		Prune: payload.Prune, Runbook: payload.Runbook,
		Initialize: payload.Initialize, ReadData: payload.ReadData,
		SnapshotId: payload.SnapshotID, Target: payload.Target,
		Include: payload.Include, Overwrite: payload.Overwrite,
	}

	// Poswiadczenia pobieramy dopiero teraz, tuz przed operacja. Zyja przez
	// chwile w pamieci agenta i helpera - nie ma ich w kopercie zadania,
	// w dzienniku ani w wyniku.
	if !payload.PasswordSecret.Pusty() {
		wartosc, wynik := e.pobierzSekret(callCtx, task, *payload.PasswordSecret)
		if wynik != nil {
			return wynik
		}
		zadanie.Password = wartosc
	}
	if len(payload.EnvSecrets) > 0 {
		zadanie.Env = map[string][]byte{}
		for nazwa, odnosnik := range payload.EnvSecrets {
			wartosc, wynik := e.pobierzSekret(callCtx, task, odnosnik)
			if wynik != nil {
				return wynik
			}
			zadanie.Env[nazwa] = wartosc
		}
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		WantProgress:   action == opspec.ActionBackupRun,
		Action:         &helperv1.HelperRequest_Backup{Backup: zadanie},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetBackupResult()
	szczegoly := &agentv1.BackupResult{
		State:   wynik.GetState(),
		Outcome: wynik.GetOutcome(),
		Message: wynik.GetMessage(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.BackupResult = szczegoly
		return odrzucone
	}
	return &agentv1.TaskResult{
		TaskId:       task.GetTaskId(),
		Status:       agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:      wynik.GetMessage(),
		BackupResult: szczegoly,
	}
}

// pobierzSekret pobiera wartosc z magazynu tuz przed operacja.
func (e *TaskExecutor) pobierzSekret(ctx context.Context, task *agentv1.TaskEnvelope,
	odnosnik opspec.SecretRef) ([]byte, *agentv1.TaskResult) {
	if e.sekrety == nil {
		return nil, rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError,
			"agent nie ma polaczenia, przez ktore mozna pobrac sekret")
	}
	wartosc, err := e.sekrety(ctx, task.GetTaskId(), odnosnik.Name, odnosnik.Version)
	if err != nil {
		// Powod odmowy jest trescia wyniku; wartosci w nim nie ma.
		return nil, rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPrecondition,
			"nie pobrano sekretu "+odnosnik.Name+": "+err.Error())
	}
	return wartosc, nil
}

// backupJSON dekoduje stan repozytorium z wyniku zadania.
func backupJSON(dane []byte) (backup.Stan, bool) {
	var stan backup.Stan
	if len(dane) == 0 {
		return stan, false
	}
	if err := json.Unmarshal(dane, &stan); err != nil {
		return stan, false
	}
	return stan, true
}
