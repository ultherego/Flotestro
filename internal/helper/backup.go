package helper

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/backup"
)

// applyBackup steruje narzedziem backupu.
//
// Helper nie robi backupu sam: robi go narzedzie, ktore host juz ma i ktoremu
// administrator juz ufa. Tutaj jest tylko to, czego narzedzie samo nie zrobi -
// sprawdzenie celu odtworzenia, podanie poswiadczen srodowiskiem i zamiana
// wyniku na cos, co panel umie pokazac.
func (s *Server) applyBackup(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.BackupRequest, postep func(*helperv1.TaskProgress)) *helperv1.HelperResponse {
	// Backup trwa dlugo i to jest normalne. Limit bierzemy ze zlecenia, bo to
	// panel wie, ile czasu operator dal tej operacji.
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 12*time.Hour {
		timeout = 2 * time.Hour
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	definicja := backup.Definicja{
		ID: action.GetId(), Tool: action.GetTool(), Repository: action.GetRepository(),
		Paths: action.GetPaths(), Excludes: action.GetExcludes(), Tags: action.GetTags(),
		KeepLast: int(action.GetKeepLast()), KeepDaily: int(action.GetKeepDaily()),
		KeepWeekly: int(action.GetKeepWeekly()), KeepMonthly: int(action.GetKeepMonthly()),
		Prune: action.GetPrune(), Runbook: action.GetRunbook(),
		Initialize: action.GetInitialize(),
	}
	if err := definicja.Waliduj(); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	adapter, err := backup.Wybierz(definicja.Tool)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if !adapter.Dostepny() {
		return reject(ErrorUnsupported, "ten host nie ma narzedzia "+definicja.Tool)
	}

	zlecenie := backup.Zlecenie{
		Definicja: definicja,
		Haslo:     action.GetPassword(),
		ReadData:  action.GetReadData(),
		Odtworzenie: backup.Odtworzenie{
			SnapshotID: action.GetSnapshotId(), Target: action.GetTarget(),
			Include: action.GetInclude(), Overwrite: action.GetOverwrite(),
		},
	}
	if len(action.GetEnv()) > 0 {
		zlecenie.Srodowisko = map[string][]byte{}
		for nazwa, wartosc := range action.GetEnv() {
			zlecenie.Srodowisko[nazwa] = wartosc
		}
	}

	odbiorca := backup.PostepFunc(nil)
	if postep != nil {
		odbiorca = func(p backup.Postep) {
			postep(&helperv1.TaskProgress{Percent: p.Percent, Message: p.Message})
		}
	}

	switch action.GetOperation() {
	case helperv1.BackupRequest_OPERATION_PLAN:
		stan, err := adapter.Plan(actionCtx, zlecenie)
		zakodowany, blad := json.Marshal(stan)
		if blad != nil {
			return reject(ErrorExecFailed, blad.Error())
		}
		if err != nil {
			// Nieodczytane repozytorium nie jest repozytorium pustym, wiec
			// stan idzie do panelu razem z powodem - a operacja jest odmowa.
			return &helperv1.HelperResponse{
				Accepted:  false,
				ErrorCode: kodBledu(err),
				Message:   err.Error(),
				BackupResult: &helperv1.BackupResult{
					State: zakodowany, Message: err.Error(),
				},
			}
		}
		return &helperv1.HelperResponse{
			Accepted:     true,
			BackupResult: &helperv1.BackupResult{State: zakodowany, Message: "stan repozytorium odczytany"},
		}

	case helperv1.BackupRequest_OPERATION_RUN:
		wynik, err := adapter.Wykonaj(actionCtx, zlecenie, odbiorca)
		return odpowiedzBackupu(wynik, err)

	case helperv1.BackupRequest_OPERATION_VERIFY:
		wynik, err := adapter.Sprawdz(actionCtx, zlecenie)
		return odpowiedzBackupu(wynik, err)

	case helperv1.BackupRequest_OPERATION_RESTORE:
		if err := backup.WalidujOdtworzenie(zlecenie.Odtworzenie); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		// Cel sprawdzamy tuz przed rozpakowaniem: tylko host wie, co w tym
		// katalogu naprawde lezy, i wie to dopiero teraz.
		if err := backup.SprawdzCel(zlecenie.Odtworzenie); err != nil {
			return reject(ErrorPreconditionFailed, err.Error())
		}
		wynik, err := adapter.Odtworz(actionCtx, zlecenie)
		return odpowiedzBackupu(wynik, err)
	}
	return reject(ErrorUnknownAction, "nieznana operacja backupu")
}

// odpowiedzBackupu sklada odpowiedz z wyniku operacji.
//
// Wynik idzie do panelu takze przy bledzie: przerwana kopia zostawia stan,
// o ktorym trzeba powiedziec, a nie samo slowo "nie powiodlo sie".
func odpowiedzBackupu(wynik backup.Wynik, err error) *helperv1.HelperResponse {
	zakodowany, blad := json.Marshal(wynik)
	if blad != nil {
		return reject(ErrorExecFailed, blad.Error())
	}
	if err != nil {
		return &helperv1.HelperResponse{
			Accepted:  false,
			ErrorCode: kodBledu(err),
			Message:   err.Error(),
			BackupResult: &helperv1.BackupResult{
				Outcome: zakodowany, Message: err.Error(),
			},
		}
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		BackupResult: &helperv1.BackupResult{
			Outcome: zakodowany, Message: wynik.Message,
		},
	}
}

// kodBledu rozroznia przerwanie od zwyklego niepowodzenia narzedzia.
func kodBledu(err error) string {
	if errors.Is(err, backup.ErrPrzerwane) {
		return ErrorTimeout
	}
	return ErrorExecFailed
}
