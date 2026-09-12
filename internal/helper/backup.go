package helper

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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
		// Plan nazwany po rodzaju jest planem kopii, a nie odczytem
		// repozytorium: liczy, co z tego hosta naprawde pojedzie i ile go to
		// kosztuje. Samo zlecenie wyglada tak samo w obu przypadkach.
		if rodzaj := action.GetPlan(); rodzaj != "" {
			if err != nil {
				stan.UnavailableReason = err.Error()
			}
			return odpowiedzPlanuKopii(stan, zlecenie.Definicja,
				rodzaj == backup.PlanSprawdzenie, action.GetReadData())
		}
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
		if odmowa := sprawdzOdciskPlanuKopii(actionCtx, adapter, zlecenie, action, false); odmowa != nil {
			return odmowa
		}
		wynik, err := adapter.Wykonaj(actionCtx, zlecenie, odbiorca)
		if err != nil {
			return odpowiedzBackupu(wynik, err)
		}
		// Kopia, ktorej nikt nie sprawdzil, nie jest sukcesem: repozytorium
		// bywa uszkodzone dokladnie tak, jak wyglada na dzialajace. Host
		// sprawdza je od razu i dopiero wtedy melduje kopie.
		if _, err := adapter.Sprawdz(actionCtx, zlecenie); err != nil {
			odpowiedz := odpowiedzBackupu(wynik, nil)
			odpowiedz.Accepted = false
			odpowiedz.ErrorCode = ErrorPreconditionFailed
			odpowiedz.Message = "kopia powstala, ale repozytorium nie przeszlo sprawdzenia: " + err.Error()
			odpowiedz.BackupResult.Message = odpowiedz.Message
			return odpowiedz
		}
		odpowiedz := odpowiedzBackupu(wynik, nil)
		odpowiedz.BackupResult.Verified = true
		odpowiedz.BackupResult.Message = wynik.Message + "; repozytorium sprawdzone"
		return odpowiedz

	case helperv1.BackupRequest_OPERATION_VERIFY:
		if odmowa := sprawdzOdciskPlanuKopii(actionCtx, adapter, zlecenie, action, true); odmowa != nil {
			return odmowa
		}
		wynik, err := adapter.Sprawdz(actionCtx, zlecenie)
		odpowiedz := odpowiedzBackupu(wynik, err)
		if err == nil {
			odpowiedz.BackupResult.Verified = true
		}
		return odpowiedz

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

// odpowiedzPlanuKopii sklada plan kopii wobec stanu repozytorium.
//
// Rozmiar zakresu liczy host: panel nie wie, ile danych naprawde tam lezy,
// a operator ma to zobaczyc przed zgoda.
func odpowiedzPlanuKopii(stan backup.Stan, definicja backup.Definicja,
	sprawdzenie, readData bool) *helperv1.HelperResponse {
	plan := backup.Zaplanuj(stan, definicja, sprawdzenie, readData, backup.RozmiarSciezki)
	zakodowany, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	stanJSON, err := json.Marshal(stan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	komunikat := "kopia nie powstanie na tym hoscie: " + plan.Refusal
	if plan.Refusal == "" {
		komunikat = strings.Join(plan.Changes, "; ")
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		BackupResult: &helperv1.BackupResult{
			State: stanJSON, Plan: zakodowany, Message: komunikat,
		},
	}
}

// sprawdzOdciskPlanuKopii porownuje plan liczony teraz z tym, na ktory
// operator sie zgodzil. Inny odcisk znaczy, ze zakres albo repozytorium
// zmienily sie od planowania - i to jest odmowa, nie ostrzezenie.
func sprawdzOdciskPlanuKopii(ctx context.Context, adapter backup.Adapter,
	zlecenie backup.Zlecenie, action *helperv1.BackupRequest, sprawdzenie bool) *helperv1.HelperResponse {
	oczekiwany := action.GetPlanHash()
	if oczekiwany == "" {
		return nil
	}
	stan, err := adapter.Plan(ctx, zlecenie)
	if err != nil {
		stan.UnavailableReason = err.Error()
	}
	teraz := backup.Zaplanuj(stan, zlecenie.Definicja, sprawdzenie,
		zlecenie.ReadData, backup.RozmiarSciezki)
	if teraz.PlanHash != oczekiwany {
		return reject(ErrorPreconditionFailed,
			"zakres kopii albo repozytorium zmienily sie od planowania; operacja wymaga nowego planu")
	}
	return nil
}
