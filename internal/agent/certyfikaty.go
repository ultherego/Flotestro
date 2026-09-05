package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/opspec"
)

// certificateProbe sklada obraz certyfikatow hosta na potrzeby inwentarza.
var certificateProbe func(context.Context) (certificates.Snapshot, error)

// SetCertificateProbe wskazuje funkcje skladajaca obraz certyfikatow.
func SetCertificateProbe(probe func(context.Context) (certificates.Snapshot, error)) {
	certificateProbe = probe
}

// faktyCertyfikatow tlumaczy nazwy faktow modulu na wyliczenie protokolu.
var faktyCertyfikatow = map[string]helperv1.CertificateRequest_Fact{
	certificates.FaktMetadaneKluczy: helperv1.CertificateRequest_FACT_KEY_METADATA,
	certificates.FaktSledzenie:      helperv1.CertificateRequest_FACT_RENEWAL_TRACKING,
	certificates.FaktTrescPliku:     helperv1.CertificateRequest_FACT_CERTIFICATE_FILES,
}

// ZbierzCertyfikaty sklada obraz certyfikatow hosta.
//
// Kolejnosc bierze sie z tego, skad pochodzi wiedza. Najpierw pytamy helpera,
// czego host pilnuje sam i o ktore pliki panel prosil wczesniej - bo dopiero
// to wyznacza zakres. Potem czytamy pliki bez uprawnien roota, bo certyfikat
// jest jawny. Na koniec zamawiamy u helpera to, czego bez roota nie widac:
// prawa kluczy i pliki zamkniete dla wszystkich poza usluga.
func (e *TaskExecutor) ZbierzCertyfikaty(ctx context.Context,
	cele []certificates.Cel, pelnaLista bool) certificates.Snapshot {
	zakres, sledzenie := e.zakresCertyfikatow(ctx, cele, pelnaLista)

	snapshot := certificates.Skanuj(zakres)
	brakujace := snapshot.Brakujace()
	if len(brakujace) > 0 {
		dodatki, err := e.faktyCertyfikatow(ctx, brakujace, zakres, false)
		if err != nil {
			for _, nazwa := range brakujace {
				snapshot.Missing[nazwa] = "helper: " + err.Error()
			}
		} else {
			snapshot = snapshot.Uzupelnij(dodatki)
		}
	}
	// Stan zlecen certmongera znamy juz z pierwszego pytania: nie pytamy
	// o niego drugi raz tylko dlatego, ze skan zglosil go jako brakujacy.
	if sledzenie != nil {
		snapshot = snapshot.Uzupelnij(*sledzenie)
	}
	return snapshot
}

// zakresCertyfikatow ustala, ktore pliki obejrzec.
func (e *TaskExecutor) zakresCertyfikatow(ctx context.Context,
	cele []certificates.Cel, pelnaLista bool) ([]certificates.Cel, *certificates.Uzupelnienie) {
	dodatki, err := e.faktyCertyfikatow(ctx,
		[]string{certificates.FaktSledzenie}, cele, pelnaLista)
	if err != nil {
		return cele, nil
	}
	zakres := dodatki.Targets
	if len(zakres) == 0 {
		zakres = cele
	}
	// Certyfikaty pod opieka certmongera dokladamy do zakresu, bo host wie
	// o nich sam. Bez tego zakladka pokazywalaby pustke na hoscie, ktory ma
	// wlasny certyfikat domenowy i odnawia go od miesiecy.
	zakres = certificates.DodajSledzone(zakres, dodatki.Tracking)
	return zakres, &dodatki
}

// faktyCertyfikatow zamawia u helpera wyliczone fakty.
func (e *TaskExecutor) faktyCertyfikatow(ctx context.Context, nazwy []string,
	cele []certificates.Cel, pelnaLista bool) (certificates.Uzupelnienie, error) {
	zadane := make([]helperv1.CertificateRequest_Fact, 0, len(nazwy))
	for _, nazwa := range nazwy {
		if fakt, znany := faktyCertyfikatow[nazwa]; znany {
			zadane = append(zadane, fakt)
		}
	}
	if len(zadane) == 0 {
		return certificates.Uzupelnienie{}, nil
	}

	zadanie := &helperv1.CertificateRequest{
		Operation:     helperv1.CertificateRequest_OPERATION_FACTS,
		Facts:         zadane,
		Authoritative: pelnaLista,
	}
	for _, cel := range cele {
		zadanie.Targets = append(zadanie.Targets, &helperv1.CertificateTarget{
			Path: cel.Path, KeyPath: cel.KeyPath, Service: cel.Service,
		})
	}

	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action:         &helperv1.HelperRequest_Certificate{Certificate: zadanie},
	}, time.Minute)
	if err != nil {
		return certificates.Uzupelnienie{}, err
	}
	if !response.GetAccepted() {
		return certificates.Uzupelnienie{}, errors.New("helper: " + response.GetMessage())
	}
	var dodatki certificates.Uzupelnienie
	dane := response.GetCertificateResult().GetFacts()
	if len(dane) == 0 {
		return dodatki, nil
	}
	if err := json.Unmarshal(dane, &dodatki); err != nil {
		return certificates.Uzupelnienie{}, err
	}
	return dodatki, nil
}

// ProbeCertificates odczytuje obraz certyfikatow na potrzeby inwentarza.
//
// Inwentarz nie przynosi ze soba listy panelu: zakres bierze sie z tego, co
// host juz zna - z rejestru helpera i ze zlecen certmongera. Dlatego lista
// nie jest tu pelna lista panelu i niczego w rejestrze nie kasuje.
func (e *TaskExecutor) ProbeCertificates(ctx context.Context) (certificates.Snapshot, error) {
	return e.ZbierzCertyfikaty(ctx, nil, false), nil
}

// applyCertificate wykonuje operacje modulu certyfikatow.
func (e *TaskExecutor) applyCertificate(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.CertificatePayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	if action == opspec.ActionCertificateScan {
		cele := make([]certificates.Cel, 0)
		if payload != nil {
			for _, cel := range payload.Targets {
				cele = append(cele, certificates.Cel{
					Path: cel.Path, KeyPath: cel.KeyPath, Service: cel.Service,
				})
			}
		}
		// Skan zlecony przez panel niesie jego pelna liste celow, wiec host
		// zapamietuje wlasnie ja: cel skasowany w panelu ma zniknac takze
		// z inwentarza, a nie zostac w nim na zawsze.
		snapshot := e.ZbierzCertyfikaty(callCtx, cele, true)
		return wynikCertyfikatu(task, snapshot, "certyfikaty odczytane", nil)
	}

	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"brak payloadu certyfikatu")
	}

	zadanie := &helperv1.CertificateRequest{
		Operation:   helperv1.CertificateRequest_OPERATION_RENEW,
		Path:        payload.Path,
		KeyPath:     payload.KeyPath,
		Owner:       payload.Owner,
		Group:       payload.Group,
		Mode:        payload.Mode,
		KeyMode:     payload.KeyMode,
		ReloadUnit:  payload.ReloadUnit,
		ProbeTarget: payload.ProbeTarget,
		Request:     payload.Request,
	}
	if action == opspec.ActionCertificateDeploy {
		zadanie.Operation = helperv1.CertificateRequest_OPERATION_DEPLOY
		zadanie.Certificate = []byte(payload.Certificate)
		// Klucz pobieramy dopiero teraz, tuz przed podmiana. Wartosc zyje
		// przez chwile w pamieci agenta i helpera - nie ma jej w kopercie
		// zadania, w dzienniku ani w wyniku.
		if !payload.KeySecret.Pusty() {
			if e.sekrety == nil {
				return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError,
					"agent nie ma polaczenia, przez ktore mozna pobrac sekret")
			}
			wartosc, err := e.sekrety(callCtx, task.GetTaskId(),
				payload.KeySecret.Name, payload.KeySecret.Version)
			if err != nil {
				// Powod odmowy jest trescia wyniku; wartosci w nim nie ma.
				return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPrecondition,
					"nie pobrano sekretu "+payload.KeySecret.Name+": "+err.Error())
			}
			zadanie.Key = wartosc
		}
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_Certificate{Certificate: zadanie},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetCertificateResult()
	szczegoly := &agentv1.CertificateResult{
		Message:           wynik.GetMessage(),
		FingerprintSha256: wynik.GetFingerprintSha256(),
		NotAfter:          wynik.GetNotAfter(),
		Probe:             wynik.GetProbe(),
		RolledBack:        wynik.GetRolledBack(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.CertificateResult = szczegoly
		return odrzucone
	}

	// Obraz po operacji sklada agent, tak samo jak przy zwyklym skanie:
	// panel ma zobaczyc plik, ktory naprawde lezy na hoscie, a nie ten,
	// ktory wyslal.
	snapshot := e.ZbierzCertyfikaty(callCtx, nil, false)
	return wynikCertyfikatu(task, snapshot, wynik.GetMessage(), szczegoly)
}

// wynikCertyfikatu sklada wynik zadania wraz z obrazem po operacji.
func wynikCertyfikatu(task *agentv1.TaskEnvelope, snapshot certificates.Snapshot,
	komunikat string, szczegoly *agentv1.CertificateResult) *agentv1.TaskResult {
	zakodowany, err := json.Marshal(snapshot)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	if szczegoly == nil {
		szczegoly = &agentv1.CertificateResult{}
	}
	szczegoly.Snapshot = zakodowany
	if szczegoly.Message == "" {
		szczegoly.Message = komunikat
	}
	return &agentv1.TaskResult{
		TaskId:            task.GetTaskId(),
		Status:            agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:           komunikat,
		CertificateResult: szczegoly,
	}
}
