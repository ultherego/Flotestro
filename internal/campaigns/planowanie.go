package campaigns

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/ultherego/flotestro/internal/jobs"
	backupmodul "github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/modules/storage"
	"github.com/ultherego/flotestro/internal/opspec"
)

// planuj prowadzi faze planowania kampanii.
//
// Kazdy host liczy wlasny plan, bo dwa hosty wybrane tym samym zamowieniem
// prawie nigdy nie maja tego samego diffu. Faza konczy sie odciskiem calego
// zestawu planow: to on wchodzi do odcisku zatwierdzenia, wiec zgoda dotyczy
// tych planow, a nie samego zamowienia.
//
// Plan jest odczytem i niczego nie zmienia, wiec faza nie ma fal ani limitu
// rownoleglosci kampanii: hosty licza rownolegle, a blokady zasobow po stronie
// agenta i tak nie pozwola planowi wejsc w trwajaca transakcje pakietowa.
func (o *Orchestrator) planuj(ctx context.Context, campaign Campaign, targets []Target) error {
	akcja := opspec.AkcjaPlanowania(opspec.ActionType(campaign.ActionType))
	if akcja == "" {
		// Kampania nie powinna byla powstac; zatrzymanie jest jedyna uczciwa
		// odpowiedzia, bo planu nie ma czym policzyc.
		return o.pauseOnThreshold(ctx, campaign,
			"operacji nie da sie zaplanowac na hostach", 0, 0)
	}

	var payload opspec.Payload
	if len(campaign.Payload) > 0 {
		if err := json.Unmarshal(campaign.Payload, &payload); err != nil {
			return err
		}
	}

	gotowe := 0
	for i := range targets {
		target := &targets[i]
		if target.State.Finished() {
			gotowe++
			continue
		}
		switch target.State {
		case TargetPending:
			if err := o.zlecPlan(ctx, campaign, target, akcja,
				opspec.ActionType(campaign.ActionType), payload); err != nil {
				return err
			}
		case TargetPlanning:
			zamkniete, err := o.odbierzPlan(ctx, campaign, target)
			if err != nil {
				return err
			}
			if zamkniete {
				gotowe++
			}
		}
	}

	if gotowe < len(targets) {
		return nil
	}
	return o.zamknijPlanowanie(ctx, campaign, targets)
}

// zlecPlan uruchamia na hoscie operacje planujaca.
func (o *Orchestrator) zlecPlan(ctx context.Context, campaign Campaign, target *Target,
	akcja, zmiana opspec.ActionType, payload opspec.Payload) error {
	host, err := o.hosts.Get(ctx, target.HostID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetSkipped, "host_unavailable", err.Error())
		return nil
	}
	// Host niepodlaczony nie jest bledem planowania: plan poczeka, az wroci.
	if host.ConnectionState != "online" {
		return nil
	}

	jobID, err := o.submitJob(ctx, campaign, host, akcja, planPayload(akcja, zmiana, payload),
		"campaign:"+campaign.ID+":plan:"+target.HostID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetFailed, "plan_create_failed", err.Error())
		return nil
	}
	if err := o.store.AttachJob(ctx, target.ID, "plan_job_id", jobID); err != nil {
		return err
	}
	if err := o.store.UpdateTarget(ctx, target.ID, TargetPlanning, "", ""); err != nil {
		return err
	}
	target.State = TargetPlanning
	target.PlanJobID = &jobID
	o.log.Info("kampania planuje host",
		"campaign_id", campaign.ID, "host_id", target.HostID, "job_id", jobID)
	return nil
}

// odbierzPlan zapisuje wynik planowania hosta. Zwraca true, gdy host ma
// rozstrzygniety plan - wlasny albo brak, ktory konczy jego udzial.
func (o *Orchestrator) odbierzPlan(ctx context.Context, campaign Campaign,
	target *Target) (bool, error) {
	if target.PlanJobID == nil {
		return false, nil
	}
	job, err := o.jobs.Get(ctx, *target.PlanJobID)
	if err != nil {
		return false, err
	}
	if !jobs.State(job.State).Terminal() {
		return false, nil
	}
	if job.State != jobs.StateSucceeded {
		o.finishTarget(ctx, campaign, target, TargetFailed,
			orDefault(job.ResultErrorCode, "plan_failed"), job.ResultMessage)
		return true, nil
	}

	hash, plan, err := o.odciskPlanu(ctx, *target.PlanJobID)
	if err != nil {
		return false, err
	}
	if hash == "" {
		// Plan bez odcisku nie jest planem: nie da sie go zwiazac ze zgoda.
		o.finishTarget(ctx, campaign, target, TargetFailed, "plan_hash_missing",
			"host nie podal odcisku planu")
		return true, nil
	}
	if powod := odmowaPlanu(plan); powod != "" {
		// Plan, ktory mowi "ta zmiana nie wejdzie na ten host", jest
		// odpowiedzia, a nie awaria odczytu. Host konczy udzial tutaj,
		// zanim ktokolwiek zatwierdzi cokolwiek - a nie w polowie floty,
		// gdy zmiana odbija sie od hosta w trakcie wykonania.
		o.finishTarget(ctx, campaign, target, TargetIneligible, "plan_refused", powod)
		return true, nil
	}
	if err := o.store.ZapiszPlan(ctx, campaign.ID, target.HostID, hash, plan); err != nil {
		return false, err
	}
	// Host wraca do kolejki: plan jest policzony, zmiana ruszy po zgodzie.
	if err := o.store.UpdateTarget(ctx, target.ID, TargetPending, "", ""); err != nil {
		return false, err
	}
	target.State = TargetPending
	return true, nil
}

// odciskPlanu wyciaga odcisk planu z wyniku zadania planujacego.
//
// Odcisk moze pochodzic z dwoch miejsc i to nie jest to samo. Odcisk policzony
// przez hosta wiaze takze wykonanie: transakcja pakietowa i wdrozenie Compose
// niosa go z powrotem, a host odmawia, gdy przestal pasowac do stanu, ktory ma
// teraz. Odcisk policzony w panelu wiaze wylacznie zgode: mowi, ze operator
// zatwierdzil dokladnie ten diff, ktory host zglosil.
//
// Wolimy odcisk hosta wszedzie, gdzie istnieje. Cichy zamiennik po stronie
// panelu obiecywalby wiecej, niz naprawde pilnuje.
func (o *Orchestrator) odciskPlanu(ctx context.Context, jobID string) (string, json.RawMessage, error) {
	proby, err := o.jobs.Attempts(ctx, jobID)
	if err != nil {
		return "", nil, err
	}
	for i := len(proby) - 1; i >= 0; i-- {
		detal := proby[i].Detail
		if len(detal) == 0 {
			continue
		}
		if odcisk := odciskZHosta(detal); odcisk != "" {
			return odcisk, detal, nil
		}
		// Plan bez wlasnego odcisku nadal jest planem: to opis diffu, ktory
		// host wlasnie policzyl. Liczymy odcisk z jego tresci, zeby zgoda
		// dotyczyla tego opisu, a nie samego faktu, ze plan powstal.
		if odcisk := OdciskTresci(detal); odcisk != "" {
			return odcisk, detal, nil
		}
	}
	return "", nil, nil
}

// odciskZHosta czyta odcisk policzony na hoscie.
//
// Kazda rodzina nazywa go inaczej, bo kazda liczy go z czego innego: plan
// pakietowy z listy zmian, plan Compose z manifestu i digestow obrazow.
func odciskZHosta(detal json.RawMessage) string {
	var szczegol struct {
		PlanHash string `json:"plan_hash"`
		Kind     string `json:"kind"`
		Payload  struct {
			Digest string `json:"digest"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(detal, &szczegol); err != nil {
		return ""
	}
	if szczegol.PlanHash != "" {
		return szczegol.PlanHash
	}
	if szczegol.Kind == "compose" {
		return szczegol.Payload.Digest
	}
	return ""
}

// OdciskTresci liczy odcisk planu z jego opisu.
func OdciskTresci(detal json.RawMessage) string {
	if len(detal) == 0 {
		return ""
	}
	// Kanonizujemy przez ponowne zakodowanie: kolejnosc kluczy w JSON-ie od
	// hosta nie jest decyzja i nie moze zmieniac odcisku.
	var wartosc any
	if err := json.Unmarshal(detal, &wartosc); err != nil {
		return ""
	}
	kanoniczny, err := json.Marshal(wartosc)
	if err != nil {
		return ""
	}
	return odciskTekstu([]string{string(kanoniczny)})
}

// zamknijPlanowanie liczy odcisk zestawu planow i przenosi kampanie do
// decyzji operatora.
func (o *Orchestrator) zamknijPlanowanie(ctx context.Context, campaign Campaign,
	targets []Target) error {
	plany, err := o.store.Plany(ctx, campaign.ID)
	if err != nil {
		return err
	}
	if len(plany) == 0 {
		// Zaden host nie policzyl planu: nie ma czego zatwierdzac.
		return o.pauseOnThreshold(ctx, campaign,
			"zaden host nie policzyl planu zmiany", len(targets), len(targets))
	}

	zestaw := OdciskZestawuPlanow(plany)
	odcisk, err := OdciskZPlanami(campaign, zestaw)
	if err != nil {
		return err
	}
	dalej := StatePlanned
	if campaign.RequiresApproval {
		dalej = StateAwaitingApproval
	}
	if err := o.store.ZamknijPlanowanie(ctx, campaign.ID, zestaw, odcisk, dalej); err != nil {
		return err
	}
	o.log.Info("kampania zamknela planowanie",
		"campaign_id", campaign.ID, "planow", len(plany), "plan_set_hash", zestaw)
	return nil
}

// planPayload przycina payload zmiany do tego, co potrzebne planowi.
//
// Plan pyta o ten sam stan docelowy, ale innym typem operacji. Dla wiekszosci
// rodzin payload jest ten sam - plan pliku czy manifestu Compose potrzebuje
// dokladnie tego, co zmiana - i tylko transakcja pakietowa ma osobny ksztalt:
// aktualizacja niesie odcisk zatwierdzonego planu, a plan go dopiero liczy.
func planPayload(akcja opspec.ActionType, zmiana opspec.ActionType,
	payload opspec.Payload) opspec.Payload {
	// Plan urzadzenia dostaje nazwe rodzaju: sama sciezka /dev/... nie mowi,
	// czy operator sprawdza, czy rozszerza.
	// Plan kopii tez dostaje nazwe rodzaju: to samo zlecenie sluzy odczytowi
	// repozytorium i planowaniu kopii.
	if zmiana == opspec.ActionBackupRun || zmiana == opspec.ActionBackupVerify {
		if payload.Backup != nil {
			kopia := *payload.Backup
			kopia.Plan = backupmodul.PlanKopia
			if zmiana == opspec.ActionBackupVerify {
				kopia.Plan = backupmodul.PlanSprawdzenie
			}
			payload.Backup = &kopia
		}
		return payload
	}
	if rodzaj := rodzajPlanuUrzadzenia(zmiana); rodzaj != "" && payload.Storage != nil {
		przestrzen := *payload.Storage
		przestrzen.Plan = rodzaj
		payload.Storage = &przestrzen
		return payload
	}
	if akcja != opspec.ActionPackagePlan {
		return payload
	}
	plan := &opspec.PackagePlanPayload{Mode: trybPlanu(zmiana)}
	switch {
	case payload.PackageUpgrade != nil:
		plan.OnlyPackages = payload.PackageUpgrade.Packages
		plan.SecurityOnly = payload.PackageUpgrade.SecurityOnly
	case payload.PackageChange != nil:
		plan.OnlyPackages = payload.PackageChange.Packages
	}
	return opspec.Payload{PackagePlan: plan}
}

// rodzajPlanuUrzadzenia mowi, o ktory plan urzadzenia pytamy.
func rodzajPlanuUrzadzenia(zmiana opspec.ActionType) string {
	switch zmiana {
	case opspec.ActionFilesystemCheck:
		return storage.PlanSprawdzenie
	case opspec.ActionFilesystemResize:
		return storage.PlanRozszerzenieFS
	case opspec.ActionLVMExtend:
		return storage.PlanRozszerzenieLV
	}
	return ""
}

// trybPlanu mowi, o co pytamy planer pakietow.
func trybPlanu(zmiana opspec.ActionType) string {
	switch zmiana {
	case opspec.ActionPackageInstall:
		return "install"
	case opspec.ActionPackageRemove:
		return "remove"
	default:
		return "upgrade"
	}
}

// zPlanem dokleda do payloadu zmiany odcisk planu policzonego na tym hoscie.
//
// Bez tego kampania wyslalaby zmiane bez planu, a host nie mialby czego
// porownac ze stanem, ktory ma teraz.
func zPlanem(action opspec.ActionType, payload opspec.Payload, hash string,
	plan json.RawMessage) opspec.Payload {
	switch action {
	case opspec.ActionPackageInstall:
		instalacja := &opspec.PackageChangePayload{PlanHash: hash}
		if payload.PackageChange != nil {
			instalacja.Packages = payload.PackageChange.Packages
		}
		payload.PackageChange = instalacja

	case opspec.ActionPackageUpgrade:
		aktualizacja := &opspec.PackageUpgradePayload{PlanHash: hash}
		if payload.PackageUpgrade != nil {
			aktualizacja.Packages = payload.PackageUpgrade.Packages
			aktualizacja.SecurityOnly = payload.PackageUpgrade.SecurityOnly
		}
		payload.PackageUpgrade = aktualizacja

	case opspec.ActionFileEnsure, opspec.ActionFileRemove, opspec.ActionFileRollback:
		// Plik wiaze sie z planem inaczej niz pakiety: host nie porownuje
		// odcisku planu, tylko odcisk tresci, ktora zastal. To jest ten sam
		// mechanizm, ktory chroni pojedynczy zapis przed nadpisaniem cudzej
		// zmiany - a tutaj daje kazdemu hostowi jego wlasny warunek wstepny.
		if odcisk := odciskZastanejTresci(plan); odcisk != "" && payload.File != nil {
			plik := *payload.File
			plik.ExpectedSHA256 = odcisk
			payload.File = &plik
		}

	case opspec.ActionFirewallRuleEnsure, opspec.ActionFirewallRuleRemove,
		opspec.ActionFirewallZonePort, opspec.ActionFirewallZoneService:
		// Zapora wiaze sie odciskiem calego zestawu regul, ktory host mial
		// przy planowaniu: zmiana ma wejsc w to sasiedztwo, ktore operator
		// ogladal, a nie w inne.
		if odcisk := odciskZestawuRegul(plan); odcisk != "" && payload.Firewall != nil {
			regula := *payload.Firewall
			regula.ExpectedHash = odcisk
			payload.Firewall = &regula
		}

	case opspec.ActionNetworkProfileApply, opspec.ActionNetworkRouteEnsure,
		opspec.ActionNetworkMTUSet:
		// Siec wiaze sie odciskiem planu: host liczy plan jeszcze raz przed
		// zmiana i profil zmieniony od planowania zatrzymuje ja.
		if payload.Network != nil {
			siec := *payload.Network
			siec.PlanHash = hash
			payload.Network = &siec
		}

	case opspec.ActionBackupRun, opspec.ActionBackupVerify:
		// Kopia wiaze sie odciskiem planu: zakres albo repozytorium
		// zmienione od planowania zatrzymuja operacje.
		if payload.Backup != nil {
			kopia := *payload.Backup
			kopia.PlanHash = hash
			payload.Backup = &kopia
		}

	case opspec.ActionCertificateTrustEnsure, opspec.ActionCertificateTrustRemove:
		// Kotwica wiaze sie odciskiem planu: magazyn zaufania zmieniony od
		// planowania zatrzymuje krok rotacji.
		if payload.Certificate != nil {
			certyfikat := *payload.Certificate
			certyfikat.PlanHash = hash
			payload.Certificate = &certyfikat
		}

	case opspec.ActionCertificateDeploy:
		// Certyfikat wiaze sie odciskiem planu: plik pod ta sciezka zmieniony
		// od planowania zatrzymuje wdrozenie zamiast nadpisac cudzy material.
		if payload.Certificate != nil {
			certyfikat := *payload.Certificate
			certyfikat.PlanHash = hash
			payload.Certificate = &certyfikat
		}

	case opspec.ActionTimeConfigApply:
		// Zrodla czasu wiaza sie odciskiem planu: plik panelu albo demon
		// zmieniony od planowania zatrzymuje zmiane.
		if payload.Time != nil {
			zegar := *payload.Time
			zegar.PlanHash = hash
			payload.Time = &zegar
		}

	case opspec.ActionKernelModuleBlacklist:
		// Blokada modulu wiaze sie odciskiem planu: plik blokad albo stan
		// modulu zmieniony od planowania zatrzymuje zmiane.
		if payload.Kernel != nil {
			jadro := *payload.Kernel
			jadro.PlanHash = hash
			payload.Kernel = &jadro
		}

	case opspec.ActionSSHConfigApply:
		// sshd wiaze sie odciskiem planu: host liczy plan jeszcze raz przed
		// zapisem, a serwer albo plik panelu zmieniony od planowania
		// zatrzymuje zmiane.
		if payload.SSH != nil {
			serwer := *payload.SSH
			serwer.PlanHash = hash
			payload.SSH = &serwer
		}

	case opspec.ActionDNSHostApply:
		// Resolver wiaze sie odciskiem planu tak samo jak reszta sieci.
		if payload.DNS != nil {
			resolver := *payload.DNS
			resolver.PlanHash = hash
			payload.DNS = &resolver
		}

	case opspec.ActionFilesystemCheck, opspec.ActionFilesystemResize, opspec.ActionLVMExtend:
		// Urzadzenie wiaze sie odciskiem planu: dysk, grupa albo montowanie
		// zmienione od planowania zatrzymuja operacje.
		if payload.Storage != nil {
			przestrzen := *payload.Storage
			przestrzen.PlanHash = hash
			payload.Storage = &przestrzen
		}

	case opspec.ActionMountEnsure:
		// Montowanie wiaze sie zrodlem rozwiazanym do UUID na tym hoscie:
		// mount po UUID znajdzie ten sam filesystem albo zaden, a nigdy
		// cudzy dysk, ktory po restarcie dostal te sama sciezke.
		if zrodlo := zrodloRozwiazane(plan); zrodlo != "" && payload.Storage != nil {
			montowanie := *payload.Storage
			montowanie.Source = zrodlo
			payload.Storage = &montowanie
		}

	case opspec.ActionComposeDeploy:
		// Digest planu Compose powstaje z manifestu i z digestow obrazow.
		// Wdrozenie bez niego nie ma podstawy, a wdrozenie z cudzym trafiloby
		// na host, ktory tego planu nigdy nie widzial.
		if payload.Compose != nil {
			manifest := *payload.Compose
			manifest.PlanDigest = hash
			payload.Compose = &manifest
		}
	}
	return payload
}

// odciskZastanejTresci wyjmuje z planu odcisk pliku, ktory host mial w chwili
// planowania.
//
// Pusty wynik jest tu poprawna odpowiedzia: pliku moze nie byc, a wtedy zapis
// nie ma czego oczekiwac i host sam sprawdzi, ze nadal go nie ma.
func odciskZastanejTresci(plan json.RawMessage) string {
	if len(plan) == 0 {
		return ""
	}
	var szczegol struct {
		Plan struct {
			SHA256 string `json:"sha256"`
			Exists bool   `json:"exists"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(plan, &szczegol); err != nil {
		return ""
	}
	if !szczegol.Plan.Exists {
		return ""
	}
	return szczegol.Plan.SHA256
}

// odmowaPlanu czyta z planu powod, dla ktorego zmiana nie wejdzie na host.
//
// Kazdy planer moze go podac: regula odcinajaca kanal zarzadzania, walidator
// odrzucajacy tresc pliku. Pusty wynik znaczy plan wykonalny.
func odmowaPlanu(plan json.RawMessage) string {
	if len(plan) == 0 {
		return ""
	}
	var szczegol struct {
		Plan struct {
			Refusal         string `json:"refusal"`
			ValidatorFailed bool   `json:"validator_failed"`
			ValidatorOutput string `json:"validator_output"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(plan, &szczegol); err != nil {
		return ""
	}
	if szczegol.Plan.Refusal != "" {
		return szczegol.Plan.Refusal
	}
	if szczegol.Plan.ValidatorFailed {
		return "walidator odrzucil tresc docelowa: " + szczegol.Plan.ValidatorOutput
	}
	return ""
}

// zrodloRozwiazane wyjmuje z planu montowania zrodlo po UUID.
func zrodloRozwiazane(plan json.RawMessage) string {
	if len(plan) == 0 {
		return ""
	}
	var szczegol struct {
		Plan struct {
			ResolvedSource string `json:"resolved_source"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(plan, &szczegol); err != nil {
		return ""
	}
	return szczegol.Plan.ResolvedSource
}

// odciskZestawuRegul wyjmuje z planu zapory odcisk zestawu regul hosta.
func odciskZestawuRegul(plan json.RawMessage) string {
	if len(plan) == 0 {
		return ""
	}
	var szczegol struct {
		Plan struct {
			RulesetHash string `json:"ruleset_hash"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(plan, &szczegol); err != nil {
		return ""
	}
	return szczegol.Plan.RulesetHash
}

// OdciskZestawuPlanow liczy odcisk calego zestawu planow.
//
// Pary host:plan sa sortowane, bo kolejnosc odczytu z bazy nie jest decyzja.
func OdciskZestawuPlanow(plany map[string]string) string {
	pary := make([]string, 0, len(plany))
	for host, hash := range plany {
		pary = append(pary, host+":"+hash)
	}
	sort.Strings(pary)
	return odciskTekstu(pary)
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
