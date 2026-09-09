package campaigns

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/ultherego/flotestro/internal/jobs"
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
			if err := o.zlecPlan(ctx, campaign, target, akcja, payload); err != nil {
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
	akcja opspec.ActionType, payload opspec.Payload) error {
	host, err := o.hosts.Get(ctx, target.HostID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetSkipped, "host_unavailable", err.Error())
		return nil
	}
	// Host niepodlaczony nie jest bledem planowania: plan poczeka, az wroci.
	if host.ConnectionState != "online" {
		return nil
	}

	jobID, err := o.submitJob(ctx, campaign, host, akcja, planPayload(akcja, payload),
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
func (o *Orchestrator) odciskPlanu(ctx context.Context, jobID string) (string, json.RawMessage, error) {
	proby, err := o.jobs.Attempts(ctx, jobID)
	if err != nil {
		return "", nil, err
	}
	for i := len(proby) - 1; i >= 0; i-- {
		if len(proby[i].Detail) == 0 {
			continue
		}
		var szczegol struct {
			PlanHash string `json:"plan_hash"`
		}
		if err := json.Unmarshal(proby[i].Detail, &szczegol); err != nil {
			continue
		}
		if szczegol.PlanHash != "" {
			return szczegol.PlanHash, proby[i].Detail, nil
		}
	}
	return "", nil, nil
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
// Plan pyta o ten sam zakres, ale innym typem operacji: aktualizacja niesie
// odcisk zatwierdzonego planu, a plan go dopiero liczy.
func planPayload(akcja opspec.ActionType, payload opspec.Payload) opspec.Payload {
	if akcja != opspec.ActionPackagePlan {
		return payload
	}
	plan := &opspec.PackagePlanPayload{Mode: "upgrade"}
	if payload.PackageUpgrade != nil {
		plan.OnlyPackages = payload.PackageUpgrade.Packages
		plan.SecurityOnly = payload.PackageUpgrade.SecurityOnly
	}
	return opspec.Payload{PackagePlan: plan}
}

// zPlanem dokleda do payloadu zmiany odcisk planu policzonego na tym hoscie.
//
// Bez tego kampania wyslalaby zmiane bez planu, a host nie mialby czego
// porownac ze stanem, ktory ma teraz.
func zPlanem(action opspec.ActionType, payload opspec.Payload, hash string) opspec.Payload {
	if action == opspec.ActionPackageUpgrade {
		aktualizacja := &opspec.PackageUpgradePayload{PlanHash: hash}
		if payload.PackageUpgrade != nil {
			aktualizacja.Packages = payload.PackageUpgrade.Packages
			aktualizacja.SecurityOnly = payload.PackageUpgrade.SecurityOnly
		}
		payload.PackageUpgrade = aktualizacja
	}
	return payload
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
