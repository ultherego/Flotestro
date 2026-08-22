package campaigns

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// progressTarget domyka jeden krok hosta w kampanii: zmiane, restart albo
// weryfikacje po restarcie.
func (o *Orchestrator) progressTarget(ctx context.Context, campaign Campaign, target *Target) error {
	switch target.State {
	case TargetRunning:
		return o.afterMainJob(ctx, campaign, target)
	case TargetRebooting:
		return o.afterReboot(ctx, campaign, target)
	case TargetVerifying:
		return o.afterHealthCheck(ctx, campaign, target)
	default:
		return nil
	}
}

// afterMainJob reaguje na wynik zadania glownego i decyduje o restarcie.
func (o *Orchestrator) afterMainJob(ctx context.Context, campaign Campaign, target *Target) error {
	if target.JobID == nil {
		return nil
	}
	job, err := o.jobs.Get(ctx, *target.JobID)
	if err != nil {
		return err
	}
	if !jobs.State(job.State).Terminal() {
		return nil
	}
	if job.State != jobs.StateSucceeded {
		o.finishTarget(ctx, campaign, target, TargetFailed,
			job.ResultErrorCode, job.ResultMessage)
		return nil
	}

	needsReboot, err := o.rebootNeeded(ctx, campaign, *target.JobID)
	if err != nil {
		return err
	}
	if !needsReboot {
		o.finishTarget(ctx, campaign, target, TargetSucceeded, "", "")
		return nil
	}

	host, err := o.hosts.Get(ctx, target.HostID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetFailed, "host_unavailable", err.Error())
		return nil
	}
	// Boot ID sprzed restartu jest jedynym pewnym dowodem, ze host faktycznie
	// wstal, a nie tylko nie zdazyl sie rozlaczyc.
	if err := o.store.SetBootIDBefore(ctx, target.ID, host.BootID); err != nil {
		return err
	}
	target.BootIDBefore = host.BootID

	rebootJobID, err := o.submitJob(ctx, campaign, host, opspec.ActionSystemReboot,
		opspec.Payload{Reboot: &opspec.RebootPayload{
			DelaySeconds: 15,
			Reason:       "Flotestro: kampania " + campaign.Name,
		}}, "campaign:"+campaign.ID+":reboot:"+target.HostID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetFailed, "reboot_create_failed", err.Error())
		return nil
	}
	if err := o.store.AttachJob(ctx, target.ID, "reboot_job_id", rebootJobID); err != nil {
		return err
	}
	if err := o.store.UpdateTarget(ctx, target.ID, TargetRebooting, "", "zaplanowano restart"); err != nil {
		return err
	}
	target.State = TargetRebooting

	o.log.Info("kampania zleca restart hosta",
		"campaign_id", campaign.ID, "host_id", target.HostID, "job_id", rebootJobID)
	return nil
}

// rebootNeeded odpowiada, czy polityka kampanii i wynik zadania wymagaja
// restartu hosta.
func (o *Orchestrator) rebootNeeded(ctx context.Context, campaign Campaign, jobID string) (bool, error) {
	switch RebootPolicy(campaign.RebootPolicy) {
	case RebootNever:
		return false, nil
	case RebootAlways:
		return true, nil
	}

	attempts, err := o.jobs.Attempts(ctx, jobID)
	if err != nil {
		return false, err
	}
	if len(attempts) == 0 {
		return false, nil
	}
	detail := attempts[len(attempts)-1].Detail
	if len(detail) == 0 {
		return false, nil
	}
	var parsed struct {
		Kind           string `json:"kind"`
		RebootRequired bool   `json:"reboot_required"`
	}
	if err := json.Unmarshal(detail, &parsed); err != nil {
		return false, nil
	}
	return parsed.Kind == "package_apply" && parsed.RebootRequired, nil
}

// afterReboot czeka, az host wroci z nowym boot ID, i zleca health check.
// Host jest uznany za przywrocony dopiero po nowej sesji i weryfikacji, a nie
// po samym wyslaniu polecenia restartu.
func (o *Orchestrator) afterReboot(ctx context.Context, campaign Campaign, target *Target) error {
	if target.RebootJobID != nil {
		job, err := o.jobs.Get(ctx, *target.RebootJobID)
		if err != nil {
			return err
		}
		if jobs.State(job.State).Terminal() && job.State != jobs.StateSucceeded {
			o.finishTarget(ctx, campaign, target, TargetFailed,
				firstNonEmpty(job.ResultErrorCode, "reboot_failed"), job.ResultMessage)
			return nil
		}
	}

	host, err := o.hosts.Get(ctx, target.HostID)
	if err != nil {
		return err
	}
	// Nowy boot ID i aktywna sesja oznaczaja, ze host wrocil.
	if host.ConnectionState != "online" || host.BootID == "" || host.BootID == target.BootIDBefore {
		if o.rebootTimedOut(target) {
			o.finishTarget(ctx, campaign, target, TargetFailed, "reboot_timeout",
				"host nie wrocil po restarcie w zadanym czasie")
		}
		return nil
	}

	if len(campaign.HealthCheckUnits) == 0 {
		o.finishTarget(ctx, campaign, target, TargetSucceeded, "", "host wrocil po restarcie")
		return nil
	}

	healthJobID, err := o.submitJob(ctx, campaign, host, opspec.ActionUnitStatus,
		opspec.Payload{UnitStatus: &opspec.UnitStatusPayload{Units: campaign.HealthCheckUnits}},
		"campaign:"+campaign.ID+":health:"+target.HostID+":"+host.BootID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetFailed, "health_create_failed", err.Error())
		return nil
	}
	if err := o.store.AttachJob(ctx, target.ID, "health_job_id", healthJobID); err != nil {
		return err
	}
	if err := o.store.UpdateTarget(ctx, target.ID, TargetVerifying, "", "host wrocil, trwa weryfikacja"); err != nil {
		return err
	}
	target.State = TargetVerifying

	o.log.Info("host wrocil po restarcie, trwa weryfikacja",
		"campaign_id", campaign.ID, "host_id", target.HostID, "boot_id", host.BootID)
	return nil
}

// rebootTimeout ogranicza czekanie na powrot hosta. Bez tego kampania
// czekalaby w nieskonczonosc na maszyne, ktora nie wstala.
const rebootTimeout = 15 * time.Minute

func (o *Orchestrator) rebootTimedOut(target *Target) bool {
	if target.StartedAt == nil {
		return false
	}
	return time.Since(*target.StartedAt) > rebootTimeout
}

// afterHealthCheck domyka hosta po weryfikacji jednostek.
func (o *Orchestrator) afterHealthCheck(ctx context.Context, campaign Campaign, target *Target) error {
	if target.HealthJobID == nil {
		return nil
	}
	job, err := o.jobs.Get(ctx, *target.HealthJobID)
	if err != nil {
		return err
	}
	if !jobs.State(job.State).Terminal() {
		return nil
	}
	if job.State != jobs.StateSucceeded {
		// Negatywny health check jest bledem hosta w kampanii: zmiana zostala
		// wykonana, ale host nie wrocil do sprawnego stanu.
		o.finishTarget(ctx, campaign, target, TargetFailed,
			firstNonEmpty(job.ResultErrorCode, "health_check_failed"), job.ResultMessage)
		return nil
	}
	o.finishTarget(ctx, campaign, target, TargetSucceeded, "", "health check przeszedl")
	return nil
}

// finishTarget zamyka host w kampanii i odnotowuje to w audycie.
func (o *Orchestrator) finishTarget(ctx context.Context, campaign Campaign, target *Target,
	state TargetState, errorCode, message string) {
	if err := o.store.UpdateTarget(ctx, target.ID, state, errorCode, message); err != nil {
		o.log.Error("nie zapisano stanu celu kampanii",
			"campaign_id", campaign.ID, "host_id", target.HostID, "err", err)
		return
	}
	target.State = state

	outcome := audit.OutcomeSuccess
	if state == TargetFailed {
		outcome = audit.OutcomeFailure
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.target." + string(state), TargetType: "host", TargetID: target.HostID,
		RequestID: campaign.RequestID, Outcome: outcome,
		Detail: map[string]any{
			"campaign_id": campaign.ID, "wave": target.Wave,
			"error_code": errorCode, "message": message,
		},
	})
	o.log.Info("kampania zamknela host",
		"campaign_id", campaign.ID, "host_id", target.HostID,
		"stan", state, "kod", errorCode)
}

// pauseOnThreshold wstrzymuje kampanie po przekroczeniu progu bledow.
// Hosty juz uruchomione dokoncza swoje zadania; nowe nie ruszaja.
func (o *Orchestrator) pauseOnThreshold(ctx context.Context, campaign Campaign,
	reason string, failed, finished int) error {
	if err := o.store.SetState(ctx, campaign.ID, StatePaused, reason); err != nil {
		return err
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.pause", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeFailure,
		Detail: map[string]any{
			"reason": reason, "failed": failed, "finished": finished,
			"threshold_percent":  campaign.FailureThresholdPercent,
			"threshold_absolute": campaign.FailureThresholdAbsolute,
		},
	})
	o.log.Warn("kampania wstrzymana po przekroczeniu progu bledow",
		"campaign_id", campaign.ID, "powod", reason, "bledow", failed, "zakonczonych", finished)
	return nil
}

// complete zamyka kampanie i odnotowuje raport w audycie.
func (o *Orchestrator) complete(ctx context.Context, campaign Campaign,
	targets []Target, failed int) error {
	state := StateCompleted
	if failed > 0 && failed == len(targets) {
		// Kampania, w ktorej padly wszystkie hosty, nie jest ukonczona.
		state = StateFailed
	}
	if err := o.store.SetState(ctx, campaign.ID, state, ""); err != nil {
		return err
	}

	counts, err := o.store.Counts(ctx, campaign.ID)
	if err != nil {
		return err
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.complete", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"state": string(state), "totals": counts},
	})
	o.log.Info("kampania zakonczona",
		"campaign_id", campaign.ID, "stan", state, "podsumowanie", fmt.Sprint(counts))
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
