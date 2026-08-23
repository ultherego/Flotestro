package campaigns

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Orchestrator prowadzi kampanie: canary, fale, progi zatrzymania i faze
// restartu z weryfikacja. Nie wykonuje niczego sam - tworzy zadania, ktore
// dostarcza scheduler.
type Orchestrator struct {
	store    *Store
	jobs     *jobs.Store
	hosts    *hosts.Store
	audit    *audit.Recorder
	log      *slog.Logger
	interval time.Duration
}

func NewOrchestrator(store *Store, jobStore *jobs.Store, hostStore *hosts.Store,
	recorder *audit.Recorder, log *slog.Logger, interval time.Duration) *Orchestrator {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Orchestrator{store: store, jobs: jobStore, hosts: hostStore,
		audit: recorder, log: log, interval: interval}
}

// Run prowadzi kampanie do zamkniecia kontekstu.
func (o *Orchestrator) Run(ctx context.Context) {
	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.tick(ctx)
		}
	}
}

func (o *Orchestrator) tick(ctx context.Context) {
	active, err := o.store.Active(ctx)
	if err != nil {
		o.log.Error("nie pobrano aktywnych kampanii", "err", err)
		return
	}
	for _, campaign := range active {
		if err := o.advance(ctx, campaign); err != nil {
			o.log.Error("blad prowadzenia kampanii", "campaign_id", campaign.ID, "err", err)
		}
	}
}

// advance przesuwa kampanie o jeden krok.
func (o *Orchestrator) advance(ctx context.Context, campaign Campaign) error {
	targets, err := o.store.Targets(ctx, campaign.ID)
	if err != nil {
		return err
	}

	// Najpierw domykamy to, co juz biegnie: bez tego progi liczylyby sie na
	// nieaktualnym stanie.
	for i := range targets {
		if err := o.progressTarget(ctx, campaign, &targets[i]); err != nil {
			o.log.Error("blad obslugi celu kampanii",
				"campaign_id", campaign.ID, "host_id", targets[i].HostID, "err", err)
		}
	}

	failed, finished := 0, 0
	for _, target := range targets {
		if target.State.Finished() {
			finished++
		}
		if target.State == TargetFailed {
			failed++
		}
	}

	// Prog zatrzymania sprawdzamy przed uruchomieniem czegokolwiek nowego.
	if exceeded, reason := ThresholdExceeded(failed, finished, len(targets),
		campaign.FailureThresholdPercent, campaign.FailureThresholdAbsolute); exceeded {
		return o.pauseOnThreshold(ctx, campaign, reason, failed, finished)
	}

	if allFinished(targets) {
		return o.complete(ctx, campaign, targets, failed)
	}

	// Okno serwisowe wstrzymuje uruchamianie nowych hostow, ale nie przerywa
	// tych, ktore juz pracuja.
	if !WithinMaintenanceWindow(time.Now(), campaign.MaintenanceStart, campaign.MaintenanceEnd) {
		return nil
	}

	wave := currentWave(targets)
	if wave < 0 {
		return nil
	}
	// Fala rusza dopiero, gdy poprzednia jest w calosci zamknieta. Canary jest
	// fala zero, wiec ta sama regula daje wymagany przez dokument etap canary.
	if !waveFinished(targets, wave-1) {
		return nil
	}

	desiredState := StateRunning
	if wave == 0 {
		desiredState = StateCanary
	}
	if campaign.State != desiredState {
		if err := o.store.SetState(ctx, campaign.ID, desiredState, ""); err != nil {
			return err
		}
		o.log.Info("kampania wchodzi w faze",
			"campaign_id", campaign.ID, "faza", desiredState, "fala", wave)
	}

	return o.launchWave(ctx, campaign, targets, wave)
}

// launchWave uruchamia hosty biezacej fali z zachowaniem limitu rownoleglosci.
func (o *Orchestrator) launchWave(ctx context.Context, campaign Campaign,
	targets []Target, wave int) error {
	running := 0
	for _, target := range targets {
		if target.Wave == wave && !target.State.Finished() && target.State != TargetPending {
			running++
		}
	}

	for i := range targets {
		target := &targets[i]
		if target.Wave != wave || target.State != TargetPending {
			continue
		}
		if running >= campaign.MaxConcurrent {
			return nil
		}

		host, err := o.hosts.Get(ctx, target.HostID)
		if err != nil {
			o.finishTarget(ctx, campaign, target, TargetSkipped, "host_unavailable", err.Error())
			continue
		}
		// Host niepodlaczony nie jest bledem kampanii: zadanie i tak czekaloby
		// w kolejce, ale wtedy limit rownoleglosci blokowalby cala fale.
		if host.ConnectionState != "online" {
			continue
		}

		jobID, err := o.createJob(ctx, campaign, target, host)
		if err != nil {
			o.finishTarget(ctx, campaign, target, TargetFailed, "job_create_failed", err.Error())
			continue
		}
		if err := o.store.AttachJob(ctx, target.ID, "job_id", jobID); err != nil {
			return err
		}
		if err := o.store.SetBootIDBefore(ctx, target.ID, host.BootID); err != nil {
			return err
		}
		if err := o.store.UpdateTarget(ctx, target.ID, TargetRunning, "", ""); err != nil {
			return err
		}
		target.State = TargetRunning
		running++

		o.log.Info("kampania uruchomila host",
			"campaign_id", campaign.ID, "host_id", target.HostID,
			"fala", wave, "job_id", jobID)
	}
	return nil
}

// createJob tworzy zadanie glowne kampanii dla hosta.
func (o *Orchestrator) createJob(ctx context.Context, campaign Campaign,
	target *Target, host *hosts.Host) (string, error) {
	var payload opspec.Payload
	if len(campaign.Payload) > 0 {
		if err := json.Unmarshal(campaign.Payload, &payload); err != nil {
			return "", err
		}
	}
	return o.submitJob(ctx, campaign, host, opspec.ActionType(campaign.ActionType), payload,
		"campaign:"+campaign.ID+":main:"+target.HostID)
}

// submitJob tworzy zadanie zatwierdzone przez kampanie. Zatwierdzenie kampanii
// jest zatwierdzeniem jej zadan: operator nie klika osobno kazdego hosta.
func (o *Orchestrator) submitJob(ctx context.Context, campaign Campaign, host *hosts.Host,
	action opspec.ActionType, payload opspec.Payload, idempotencyKey string) (string, error) {
	tx, err := o.jobs.Pool().Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	job, err := o.jobs.Create(ctx, tx, jobs.Spec{
		HostID:          host.ID,
		Action:          action,
		Payload:         payload,
		IdempotencyKey:  idempotencyKey,
		RequiresApprova: false,
		TimeoutSeconds:  campaign.JobTimeoutSeconds,
		TTL:             time.Duration(campaign.JobTimeoutSeconds+600) * time.Second,
		CreatedBy:       "campaign:" + campaign.Name,
		RequestID:       campaign.RequestID,
		CampaignID:      campaign.ID,
		Preconditions: jobs.Preconditions{
			OSFamily:             host.OSFamily,
			RequiredCapabilities: []string{action.RequiredCapability()},
		},
	})
	if err != nil {
		return "", err
	}
	if err := o.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "job.create", TargetType: "job", TargetID: job.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"campaign_id": campaign.ID, "host_id": host.ID,
			"action_type": string(action), "approved_by": campaign.ApprovedBy,
		},
	}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return job.ID, nil
}

func allFinished(targets []Target) bool {
	for _, target := range targets {
		if !target.State.Finished() {
			return false
		}
	}
	return true
}

// currentWave zwraca najnizsza fale z niezakonczonymi celami.
func currentWave(targets []Target) int {
	wave := -1
	for _, target := range targets {
		if target.State.Finished() {
			continue
		}
		if wave < 0 || target.Wave < wave {
			wave = target.Wave
		}
	}
	return wave
}

// waveFinished mowi, czy wszystkie cele danej fali sa zamkniete.
func waveFinished(targets []Target, wave int) bool {
	if wave < 0 {
		return true
	}
	for _, target := range targets {
		if target.Wave == wave && !target.State.Finished() {
			return false
		}
	}
	return true
}
