package remediation

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

// Runner prowadzi plany naprawy przez kolejne kroki.
//
// Sam niczego nie wykonuje: tworzy zadania, ktore dostarcza scheduler, i czeka
// na ich wynik. Krok rusza dopiero, gdy poprzedni sie udal - to jest cala
// zaleznosc miedzy krokami i cale zatrzymanie po bledzie.
type Runner struct {
	store    *Store
	jobs     *jobs.Store
	hosts    *hosts.Store
	audit    *audit.Recorder
	log      *slog.Logger
	interval time.Duration
}

func NewRunner(store *Store, jobStore *jobs.Store, hostStore *hosts.Store,
	recorder *audit.Recorder, log *slog.Logger, interval time.Duration) *Runner {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Runner{store: store, jobs: jobStore, hosts: hostStore,
		audit: recorder, log: log, interval: interval}
}

// Run prowadzi plany do zamkniecia kontekstu.
func (r *Runner) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

func (r *Runner) tick(ctx context.Context) {
	plany, err := r.store.WToku(ctx)
	if err != nil {
		r.log.Error("nie pobrano planow naprawy", "err", err)
		return
	}
	for _, plan := range plany {
		if err := r.przesun(ctx, plan); err != nil {
			r.log.Error("blad prowadzenia planu naprawy", "plan_id", plan.ID, "err", err)
		}
	}
}

// przesun przesuwa plan o jeden krok.
func (r *Runner) przesun(ctx context.Context, plan Plan) error {
	krok := plan.Biezacy()
	if krok == nil {
		return r.zakoncz(ctx, plan, StanUdany, "")
	}

	if krok.State == KrokOczekuje {
		return r.zacznij(ctx, plan, krok)
	}

	// Krok trwa: czekamy na wynik zadania, a przy kroku z restartem takze na
	// powrot hosta. Wyslane polecenie restartu nie jest jeszcze hostem, ktory
	// wstal - i to jest granica, na ktorej plan sie konczy.
	zadanie, err := r.jobs.Get(ctx, krok.JobID)
	if err != nil {
		return err
	}
	if !zadanie.State.Terminal() {
		return nil
	}
	if zadanie.State != jobs.StateSucceeded {
		powod := "zadanie zakonczylo sie stanem " + string(zadanie.State)
		if zadanie.ResultMessage != "" {
			powod += ": " + zadanie.ResultMessage
		}
		if err := r.store.ZamknijKrok(ctx, krok.ID, KrokNieudany, powod); err != nil {
			return err
		}
		if !plan.StopOnFailure {
			return nil
		}
		if err := r.store.PomijPozostale(ctx, plan.ID,
			"poprzedni krok sie nie udal, a plan zatrzymuje sie po bledzie"); err != nil {
			return err
		}
		return r.zakoncz(ctx, plan, StanNieudany, powod)
	}

	if krok.RequiresReboot {
		wrocil, powod := r.hostWrocil(ctx, plan)
		if !wrocil {
			if time.Now().UTC().Before(TerminPowrotu(*krok)) {
				return nil
			}
			if err := r.store.ZamknijKrok(ctx, krok.ID, KrokNieudany, powod); err != nil {
				return err
			}
			return r.zakoncz(ctx, plan, StanNieudany, powod)
		}
	}

	if err := r.store.ZamknijKrok(ctx, krok.ID, KrokUdany, ""); err != nil {
		return err
	}
	return nil
}

// zacznij tworzy zadanie kroku.
func (r *Runner) zacznij(ctx context.Context, plan Plan, krok *Krok) error {
	host, err := r.hosts.Get(ctx, plan.HostID)
	if err != nil {
		if err := r.store.ZamknijKrok(ctx, krok.ID, KrokNieudany, err.Error()); err != nil {
			return err
		}
		return r.zakoncz(ctx, plan, StanNieudany, err.Error())
	}

	akcja := opspec.ActionType(krok.ActionType)
	var payload opspec.Payload
	if len(krok.Payload) > 0 {
		if err := json.Unmarshal(krok.Payload, &payload); err != nil {
			return r.przerwijKrok(ctx, plan, krok, "payload kroku: "+err.Error())
		}
	}
	if err := opspec.Validate(akcja, payload); err != nil {
		return r.przerwijKrok(ctx, plan, krok, "payload kroku odrzucony: "+err.Error())
	}

	tx, err := r.jobs.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	zadanie, err := r.jobs.Create(ctx, tx, jobs.Spec{
		HostID:  plan.HostID,
		Action:  akcja,
		Payload: payload,
		// Klucz wiaze zadanie z konkretnym krokiem konkretnego planu:
		// ponowne przejscie runnera nie tworzy drugiego zadania.
		IdempotencyKey:  "remediation:" + plan.ID + ":" + krok.CheckID,
		RequiresApprova: akcja.Mutating(),
		CreatedBy:       plan.CreatedBy,
		Preconditions: jobs.Preconditions{
			OSFamily:             host.OSFamily,
			RequiredCapabilities: []string{akcja.RequiredCapability()},
		},
	})
	if err != nil {
		_ = tx.Rollback(ctx)
		return r.przerwijKrok(ctx, plan, krok, "nie zlozono zadania: "+err.Error())
	}
	if err := r.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "remediation:" + plan.ID,
		Action: "security.remediate.step", TargetType: "job", TargetID: zadanie.ID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"host_id": plan.HostID, "plan_id": plan.ID, "check_id": krok.CheckID,
			"position": krok.Position, "action_type": krok.ActionType,
			"plan_hash": plan.PlanHash, "created_by": plan.CreatedBy,
		},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return r.store.ZaczniKrok(ctx, krok.ID, zadanie.ID)
}

// przerwijKrok zamyka krok bledem i konczy plan, jesli tak ustalono.
func (r *Runner) przerwijKrok(ctx context.Context, plan Plan, krok *Krok, powod string) error {
	if err := r.store.ZamknijKrok(ctx, krok.ID, KrokNieudany, powod); err != nil {
		return err
	}
	if !plan.StopOnFailure {
		return nil
	}
	if err := r.store.PomijPozostale(ctx, plan.ID, "plan zatrzymal sie po bledzie"); err != nil {
		return err
	}
	return r.zakoncz(ctx, plan, StanNieudany, powod)
}

// hostWrocil sprawdza, czy host wstal po restarcie.
//
// Rozstrzyga identyfikator startu, a nie sam fakt polaczenia: host, ktory
// odpowiada z tym samym boot_id, jeszcze sie nie restartowal.
func (r *Runner) hostWrocil(ctx context.Context, plan Plan) (bool, string) {
	host, err := r.hosts.Get(ctx, plan.HostID)
	if err != nil {
		return false, "nie odczytano stanu hosta: " + err.Error()
	}
	if host.ConnectionState != "online" {
		return false, "host nie wrocil po restarcie w " + OknoPowrotu.String()
	}
	if plan.BootIDBefore != "" && host.BootID == plan.BootIDBefore {
		return false, "host odpowiada, ale z tym samym identyfikatorem startu"
	}
	return true, ""
}

// zakoncz zamyka plan i zapisuje to w audycie.
func (r *Runner) zakoncz(ctx context.Context, plan Plan, stan, powod string) error {
	if err := r.store.ZamknijPlan(ctx, plan.ID, stan); err != nil {
		return err
	}
	r.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "remediation:" + plan.ID,
		Action: "security.remediate.finish", TargetType: "host", TargetID: plan.HostID,
		Outcome: wynikAudytu(stan),
		Detail: map[string]any{
			"plan_id": plan.ID, "state": stan, "reason": powod,
			"plan_hash": plan.PlanHash, "created_by": plan.CreatedBy,
		},
	})
	r.log.Info("plan naprawy zamkniety", "plan_id", plan.ID, "host_id", plan.HostID, "stan", stan)
	return nil
}

func wynikAudytu(stan string) audit.Outcome {
	if stan == StanUdany {
		return audit.OutcomeSuccess
	}
	return audit.OutcomeFailure
}
