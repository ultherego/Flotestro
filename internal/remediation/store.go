package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound oznacza plan, ktorego nie ma.
var ErrNotFound = errors.New("nie ma takiego planu naprawy")

// ErrPlanWToku oznacza host, na ktorym plan juz idzie.
var ErrPlanWToku = errors.New("na tym hoscie trwa juz plan naprawy")

// Store trzyma plany naprawy i ich kroki.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Pool udostepnia pule do transakcji laczonych z innymi zapisami.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Spec opisuje plan do zalozenia.
type Spec struct {
	HostID          string
	PlanHash        string
	PlanHashVersion int
	Reason          string
	CreatedBy       string
	StopOnFailure   bool
	BootIDBefore    string
}

// Zaloz zapisuje plan wraz z krokami.
//
// Dwa plany naraz na jednym hoscie nie moga isc: kroki jednego zakladaja stan
// zostawiony przez poprzedni, a rownolegly plan ten stan zmienia pod nimi.
func (s *Store) Zaloz(ctx context.Context, tx pgx.Tx, spec Spec, kroki []Krok) (*Plan, error) {
	var trwajace int
	if err := tx.QueryRow(ctx,
		`select count(*) from remediation_plans where host_id = $1 and state = $2`,
		spec.HostID, StanWToku).Scan(&trwajace); err != nil {
		return nil, err
	}
	if trwajace > 0 {
		return nil, ErrPlanWToku
	}

	plan := &Plan{
		HostID: spec.HostID, PlanHash: spec.PlanHash, PlanHashVersion: spec.PlanHashVersion,
		Reason: spec.Reason, CreatedBy: spec.CreatedBy, StopOnFailure: spec.StopOnFailure,
		State: StanWToku, BootIDBefore: spec.BootIDBefore,
	}
	if err := tx.QueryRow(ctx, `
		insert into remediation_plans
		    (host_id, plan_hash, plan_hash_version, reason, created_by, stop_on_failure, state)
		values ($1, $2, $3, $4, $5, $6, $7)
		returning id, created_at`,
		spec.HostID, spec.PlanHash, spec.PlanHashVersion, spec.Reason,
		spec.CreatedBy, spec.StopOnFailure, StanWToku).Scan(&plan.ID, &plan.CreatedAt); err != nil {
		return nil, err
	}

	batch := &pgx.Batch{}
	for _, krok := range kroki {
		batch.Queue(`
			insert into remediation_steps
			    (plan_id, position, check_id, check_version, action_type, payload,
			     lock_class, requires_reboot, state)
			values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			plan.ID, krok.Position, krok.CheckID, krok.CheckVersion, krok.ActionType,
			[]byte(pustyGdyBrak(krok.Payload)), krok.LockClass, krok.RequiresReboot, KrokOczekuje)
	}
	wyniki := tx.SendBatch(ctx, batch)
	for range kroki {
		if _, err := wyniki.Exec(); err != nil {
			_ = wyniki.Close()
			return nil, err
		}
	}
	if err := wyniki.Close(); err != nil {
		return nil, err
	}

	plan.Steps = append([]Krok(nil), kroki...)
	return plan, nil
}

// Plan zwraca plan wraz z krokami.
func (s *Store) Plan(ctx context.Context, planID string) (*Plan, error) {
	plany, err := s.zapytaj(ctx, "where id = $1", planID)
	if err != nil {
		return nil, err
	}
	if len(plany) == 0 {
		return nil, ErrNotFound
	}
	return &plany[0], nil
}

// Hosta zwraca ostatnie plany hosta.
func (s *Store) Hosta(ctx context.Context, hostID string, limit int) ([]Plan, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	return s.zapytaj(ctx, "where host_id = $1 order by created_at desc limit $2", hostID, limit)
}

// WToku zwraca plany, ktore runner ma poprowadzic dalej.
func (s *Store) WToku(ctx context.Context) ([]Plan, error) {
	return s.zapytaj(ctx, "where state = $1 order by created_at", StanWToku)
}

func (s *Store) zapytaj(ctx context.Context, klauzula string, argumenty ...any) ([]Plan, error) {
	rows, err := s.pool.Query(ctx, `
		select id, host_id, plan_hash, plan_hash_version, reason, created_by,
		       stop_on_failure, state, created_at, finished_at
		  from remediation_plans `+klauzula, argumenty...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var plany []Plan
	for rows.Next() {
		var plan Plan
		if err := rows.Scan(&plan.ID, &plan.HostID, &plan.PlanHash, &plan.PlanHashVersion,
			&plan.Reason, &plan.CreatedBy, &plan.StopOnFailure, &plan.State,
			&plan.CreatedAt, &plan.FinishedAt); err != nil {
			return nil, err
		}
		plany = append(plany, plan)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range plany {
		kroki, err := s.Kroki(ctx, plany[i].ID)
		if err != nil {
			return nil, err
		}
		plany[i].Steps = kroki
	}
	return plany, nil
}

// Kroki zwraca kroki planu w kolejnosci wykonania.
func (s *Store) Kroki(ctx context.Context, planID string) ([]Krok, error) {
	rows, err := s.pool.Query(ctx, `
		select id, position, check_id, check_version, action_type, payload,
		       lock_class, requires_reboot, coalesce(job_id::text, ''), state,
		       coalesce(reason, ''), started_at, finished_at
		  from remediation_steps
		 where plan_id = $1
		 order by position`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var kroki []Krok
	for rows.Next() {
		var krok Krok
		var payload []byte
		if err := rows.Scan(&krok.ID, &krok.Position, &krok.CheckID, &krok.CheckVersion,
			&krok.ActionType, &payload, &krok.LockClass, &krok.RequiresReboot,
			&krok.JobID, &krok.State, &krok.Reason, &krok.StartedAt, &krok.FinishedAt); err != nil {
			return nil, err
		}
		krok.Payload = json.RawMessage(payload)
		kroki = append(kroki, krok)
	}
	return kroki, rows.Err()
}

// ZaczniKrok wiaze krok z zadaniem i oznacza go jako trwajacy.
func (s *Store) ZaczniKrok(ctx context.Context, stepID, jobID string) error {
	_, err := s.pool.Exec(ctx, `
		update remediation_steps
		   set state = $2, job_id = $3, started_at = now()
		 where id = $1`, stepID, KrokWToku, jobID)
	return err
}

// ZamknijKrok zapisuje wynik kroku.
func (s *Store) ZamknijKrok(ctx context.Context, stepID, stan, powod string) error {
	_, err := s.pool.Exec(ctx, `
		update remediation_steps
		   set state = $2, reason = $3, finished_at = now()
		 where id = $1`, stepID, stan, nullable(powod))
	return err
}

// PomijPozostale zamyka kroki, ktore juz nie ruszy.
func (s *Store) PomijPozostale(ctx context.Context, planID, powod string) error {
	_, err := s.pool.Exec(ctx, `
		update remediation_steps
		   set state = $2, reason = $3, finished_at = now()
		 where plan_id = $1 and state = $4`, planID, KrokPominiety, nullable(powod), KrokOczekuje)
	return err
}

// ZamknijPlan zapisuje stan koncowy planu.
func (s *Store) ZamknijPlan(ctx context.Context, planID, stan string) error {
	_, err := s.pool.Exec(ctx, `
		update remediation_plans set state = $2, finished_at = now() where id = $1`, planID, stan)
	return err
}

func pustyGdyBrak(payload json.RawMessage) json.RawMessage {
	if len(payload) == 0 {
		return json.RawMessage("{}")
	}
	return payload
}

func nullable(wartosc string) any {
	if wartosc == "" {
		return nil
	}
	return wartosc
}

// TerminPowrotu wyznacza chwile, po ktorej host mial juz wrocic.
func TerminPowrotu(krok Krok) time.Time {
	if krok.StartedAt == nil {
		return time.Now().UTC().Add(OknoPowrotu)
	}
	return krok.StartedAt.Add(OknoPowrotu)
}
