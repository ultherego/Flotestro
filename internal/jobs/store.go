package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ultherego/flotestro/internal/authz"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/opspec"
)

var (
	// ErrNotFound oznacza brak joba o podanym identyfikatorze.
	ErrNotFound = errors.New("zadanie nie istnieje")
	// ErrConflict oznacza probe przejscia niedozwolonego w danym stanie.
	ErrConflict = errors.New("operacja niedozwolona w obecnym stanie zadania")
)

// Spec opisuje zadanie do utworzenia.
type Spec struct {
	HostID          string
	Action          opspec.ActionType
	Payload         opspec.Payload
	IdempotencyKey  string
	RequiresApprova bool
	TimeoutSeconds  int
	MaxOutputBytes  int
	TTL             time.Duration
	CreatedBy       string
	RequestID       string
	// CampaignID wiaze operacje z rolloutem, ktory ja zlecil. Bez tego
	// korelacja sladu audytowego urywa sie na operacji, a ekran kampanii nie
	// wie, ktore operacje sa jego - postep trwajacej aktualizacji nie mial jak
	// do niego trafic.
	CampaignID    string
	Preconditions Preconditions
}

// Preconditions sa sprawdzane przez agenta tuz przed wykonaniem.
type Preconditions struct {
	OSFamily             string   `json:"os_family,omitempty"`
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	ExpectedBootID       string   `json:"expected_boot_id,omitempty"`
}

// Job jest widokiem zadania zwracanym przez API.
type Job struct {
	ID              string          `json:"id"`
	HostID          string          `json:"host_id"`
	CampaignID      *string         `json:"campaign_id,omitempty"`
	ActionType      string          `json:"action_type"`
	ActionVersion   int             `json:"action_version"`
	Payload         json.RawMessage `json:"payload"`
	PayloadHash     string          `json:"payload_hash"`
	IdempotencyKey  string          `json:"idempotency_key"`
	State           State           `json:"state"`
	RequiresApprova bool            `json:"requires_approval"`
	Preconditions   json.RawMessage `json:"preconditions"`
	TimeoutSeconds  int             `json:"timeout_seconds"`
	MaxOutputBytes  int             `json:"max_output_bytes"`
	ExpiresAt       time.Time       `json:"expires_at"`
	CreatedBy       string          `json:"created_by"`
	RequestID       string          `json:"request_id,omitempty"`
	ApprovedBy      string          `json:"approved_by,omitempty"`
	ApprovedAt      *time.Time      `json:"approved_at,omitempty"`
	CanceledBy      string          `json:"canceled_by,omitempty"`
	CancelReason    string          `json:"cancel_reason,omitempty"`
	ResultStatus    string          `json:"result_status,omitempty"`
	ResultErrorCode string          `json:"result_error_code,omitempty"`
	ResultMessage   string          `json:"result_message,omitempty"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// Attempt opisuje jedna probe wykonania zadania.
type Attempt struct {
	ID              string          `json:"id"`
	JobID           string          `json:"job_id"`
	Number          int             `json:"attempt_number"`
	GatewayID       string          `json:"gateway_id,omitempty"`
	SessionID       *string         `json:"session_id,omitempty"`
	Status          string          `json:"status,omitempty"`
	ExitCode        *int            `json:"exit_code,omitempty"`
	ErrorCode       string          `json:"error_code,omitempty"`
	Message         string          `json:"message,omitempty"`
	Stdout          string          `json:"stdout,omitempty"`
	Stderr          string          `json:"stderr,omitempty"`
	OutputTruncated bool            `json:"output_truncated"`
	Replayed        bool            `json:"replayed"`
	UnitStateBefore json.RawMessage `json:"unit_state_before,omitempty"`
	UnitStateAfter  json.RawMessage `json:"unit_state_after,omitempty"`
	Detail          json.RawMessage `json:"detail,omitempty"`
	DispatchedAt    *time.Time      `json:"dispatched_at,omitempty"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
}

// Store realizuje dostep do tabel zadan.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Create tworzy zadanie wraz z hashem planu. Zadanie wymagajace zatwierdzenia
// startuje w awaiting_approval i nie trafia do kolejki, dopoki ktos go nie
// zatwierdzi.
func (s *Store) Create(ctx context.Context, tx pgx.Tx, spec Spec) (*Job, error) {
	if err := opspec.Validate(spec.Action, spec.Payload); err != nil {
		return nil, err
	}
	payloadHash, err := opspec.PayloadHash(spec.Action, opspec.ActionVersion, spec.Payload)
	if err != nil {
		return nil, err
	}
	payloadJSON, err := json.Marshal(spec.Payload)
	if err != nil {
		return nil, err
	}
	preconditionsJSON, err := json.Marshal(spec.Preconditions)
	if err != nil {
		return nil, err
	}

	state := StateQueued
	if spec.RequiresApprova {
		state = StateAwaitingApproval
	}
	timeout := spec.TimeoutSeconds
	if timeout <= 0 {
		timeout = spec.Action.DefaultTimeout()
	}
	maxOutput := spec.MaxOutputBytes
	if maxOutput <= 0 {
		maxOutput = 64 << 10
	}
	ttl := spec.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	idempotencyKey := spec.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = uuid.NewString()
	}

	const query = `
		insert into jobs (id, host_id, action_type, action_version, payload, payload_hash,
		                  idempotency_key, state, requires_approval, preconditions,
		                  timeout_seconds, max_output_bytes, expires_at, created_by, request_id,
		                  campaign_id)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
		        nullif($16, '')::uuid)
		on conflict (host_id, idempotency_key) do nothing
		returning id`
	jobID := uuid.NewString()
	err = tx.QueryRow(ctx, query, jobID, spec.HostID, string(spec.Action), opspec.ActionVersion,
		payloadJSON, payloadHash, idempotencyKey, string(state), spec.RequiresApprova,
		preconditionsJSON, timeout, maxOutput, time.Now().Add(ttl),
		spec.CreatedBy, nullable(spec.RequestID), spec.CampaignID).Scan(&jobID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Ten sam klucz idempotencji zwraca istniejace zadanie zamiast tworzyc
		// drugie. Powtorzone zlecenie nie jest bledem.
		return s.getTx(ctx, tx, "where host_id = $1 and idempotency_key = $2", spec.HostID, idempotencyKey)
	}
	if err != nil {
		return nil, fmt.Errorf("utworzenie zadania: %w", err)
	}
	return s.getTx(ctx, tx, "where id = $1", jobID)
}

// Approve zatwierdza zadanie i przenosi je do kolejki.
func (s *Store) Approve(ctx context.Context, tx pgx.Tx, jobID, actor string) (*Job, error) {
	const query = `
		update jobs set state = $2, approved_by = $3, approved_at = now(), updated_at = now()
		where id = $1 and state = $4
		returning id`
	var updated string
	err := tx.QueryRow(ctx, query, jobID, string(StateQueued), actor, string(StateAwaitingApproval)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.getTx(ctx, tx, "where id = $1", jobID)
}

// Cancel anuluje zadanie, ktore nie osiagnelo jeszcze stanu koncowego.
func (s *Store) Cancel(ctx context.Context, tx pgx.Tx, jobID, actor, reason string) (*Job, error) {
	const query = `
		update jobs set state = $2, canceled_by = $3, canceled_at = now(),
		                cancel_reason = $4, finished_at = now(), updated_at = now()
		where id = $1
		  and state in ('planned', 'awaiting_approval', 'queued', 'leased', 'dispatched', 'running')
		returning id`
	var updated string
	err := tx.QueryRow(ctx, query, jobID, string(StateCanceled), actor, nullable(reason)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.getTx(ctx, tx, "where id = $1", jobID)
}

// LeasedJob laczy zadanie z proba, ktora je wykonuje.
type LeasedJob struct {
	Job       Job
	AttemptID string
	Attempt   int
}

// Lease pobiera zadania gotowe do wykonania dla podanych hostow i nadaje im
// lease. SKIP LOCKED sprawia, ze rownolegle workery nie blokuja sie nawzajem
// ani nie pobieraja tego samego zadania.
func (s *Store) Lease(ctx context.Context, gatewayID string, hostIDs []string,
	limit int, leaseDuration time.Duration) ([]LeasedJob, error) {
	if len(hostIDs) == 0 || limit <= 0 {
		return nil, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const selectQuery = `
		select id from jobs
		where state = 'queued'
		  and host_id = any($1)
		  and expires_at > now()
		order by created_at
		limit $2
		for update skip locked`
	rows, err := tx.Query(ctx, selectQuery, hostIDs, limit)
	if err != nil {
		return nil, fmt.Errorf("pobranie zadan: %w", err)
	}
	var jobIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		jobIDs = append(jobIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(jobIDs) == 0 {
		return nil, tx.Commit(ctx)
	}

	leased := make([]LeasedJob, 0, len(jobIDs))
	deadline := time.Now().Add(leaseDuration)
	for _, jobID := range jobIDs {
		if _, err := tx.Exec(ctx,
			`update jobs set state = $2, updated_at = now() where id = $1`,
			jobID, string(StateLeased)); err != nil {
			return nil, err
		}

		var attemptNumber int
		if err := tx.QueryRow(ctx,
			`select coalesce(max(attempt_number), 0) + 1 from job_attempts where job_id = $1`,
			jobID).Scan(&attemptNumber); err != nil {
			return nil, err
		}
		attemptID := uuid.NewString()
		if _, err := tx.Exec(ctx, `
			insert into job_attempts (id, job_id, attempt_number, lease_owner, lease_expires_at, gateway_id)
			values ($1, $2, $3, $4, $5, $6)`,
			attemptID, jobID, attemptNumber, gatewayID, deadline, gatewayID); err != nil {
			return nil, err
		}

		job, err := s.getTx(ctx, tx, "where id = $1", jobID)
		if err != nil {
			return nil, err
		}
		leased = append(leased, LeasedJob{Job: *job, AttemptID: attemptID, Attempt: attemptNumber})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return leased, nil
}

// MarkDispatched odnotowuje przekazanie zadania do agenta.
func (s *Store) MarkDispatched(ctx context.Context, jobID, attemptID, sessionID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`update jobs set state = $2, updated_at = now() where id = $1 and state = $3`,
		jobID, string(StateDispatched), string(StateLeased)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`update job_attempts set dispatched_at = now(), session_id = $2 where id = $1`,
		attemptID, nullableUUID(sessionID)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ReleaseLease zwraca zadanie do kolejki, gdy nie udalo sie go dostarczyc.
func (s *Store) ReleaseLease(ctx context.Context, jobID, attemptID, reason string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		update jobs set state = $2, updated_at = now()
		where id = $1 and state in ('leased', 'dispatched')`,
		jobID, string(StateQueued)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		update job_attempts set finished_at = now(), status = 'released',
		                        message = $2, lease_expires_at = null
		where id = $1`, attemptID, reason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Result opisuje wynik zgloszony przez agenta.
type Result struct {
	Status          string
	ExitCode        int32
	Stdout          []byte
	Stderr          []byte
	OutputTruncated bool
	ErrorCode       string
	Message         string
	Replayed        bool
	UnitStateBefore json.RawMessage
	UnitStateAfter  json.RawMessage
	// Detail jest wynikiem wlasciwym dla typu operacji, np. planem aktualizacji.
	Detail json.RawMessage
}

// RecordResult zapisuje wynik proby i przenosi zadanie do stanu koncowego.
// Zwraca informacje, czy wynik zostal przyjety: pozny wynik po utracie lease
// jest zachowywany diagnostycznie, ale nie nadpisuje nowszej decyzji.
func (s *Store) RecordResult(ctx context.Context, jobID, attemptID string,
	result Result, jobState State) (accepted bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var currentState State
	if err := tx.QueryRow(ctx, `select state from jobs where id = $1 for update`, jobID).
		Scan(&currentState); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}

	if _, err := tx.Exec(ctx, `
		update job_attempts set
			status = $2, exit_code = $3, error_code = $4, message = $5,
			stdout = $6, stderr = $7, output_truncated = $8, replayed = $9,
			unit_state_before = $10, unit_state_after = $11, result_detail = $12,
			finished_at = now(), lease_expires_at = null
		where id = $1`,
		attemptID, result.Status, result.ExitCode, nullable(result.ErrorCode), nullable(result.Message),
		string(result.Stdout), string(result.Stderr), result.OutputTruncated, result.Replayed,
		nullableJSON(result.UnitStateBefore), nullableJSON(result.UnitStateAfter),
		nullableJSON(result.Detail)); err != nil {
		return false, err
	}

	// Stan koncowy jest ostateczny: wynik, ktory przyszedl po anulowaniu albo
	// po innym rozstrzygnieciu, nie cofa decyzji.
	if currentState.Terminal() {
		return false, tx.Commit(ctx)
	}
	if err := currentState.Validate(jobState); err != nil {
		return false, tx.Commit(ctx)
	}

	if _, err := tx.Exec(ctx, `
		update jobs set state = $2, result_status = $3, result_error_code = $4,
		                result_message = $5, finished_at = now(), updated_at = now()
		where id = $1`,
		jobID, string(jobState), result.Status,
		nullable(result.ErrorCode), nullable(result.Message)); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// ReclaimExpiredLeases zwraca do kolejki zadania, ktorych lease wygasl.
// Gateway moze zniknac bez zamkniecia sesji, wiec czas jest jedynym pewnym
// sygnalem, ze proba sie nie powiodla.
func (s *Store) ReclaimExpiredLeases(ctx context.Context) (int, error) {
	const query = `
		with wygasle as (
			select a.id as attempt_id, a.job_id
			from job_attempts a
			join jobs j on j.id = a.job_id
			where a.finished_at is null
			  and a.lease_expires_at is not null
			  and a.lease_expires_at < now()
			  and j.state in ('leased', 'dispatched', 'running')
			for update of a skip locked
		),
		zamkniete as (
			update job_attempts set finished_at = now(), status = 'lease_expired',
			                        lease_expires_at = null
			where id in (select attempt_id from wygasle)
			returning job_id
		)
		update jobs set state = 'queued', updated_at = now()
		where id in (select job_id from zamkniete)
		returning id`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

// ExpireOverdue oznacza zadania, ktore przekroczyly TTL, zanim ruszyly.
func (s *Store) ExpireOverdue(ctx context.Context) (int, error) {
	const query = `
		update jobs set state = 'expired', result_status = 'expired',
		                finished_at = now(), updated_at = now()
		where state in ('planned', 'awaiting_approval', 'queued')
		  and expires_at <= now()
		returning id`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

// Get zwraca zadanie.
func (s *Store) Get(ctx context.Context, jobID string) (*Job, error) {
	return s.getPool(ctx, "where id = $1", jobID)
}

// ListFilter opisuje filtry listy zadan.
type ListFilter struct {
	HostID string
	State  string
	Limit  int
	// Scopes zawezaja wynik do zakresow, w ktorych wolajacy ma prawo odczytu.
	// Pusta lista nie zaweza niczego; zakres pusty w srodku listy oznacza
	// uprawnienie globalne.
	Scopes []Scope
}

// Scope jest para lokalizacja-srodowisko. Pusta wartosc pola znaczy "dowolne".
type Scope struct {
	Site        string
	Environment string
}

// List zwraca zadania zgodne z filtrem.
func (s *Store) List(ctx context.Context, filter ListFilter) ([]Job, error) {
	clause := "where 1 = 1"
	args := []any{}
	// Zadanie nalezy do hosta, wiec widocznosc dziedziczy po nim: operator
	// jednego srodowiska nie moze ogladac zadan z calej floty.
	if len(filter.Scopes) > 0 {
		przelozone := make([]authz.Scope, 0, len(filter.Scopes))
		for _, scope := range filter.Scopes {
			przelozone = append(przelozone, authz.Scope{Site: scope.Site, Environment: scope.Environment})
		}
		if warunek, dodatkowe := authz.ScopeSQL(przelozone, "h.site", "h.environment", len(args)); warunek != "" {
			clause += " and exists (select 1 from hosts h where h.id = jobs.host_id and " + warunek + ")"
			args = append(args, dodatkowe...)
		}
	}
	if filter.HostID != "" {
		args = append(args, filter.HostID)
		clause += fmt.Sprintf(" and host_id = $%d", len(args))
	}
	if filter.State != "" {
		args = append(args, filter.State)
		clause += fmt.Sprintf(" and state = $%d", len(args))
	}
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit)
	clause += fmt.Sprintf(" order by created_at desc limit $%d", len(args))

	return s.queryJobs(ctx, s.pool, clause, args...)
}

// Attempts zwraca proby wykonania zadania.
func (s *Store) Attempts(ctx context.Context, jobID string) ([]Attempt, error) {
	const query = `
		select id, job_id, attempt_number, coalesce(gateway_id, ''), session_id,
		       coalesce(status, ''), exit_code, coalesce(error_code, ''), coalesce(message, ''),
		       coalesce(stdout, ''), coalesce(stderr, ''), output_truncated, replayed,
		       unit_state_before, unit_state_after, result_detail,
		       dispatched_at, finished_at, created_at
		from job_attempts
		where job_id = $1
		order by attempt_number`
	rows, err := s.pool.Query(ctx, query, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attempts []Attempt
	for rows.Next() {
		var a Attempt
		if err := rows.Scan(&a.ID, &a.JobID, &a.Number, &a.GatewayID, &a.SessionID,
			&a.Status, &a.ExitCode, &a.ErrorCode, &a.Message,
			&a.Stdout, &a.Stderr, &a.OutputTruncated, &a.Replayed,
			&a.UnitStateBefore, &a.UnitStateAfter, &a.Detail,
			&a.DispatchedAt, &a.FinishedAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		attempts = append(attempts, a)
	}
	return attempts, rows.Err()
}

type queryable interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (s *Store) getPool(ctx context.Context, clause string, args ...any) (*Job, error) {
	return s.getFrom(ctx, s.pool, clause, args...)
}

func (s *Store) getTx(ctx context.Context, tx pgx.Tx, clause string, args ...any) (*Job, error) {
	return s.getFrom(ctx, tx, clause, args...)
}

func (s *Store) getFrom(ctx context.Context, q queryable, clause string, args ...any) (*Job, error) {
	found, err := s.queryJobs(ctx, q, clause+" limit 1", args...)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, ErrNotFound
	}
	return &found[0], nil
}

func (s *Store) queryJobs(ctx context.Context, q queryable, clause string, args ...any) ([]Job, error) {
	query := `
		select id, host_id, campaign_id, action_type, action_version, payload,
		       encode(payload_hash, 'hex'), idempotency_key, state, requires_approval,
		       preconditions, timeout_seconds, max_output_bytes, expires_at,
		       created_by, coalesce(request_id, ''), coalesce(approved_by, ''), approved_at,
		       coalesce(canceled_by, ''), coalesce(cancel_reason, ''),
		       coalesce(result_status, ''), coalesce(result_error_code, ''),
		       coalesce(result_message, ''), finished_at, created_at, updated_at
		from jobs ` + clause

	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.HostID, &j.CampaignID, &j.ActionType, &j.ActionVersion,
			&j.Payload, &j.PayloadHash, &j.IdempotencyKey, &j.State, &j.RequiresApprova,
			&j.Preconditions, &j.TimeoutSeconds, &j.MaxOutputBytes, &j.ExpiresAt,
			&j.CreatedBy, &j.RequestID, &j.ApprovedBy, &j.ApprovedAt,
			&j.CanceledBy, &j.CancelReason, &j.ResultStatus, &j.ResultErrorCode,
			&j.ResultMessage, &j.FinishedAt, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableJSON(value json.RawMessage) any {
	if len(value) == 0 {
		return nil
	}
	return []byte(value)
}

// AttemptOwner zwraca zadanie, do ktorego nalezy proba. Agent odsyla wynik
// z identyfikatorem proby, wiec gateway musi odnalezc job.
func (s *Store) AttemptOwner(ctx context.Context, attemptID string) (jobID string, err error) {
	jobID, _, err = s.AttemptContext(ctx, attemptID)
	return jobID, err
}

// AttemptContext zwraca operacje proby wraz z jej kampania. Postep zlecony
// w kampanii musi trafic takze na ekran kampanii, a agent zna wylacznie
// identyfikator proby.
func (s *Store) AttemptContext(ctx context.Context, attemptID string) (jobID, campaignID string, err error) {
	var kampania *string
	err = s.pool.QueryRow(ctx, `
		select a.job_id, j.campaign_id::text
		  from job_attempts a join jobs j on j.id = a.job_id
		 where a.id = $1`, attemptID).Scan(&jobID, &kampania)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if kampania != nil {
		campaignID = *kampania
	}
	return jobID, campaignID, err
}
