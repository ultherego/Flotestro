package campaigns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ultherego/flotestro/internal/authz"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrNotFound oznacza brak kampanii.
	ErrNotFound = errors.New("kampania nie istnieje")
	// ErrConflict oznacza operacje niedozwolona w obecnym stanie.
	ErrConflict = errors.New("operacja niedozwolona w obecnym stanie kampanii")
	// ErrNoTargets oznacza selektor, ktory nie wskazal zadnego hosta.
	ErrNoTargets = errors.New("selektor nie wskazal zadnego hosta")
)

// Store realizuje dostep do tabel kampanii.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// TargetHost jest hostem wybranym do kampanii.
type TargetHost struct {
	ID     string
	BootID string
}

// Create tworzy kampanie wraz z niemutowalna migawka celow. Podzial na fale
// nastepuje w chwili planowania: host dodany do floty pozniej nie wejdzie do
// trwajacej kampanii bez wiedzy operatora.
func (s *Store) Create(ctx context.Context, tx pgx.Tx, spec Spec, hosts []TargetHost) (*Campaign, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, ErrNoTargets
	}

	selectorJSON, err := json.Marshal(spec.Selector)
	if err != nil {
		return nil, err
	}
	payload := spec.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	// Pusty wycinek w Go trafilby do bazy jako NULL, a kolumna wymaga tablicy.
	healthChecks := spec.HealthCheckUnits
	if healthChecks == nil {
		healthChecks = []string{}
	}

	state := StateQueuedOrApproval(spec.RequiresApproval)
	campaignID := uuid.NewString()

	const insert = `
		insert into campaigns (id, name, action_type, payload, selector, state,
		                       canary_size, wave_size, max_concurrent,
		                       failure_threshold_percent, failure_threshold_absolute,
		                       maintenance_start, maintenance_end, reboot_policy,
		                       health_check_units, job_timeout_seconds,
		                       requires_approval, created_by, request_id)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`
	if _, err := tx.Exec(ctx, insert, campaignID, spec.Name, spec.ActionType, payload, selectorJSON,
		string(state), spec.CanarySize, spec.WaveSize, spec.MaxConcurrent,
		spec.FailureThresholdPercent, spec.FailureThresholdAbsolute,
		spec.MaintenanceStart, spec.MaintenanceEnd, string(spec.RebootPolicy),
		healthChecks, spec.JobTimeoutSeconds,
		spec.RequiresApproval, spec.CreatedBy, nullable(spec.RequestID)); err != nil {
		return nil, fmt.Errorf("utworzenie kampanii: %w", err)
	}

	for index, host := range hosts {
		wave, position := AssignWave(index, spec.CanarySize, spec.WaveSize)
		const insertTarget = `
			insert into campaign_targets (id, campaign_id, host_id, wave, position, boot_id_before)
			values ($1, $2, $3, $4, $5, $6)`
		if _, err := tx.Exec(ctx, insertTarget, uuid.NewString(), campaignID,
			host.ID, wave, position, nullable(host.BootID)); err != nil {
			return nil, fmt.Errorf("zapis celu kampanii: %w", err)
		}
	}

	return s.getTx(ctx, tx, campaignID)
}

// StateQueuedOrApproval zwraca stan poczatkowy kampanii.
func StateQueuedOrApproval(requiresApproval bool) State {
	if requiresApproval {
		return StateAwaitingApproval
	}
	return StatePlanned
}

// AssignWave przydziela hosta do fali. Fala 0 jest canary i ma wlasny rozmiar;
// kolejne fale maja staly rozmiar.
func AssignWave(index, canarySize, waveSize int) (wave, position int) {
	if index < canarySize {
		return 0, index
	}
	remaining := index - canarySize
	return remaining/waveSize + 1, remaining % waveSize
}

// Approve zatwierdza kampanie i pozwala jej ruszyc.
func (s *Store) Approve(ctx context.Context, tx pgx.Tx, campaignID, actor string) (*Campaign, error) {
	const query = `
		update campaigns set state = $2, approved_by = $3, approved_at = now(), updated_at = now()
		where id = $1 and state = $4
		returning id`
	var updated string
	err := tx.QueryRow(ctx, query, campaignID, string(StatePlanned), actor,
		string(StateAwaitingApproval)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.getTx(ctx, tx, campaignID)
}

// Pause wstrzymuje kampanie. Hosty juz uruchomione dokoncza swoje zadania.
func (s *Store) Pause(ctx context.Context, campaignID, actor, reason string) (*Campaign, error) {
	const query = `
		update campaigns set state = $2, paused_by = $3, paused_at = now(),
		                     pause_reason = $4, updated_at = now()
		where id = $1 and state in ('planned', 'canary', 'running')
		returning id`
	var updated string
	err := s.pool.QueryRow(ctx, query, campaignID, string(StatePaused), actor, nullable(reason)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, campaignID)
}

// Resume wznawia wstrzymana kampanie.
func (s *Store) Resume(ctx context.Context, campaignID, actor string) (*Campaign, error) {
	const query = `
		update campaigns set state = $2, paused_by = null, paused_at = null,
		                     pause_reason = null, updated_at = now()
		where id = $1 and state = $3
		returning id`
	var updated string
	err := s.pool.QueryRow(ctx, query, campaignID, string(StatePlanned), string(StatePaused)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, campaignID)
}

// Cancel konczy kampanie. Cele, ktore jeszcze nie ruszyly, sa pomijane.
func (s *Store) Cancel(ctx context.Context, campaignID, actor, reason string) (*Campaign, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const query = `
		update campaigns set state = $2, canceled_by = $3, canceled_at = now(),
		                     pause_reason = $4, finished_at = now(), updated_at = now()
		where id = $1 and state not in ('completed', 'failed', 'canceled')
		returning id`
	var updated string
	err = tx.QueryRow(ctx, query, campaignID, string(StateCanceled), actor, nullable(reason)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}

	// Hosty, ktore jeszcze nie ruszyly, nie zostana ruszone.
	if _, err := tx.Exec(ctx, `
		update campaign_targets set state = 'canceled', finished_at = now()
		where campaign_id = $1 and state = 'pending'`, campaignID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Get(ctx, campaignID)
}

// SetState zmienia stan kampanii.
func (s *Store) SetState(ctx context.Context, campaignID string, state State, reason string) error {
	const query = `
		update campaigns set state = $2, updated_at = now(),
			pause_reason = case when $2 = 'paused' then $3 else pause_reason end,
			paused_at    = case when $2 = 'paused' then now() else paused_at end,
			paused_by    = case when $2 = 'paused' then 'system' else paused_by end,
			started_at   = coalesce(started_at, case when $2 in ('canary', 'running') then now() end),
			finished_at  = case when $2 in ('completed', 'failed', 'canceled') then now() else finished_at end
		where id = $1`
	_, err := s.pool.Exec(ctx, query, campaignID, string(state), nullable(reason))
	return err
}

// Active zwraca kampanie wymagajace obslugi przez orkiestrator.
func (s *Store) Active(ctx context.Context) ([]Campaign, error) {
	return s.query(ctx, "where state in ('planned', 'canary', 'running') order by created_at")
}

// Get zwraca kampanie.
func (s *Store) Get(ctx context.Context, campaignID string) (*Campaign, error) {
	found, err := s.query(ctx, "where id = $1", campaignID)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, ErrNotFound
	}
	return &found[0], nil
}

func (s *Store) getTx(ctx context.Context, tx pgx.Tx, campaignID string) (*Campaign, error) {
	rows, err := tx.Query(ctx, campaignColumns+" where id = $1", campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	campaigns, err := scanCampaigns(rows)
	if err != nil {
		return nil, err
	}
	if len(campaigns) == 0 {
		return nil, ErrNotFound
	}
	return &campaigns[0], nil
}

// List zwraca kampanie, opcjonalnie zawezone stanem.
// Scope jest para lokalizacja-srodowisko. Pusta wartosc pola znaczy "dowolne".
type Scope struct {
	Site        string
	Environment string
}

// List zwraca kampanie zawezone do zakresow, w ktorych wolajacy ma prawo
// odczytu.
//
// Kampania nie ma wlasnego zakresu - ma cele. Widoczna jest wiec ta, ktora
// dotyka choc jednego hosta z zakresu wolajacego; operator jednego srodowiska
// widzi kampanie, ktore go dotycza, i nie widzi cudzych.
func (s *Store) List(ctx context.Context, state string, limit int, scopes []Scope) ([]Campaign, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	clause := "where 1 = 1"
	args := []any{}
	if state != "" {
		args = append(args, state)
		clause += fmt.Sprintf(" and state = $%d", len(args))
	}
	if warunek, dodatkowe := scopeCondition(scopes, len(args)); warunek != "" {
		clause += warunek
		args = append(args, dodatkowe...)
	}
	return s.query(ctx, clause+" order by created_at desc limit "+itoa(limit), args...)
}

// scopeCondition buduje warunek widocznosci po celach kampanii.
func scopeCondition(scopes []Scope, offset int) (string, []any) {
	przelozone := make([]authz.Scope, 0, len(scopes))
	for _, scope := range scopes {
		przelozone = append(przelozone, authz.Scope{Site: scope.Site, Environment: scope.Environment})
	}
	warunek, args := authz.ScopeSQL(przelozone, "h.site", "h.environment", offset)
	if warunek == "" {
		return "", nil
	}
	return " and exists (select 1 from campaign_targets t join hosts h on h.id = t.host_id" +
		" where t.campaign_id = campaigns.id and " + warunek + ")", args
}

const campaignColumns = `
	select id, name, action_type, payload, selector, state,
	       canary_size, wave_size, max_concurrent,
	       failure_threshold_percent, failure_threshold_absolute,
	       maintenance_start, maintenance_end, reboot_policy, health_check_units,
	       job_timeout_seconds, requires_approval,
	       coalesce(approved_by, ''), approved_at, coalesce(paused_by, ''),
	       coalesce(pause_reason, ''), coalesce(canceled_by, ''),
	       created_by, coalesce(request_id, ''), started_at, finished_at, created_at, updated_at
	from campaigns `

func (s *Store) query(ctx context.Context, clause string, args ...any) ([]Campaign, error) {
	rows, err := s.pool.Query(ctx, campaignColumns+clause, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCampaigns(rows)
}

func scanCampaigns(rows pgx.Rows) ([]Campaign, error) {
	var campaigns []Campaign
	for rows.Next() {
		var c Campaign
		if err := rows.Scan(&c.ID, &c.Name, &c.ActionType, &c.Payload, &c.Selector, &c.State,
			&c.CanarySize, &c.WaveSize, &c.MaxConcurrent,
			&c.FailureThresholdPercent, &c.FailureThresholdAbsolute,
			&c.MaintenanceStart, &c.MaintenanceEnd, &c.RebootPolicy, &c.HealthCheckUnits,
			&c.JobTimeoutSeconds, &c.RequiresApproval,
			&c.ApprovedBy, &c.ApprovedAt, &c.PausedBy, &c.PauseReason, &c.CanceledBy,
			&c.CreatedBy, &c.RequestID, &c.StartedAt, &c.FinishedAt,
			&c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		campaigns = append(campaigns, c)
	}
	return campaigns, rows.Err()
}

// Targets zwraca cele kampanii w kolejnosci fal.
func (s *Store) Targets(ctx context.Context, campaignID string) ([]Target, error) {
	const query = `
		select t.id, t.campaign_id, t.host_id, coalesce(h.hostname, ''), t.wave, t.position,
		       t.state, t.job_id, t.reboot_job_id, t.health_job_id, coalesce(t.boot_id_before, ''),
		       coalesce(t.error_code, ''), coalesce(t.message, ''), t.started_at, t.finished_at
		from campaign_targets t
		left join hosts h on h.id = t.host_id
		where t.campaign_id = $1
		order by t.wave, t.position`
	rows, err := s.pool.Query(ctx, query, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.CampaignID, &t.HostID, &t.Hostname, &t.Wave, &t.Position,
			&t.State, &t.JobID, &t.RebootJobID, &t.HealthJobID, &t.BootIDBefore,
			&t.ErrorCode, &t.Message, &t.StartedAt, &t.FinishedAt); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// UpdateTarget zapisuje stan celu kampanii.
func (s *Store) UpdateTarget(ctx context.Context, targetID string, state TargetState,
	errorCode, message string) error {
	const query = `
		update campaign_targets set
			state       = $2,
			error_code  = $3,
			message     = $4,
			started_at  = coalesce(started_at, case when $2 <> 'pending' then now() end),
			finished_at = case when $2 in ('succeeded', 'failed', 'skipped', 'canceled')
			                   then now() else finished_at end
		where id = $1`
	_, err := s.pool.Exec(ctx, query, targetID, string(state), nullable(errorCode), nullable(message))
	return err
}

// AttachJob wiaze cel z utworzonym zadaniem.
func (s *Store) AttachJob(ctx context.Context, targetID, column, jobID string) error {
	var query string
	switch column {
	case "job_id":
		query = `update campaign_targets set job_id = $2 where id = $1`
	case "reboot_job_id":
		query = `update campaign_targets set reboot_job_id = $2 where id = $1`
	case "health_job_id":
		query = `update campaign_targets set health_job_id = $2 where id = $1`
	default:
		return fmt.Errorf("nieznana kolumna zadania %q", column)
	}
	_, err := s.pool.Exec(ctx, query, targetID, jobID)
	return err
}

// SetBootIDBefore zapisuje boot ID sprzed restartu.
func (s *Store) SetBootIDBefore(ctx context.Context, targetID, bootID string) error {
	_, err := s.pool.Exec(ctx,
		`update campaign_targets set boot_id_before = $2 where id = $1`, targetID, nullable(bootID))
	return err
}

// Counts zwraca liczbe celow w kazdym stanie.
func (s *Store) Counts(ctx context.Context, campaignID string) (map[string]int, error) {
	const query = `select state, count(*) from campaign_targets where campaign_id = $1 group by state`
	rows, err := s.pool.Query(ctx, query, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		counts[state] = count
	}
	return counts, rows.Err()
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func itoa(value int) string {
	return fmt.Sprintf("%d", value)
}
