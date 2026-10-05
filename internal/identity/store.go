package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrNotFound means there is no change with the given identifier.
	ErrNotFound = errors.New("the change does not exist")
	// ErrNoPrincipal means the panel holds no identity under the name an
	// operation was aimed at. A denial that marks nobody is not a denial.
	ErrNoPrincipal = errors.New("the panel holds no identity under that name")
	// ErrConflict means an operation not allowed in the current state.
	ErrConflict = errors.New("the operation is not allowed in the current state of the change")
	// ErrBlocked means a plan that rules out execution.
	ErrBlocked = errors.New("the plan holds conflicts and cannot be carried out")
)

// Store gives access to the directory change table, and holds the one-time
// values of changes that must not enter it.
type Store struct {
	pool    *pgxpool.Pool
	secrets *secretVault
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, secrets: newSecretVault()}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Spec describes the change to create.
type Spec struct {
	Action           ActionType
	Payload          Payload
	Plan             Plan
	RequiresApproval bool
	CreatedBy        string
	RequestID        string
}

// Create records a planned change. A change that requires approval does not
// start until somebody approves it.
func (s *Store) Create(ctx context.Context, tx pgx.Tx, spec Spec) (*Change, error) {
	if err := Validate(spec.Action, spec.Payload); err != nil {
		return nil, err
	}
	hash, err := PayloadHash(spec.Action, spec.Payload)
	if err != nil {
		return nil, err
	}
	payloadJSON, err := json.Marshal(spec.Payload)
	if err != nil {
		return nil, err
	}
	planJSON, err := json.Marshal(spec.Plan)
	if err != nil {
		return nil, err
	}

	state := StatePlanned
	if spec.RequiresApproval {
		state = StateAwaitingApproval
	}
	id := uuid.NewString()

	const query = `
		insert into directory_changes
			(id, action_type, payload, payload_hash, plan, state, requires_approval,
			 created_by, request_id)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	if _, err := tx.Exec(ctx, query, id, string(spec.Action), payloadJSON, hash, planJSON,
		string(state), spec.RequiresApproval, spec.CreatedBy, nullable(spec.RequestID)); err != nil {
		return nil, fmt.Errorf("recording the directory change: %w", err)
	}
	return s.getTx(ctx, tx, id)
}

// Approve approves the change and admits it to execution.
func (s *Store) Approve(ctx context.Context, tx pgx.Tx, changeID, actor string) (*Change, error) {
	const query = `
		update directory_changes set state = $2, approved_by = $3, approved_at = now(),
		                             updated_at = now()
		where id = $1 and state = $4
		returning id`
	var updated string
	err := tx.QueryRow(ctx, query, changeID, string(StatePlanned), actor,
		string(StateAwaitingApproval)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.getTx(ctx, tx, changeID)
}

// Cancel cancels a change that has not started yet.
func (s *Store) Cancel(ctx context.Context, changeID, actor, reason string) (*Change, error) {
	const query = `
		update directory_changes set state = $2, canceled_by = $3, canceled_at = now(),
		                             result_message = $4, finished_at = now(), updated_at = now()
		where id = $1 and state in ('planned', 'awaiting_approval')
		returning id`
	var updated string
	err := s.pool.QueryRow(ctx, query, changeID, string(StateCanceled), actor, nullable(reason)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, changeID)
}

// ClaimTerm is how long a claim on a directory change holds. What it bounds is
// not the work but how long a change stays invisible after the replica carrying
// it stops: a holder that is alive renews the claim through RenewClaim, so a
// change slower than the term is not taken from under it.
const ClaimTerm = 15 * time.Minute

// RenewTerm is how often a holder renews its claim while it works. It is a
// third of the term, so two renewals may be lost without the change being
// declared stalled.
const RenewTerm = ClaimTerm / 3

// ClaimStanding is what a claiming or renewing statement said about the term,
// and when it was asked. Both halves come from the database: the deadline it
// stored, and how much of the term was left by its own clock when it answered.
// The remaining term is the usable one, because the database's clock and the
// holder's are not the same clock, and subtracting one from the other measures
// the skew along with the time.
type ClaimStanding struct {
	// Asked is the local clock at the moment the statement was sent.
	Asked time.Time
	// ExpiresAt is the deadline the database stored, in the database's clock.
	ExpiresAt time.Time
	// Remaining is ExpiresAt less the database's own clock at the moment the
	// statement answered.
	Remaining time.Duration
}

// Known says whether the database answered with a term at all. An unknown
// standing is neither a lapsed claim nor an endless one: the caller falls back
// to the conservative local reading, and says which of the two it used.
func (c ClaimStanding) Known() bool { return !c.Asked.IsZero() && !c.ExpiresAt.IsZero() }

// Deadline is the local instant after which this claim cannot be relied on. It
// is measured from Asked and never from the moment the answer was read: the
// database stamped the deadline when its transaction began, so whatever a slow
// statement spent - a loaded directory, a retried connection, a lock wait - is
// term the holder no longer has. Measuring it from the answer handed that time
// back, and two replicas then believed they held the same change.
//
// Zero where the standing is unknown; the caller decides what to make of that.
func (c ClaimStanding) Deadline() time.Time {
	if !c.Known() {
		return time.Time{}
	}
	return c.Asked.Add(c.Remaining)
}

// claimStanding is the one reader of the two values every claim statement
// returns, so the claim and the renewal cannot read them differently.
func claimStanding(asked, expiresAt time.Time, remainingSeconds float64) ClaimStanding {
	return ClaimStanding{Asked: asked, ExpiresAt: expiresAt,
		Remaining: time.Duration(remainingSeconds * float64(time.Second))}
}

// claimStandingColumns is what a claim statement returns about the term: the
// deadline it stored, and the term left by the database's own wall clock at the
// moment the statement ran. now() would answer the second with the whole term,
// because it is the transaction's start time - the very value the deadline was
// computed from - so the time the statement itself spent would go unmeasured.
const claimStandingColumns = `directory_changes.claim_expires_at,
		       extract(epoch from (directory_changes.claim_expires_at - clock_timestamp()))::double precision`

// Hold is one replica's hold on one change: which replica took it, and which
// attempt that take is. Every write about a running change names both, because
// "the holder" alone cannot tell a run from the run that replaced it.
type Hold struct {
	Holder string
	// Attempt is minted by Claim, once per take of the row.
	Attempt string
	// Resumed says the row was already running when this attempt took it: an
	// earlier attempt had begun and recorded no result. It is read by the
	// claiming statement itself, because the snapshot a poll took before the
	// claim can say "planned" about a row that is being taken out of running.
	Resumed bool
	// Phases are the phases the row carried at the moment of the take - what an
	// earlier attempt wrote down, read in the same statement that claimed it.
	Phases json.RawMessage
	// Standing is the term as the database stated it when the claim landed. It
	// is the only deadline there is: a term counted locally from the answer runs
	// past the row's claim_expires_at by however long the statement took.
	Standing ClaimStanding
}

// Held says whether the hold names an attempt. A write that cannot say which
// run produced it does not land.
func (h Hold) Held() bool { return h.Attempt != "" }

// RenewClaim extends the claim of the holder that is carrying the change out.
// It answers false when the row is no longer this hold's - the claim lapsed and
// somebody else took the change, or the change has finished - and the holder
// then has to stop writing to it.
func (s *Store) RenewClaim(ctx context.Context, changeID string, hold Hold) (ClaimStanding, bool, error) {
	if !hold.Held() {
		return ClaimStanding{}, false, nil
	}
	const query = `
		update directory_changes
		   set claim_expires_at = now() + make_interval(secs => $4::double precision),
		       updated_at = now()
		 where id = $1 and state = 'running'
		   and claimed_by = $2 and claim_token = $3::uuid
		returning ` + claimStandingColumns
	asked := time.Now()
	var expiresAt time.Time
	var remaining float64
	err := s.pool.QueryRow(ctx, query, changeID, nullable(hold.Holder), hold.Attempt,
		ClaimTerm.Seconds()).Scan(&expiresAt, &remaining)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimStanding{}, false, nil
	}
	if err != nil {
		return ClaimStanding{}, false, err
	}
	return claimStanding(asked, expiresAt, remaining), true, nil
}

// SavePhases records the phases of a change that is still running, so that a
// replica which takes the change over - or takes it again after a crash - reads
// what already happened instead of assuming nothing did. It writes only under
// this hold, and never to a change that has finished.
func (s *Store) SavePhases(ctx context.Context, changeID string, hold Hold, phases []Phase) error {
	if !hold.Held() {
		return fmt.Errorf("the phases of the change %s name no attempt, so they were not recorded", changeID)
	}
	phasesJSON, err := json.Marshal(phases)
	if err != nil {
		return err
	}
	const query = `
		update directory_changes set phases = $2, updated_at = now()
		 where id = $1 and state = 'running'
		   and claimed_by = $3 and claim_token = $4::uuid`
	tag, err := s.pool.Exec(ctx, query, changeID, phasesJSON, nullable(hold.Holder), hold.Attempt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("the change %s is no longer this attempt's, so its phases were not recorded",
			changeID)
	}
	return nil
}

// Claim takes a change for execution. The condition on the state means two
// replicas will not carry out the same change in parallel - and the claim is
// recorded with a holder and a term, because a change left in running by a
// replica that stopped was afterwards seen by nobody: Pending reads the
// planned ones, so there was no way back to it and no view that showed it as
// overdue.
// Every take mints an attempt, so the result of a run can be told from the
// result of the run that replaced it.
//
// The take also reports what it found: whether the row was already running, and
// the phases it carried. That is read here and not from the list a tick polled,
// because between the poll and the claim the row moves: a snapshot saying
// "planned" has admitted a second password reset to a change that was already
// running, which is precisely what the guard against repeating one exists to
// stop. The claiming statement is the only reader whose answer is about the row
// it took.
func (s *Store) Claim(ctx context.Context, changeID, holder string) (Hold, bool, error) {
	hold := Hold{Holder: holder, Attempt: uuid.NewString()}
	const query = `
		with before as (
		    select id, state, phases from directory_changes where id = $1 for update
		)
		update directory_changes
		   set state = $2, started_at = now(), updated_at = now(),
		       claimed_by = $4, claim_token = $6::uuid,
		       claim_expires_at = now() + make_interval(secs => $5::double precision)
		  from before
		 where directory_changes.id = before.id
		   and (before.state = $3
		        or (before.state = $2 and directory_changes.claim_expires_at < now()))
		returning (before.state = $2) as resumed, before.phases,
		          ` + claimStandingColumns
	// Asked before the statement goes out, because that is where the term the
	// database is about to stamp begins. The lock wait in the clause above is
	// part of it, and a take that waited has that much less term left.
	asked := time.Now()
	var phases []byte
	var expiresAt time.Time
	var remaining float64
	err := s.pool.QueryRow(ctx, query, changeID, string(StateRunning), string(StatePlanned),
		nullable(holder), ClaimTerm.Seconds(), hold.Attempt).
		Scan(&hold.Resumed, &phases, &expiresAt, &remaining)
	if errors.Is(err, pgx.ErrNoRows) {
		return Hold{}, false, nil
	}
	if err != nil {
		return Hold{}, false, err
	}
	hold.Phases = phases
	hold.Standing = claimStanding(asked, expiresAt, remaining)
	return hold, true, nil
}

// Finish records the execution result phase by phase. The hold is the whole of
// the condition, and the state is the other half of it: the result of an
// attempt the row has moved on from does not land, and a change that has
// reached a terminal state is terminal - a predecessor whose claim lapsed used
// to satisfy "nobody holds it" once the successor had cleared the holder, and
// wrote failed over the successor's succeeded.
func (s *Store) Finish(ctx context.Context, changeID string, hold Hold, state State,
	phases []Phase, message string) error {
	if !hold.Held() {
		return fmt.Errorf("the result of the change %s names no attempt, so it was not recorded", changeID)
	}
	phasesJSON, err := json.Marshal(phases)
	if err != nil {
		return err
	}
	const query = `
		update directory_changes set state = $2, phases = $3, result_message = $4,
		                             finished_at = now(), updated_at = now(),
		                             claimed_by = null, claim_expires_at = null,
		                             claim_token = null
		where id = $1 and state = $7
		  and claimed_by = $5 and claim_token = $6::uuid`
	tag, err := s.pool.Exec(ctx, query, changeID, string(state), phasesJSON, nullable(message),
		nullable(hold.Holder), hold.Attempt, string(StateRunning))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: the change %s is no longer this attempt's, so its result was not recorded",
			ErrClaimLost, changeID)
	}
	return nil
}

// ErrClaimLost means a write about a running change did not land, because the
// change belongs to another attempt or has already finished.
var ErrClaimLost = errors.New("the change is no longer this attempt's")

// Pending returns the approved changes waiting for execution, and the ones
// somebody claimed and did not finish within the term. The second half is what
// brings back a change whose replica stopped between the claim and the finish:
// without it the row stayed in running and was read by nothing.
func (s *Store) Pending(ctx context.Context) ([]Change, error) {
	return s.query(ctx, `where state = 'planned'
	                        or (state = 'running' and claim_expires_at < now())
	                     order by created_at limit 20`)
}

// Stalled returns the changes whose claim has lapsed, so the panel can show a
// change that is overdue rather than one that silently stays.
func (s *Store) Stalled(ctx context.Context) ([]Change, error) {
	return s.query(ctx, `where state = 'running' and claim_expires_at < now()
	                     order by started_at limit 50`)
}

// Get zwraca zmiane.
func (s *Store) Get(ctx context.Context, changeID string) (*Change, error) {
	found, err := s.query(ctx, "where id = $1", changeID)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, ErrNotFound
	}
	return &found[0], nil
}

func (s *Store) getTx(ctx context.Context, tx pgx.Tx, changeID string) (*Change, error) {
	rows, err := tx.Query(ctx, changeColumns+" where id = $1", changeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	changes, err := scanChanges(rows)
	if err != nil {
		return nil, err
	}
	if len(changes) == 0 {
		return nil, ErrNotFound
	}
	return &changes[0], nil
}

// List returns the changes, optionally narrowed by state.
func (s *Store) List(ctx context.Context, state string, limit int) ([]Change, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if state != "" {
		return s.query(ctx, fmt.Sprintf("where state = $1 order by created_at desc limit %d", limit), state)
	}
	return s.query(ctx, fmt.Sprintf("order by created_at desc limit %d", limit))
}

const changeColumns = `
	select id, action_type, payload, encode(payload_hash, 'hex'), plan, state,
	       requires_approval, coalesce(approved_by, ''), approved_at,
	       coalesce(canceled_by, ''), phases, coalesce(result_message, ''),
	       created_by, coalesce(request_id, ''), started_at, finished_at, created_at
	from directory_changes `

func (s *Store) query(ctx context.Context, clause string, args ...any) ([]Change, error) {
	rows, err := s.pool.Query(ctx, changeColumns+clause, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChanges(rows)
}

func scanChanges(rows pgx.Rows) ([]Change, error) {
	var changes []Change
	for rows.Next() {
		var c Change
		if err := rows.Scan(&c.ID, &c.ActionType, &c.Payload, &c.PayloadHash, &c.Plan,
			&c.State, &c.RequiresApproval, &c.ApprovedBy, &c.ApprovedAt, &c.CanceledBy,
			&c.Phases, &c.ResultMessage, &c.CreatedBy, &c.RequestID,
			&c.StartedAt, &c.FinishedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}
	return changes, rows.Err()
}

// SetLocalDeny sets the local denial marker on one panel identity, named
// exactly as the identity provider wrote it. Which identities a directory
// account covers is decided once, by MatchesDirectoryUser.
func (s *Store) SetLocalDeny(ctx context.Context, subject, reason string, denied bool) (int64, error) {
	var query string
	var args []any
	if denied {
		query = `update principals set denied_at = now(), denied_reason = $2, updated_at = now()
		         where subject = $1`
		args = []any{subject, nullable(reason)}
	} else {
		query = `update principals set denied_at = null, denied_reason = null, updated_at = now()
		         where subject = $1`
		args = []any{subject}
	}
	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() == 0 {
		// The caller is locking an account out, and the count went into a
		// phase the operator read as a success: "identities marked: 0" beside
		// a step that said it had done its work. The subject here is the name
		// of an account, and principals are keyed by what the identity
		// provider calls the person - so a denial aimed at the wrong key
		// marked nobody and said nothing.
		return 0, fmt.Errorf("%w: no identity of the panel answers to %q, so the denial marked nobody",
			ErrNoPrincipal, subject)
	}
	return tag.RowsAffected(), nil
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
