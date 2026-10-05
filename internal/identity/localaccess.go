package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
)

// The local half of an access cut is owed on its own row, with its own claim,
// its own term and its own backoff. It does not share the directory change's
// claim: by the time this is retried the change is terminal, and a terminal
// change is never claimed again.
const (
	// ArrearClaimTerm bounds how long one row stays invisible after the replica
	// carrying it stops. The work under it is short - a few statements and one
	// call to the identity provider - so there is nothing to renew.
	ArrearClaimTerm = 2 * time.Minute
	// ArrearBaseBackoff is the pause after the first attempt that did not
	// confirm the effects; it doubles from there.
	ArrearBaseBackoff = 5 * time.Second
	// ArrearMaxBackoff bounds that pause. An access cut is not left for an hour.
	ArrearMaxBackoff = 2 * time.Minute
	// arrearPoll is how often a replica looks for a due row.
	arrearPoll = 5 * time.Second
	// arrearBatch bounds one round, so one replica does not hold the whole
	// backlog while the others idle.
	arrearBatch = 20
)

// AccessPrincipal is one panel identity an access cut names: the subject whose
// denial marker goes on and the identifier whose sessions end. Both are
// resolved once, before the directory is touched, and kept - the retry must not
// resolve them from a directory read, because the account it would read may be
// the one the change removed.
type AccessPrincipal struct {
	Subject     string `json:"subject"`
	PrincipalID string `json:"principal_id"`
}

// LocalAccessArrear is the panel half of an access cut that is still owed, as
// the panel reads it.
type LocalAccessArrear struct {
	ID           string            `json:"id"`
	ChangeID     string            `json:"change_id"`
	DirectoryUID string            `json:"directory_uid"`
	Principals   []AccessPrincipal `json:"principals"`
	Reason       string            `json:"reason,omitempty"`
	State        string            `json:"state"`
	Attempts     int               `json:"attempts"`
	// OutstandingSince and ArrearsSeconds are the two readings of the same
	// thing: when the panel took the obligation on, and how long it has been
	// owed. The panel shows the second one beside the last error.
	OutstandingSince time.Time  `json:"outstanding_since"`
	ArrearsSeconds   float64    `json:"arrears_seconds"`
	NextAttemptAt    time.Time  `json:"next_attempt_at"`
	LastError        string     `json:"last_error"`
	SettledAt        *time.Time `json:"settled_at,omitempty"`
	UpdatedAt        time.Time  `json:"updated_at"`

	// claim is the hold this replica has on the row while it retries it. It is
	// the row's own and never leaves the package.
	claimedBy  string
	claimToken string
}

// arrearColumns is the one column list every read of the table uses, so a read
// cannot go out of step with the scanner.
const arrearColumns = `
	select id, change_id, directory_uid, principals, reason, state, attempts,
	       created_at, extract(epoch from (now() - created_at))::double precision,
	       next_attempt_at, last_error, settled_at, updated_at,
	       coalesce(claimed_by, ''), coalesce(claim_token::text, '')
	  from local_access_arrears `

func scanArrears(rows pgx.Rows) ([]LocalAccessArrear, error) {
	var arrears []LocalAccessArrear
	for rows.Next() {
		var arrear LocalAccessArrear
		var principals []byte
		if err := rows.Scan(&arrear.ID, &arrear.ChangeID, &arrear.DirectoryUID, &principals,
			&arrear.Reason, &arrear.State, &arrear.Attempts, &arrear.OutstandingSince,
			&arrear.ArrearsSeconds, &arrear.NextAttemptAt, &arrear.LastError, &arrear.SettledAt,
			&arrear.UpdatedAt, &arrear.claimedBy, &arrear.claimToken); err != nil {
			return nil, err
		}
		if len(principals) > 0 {
			if err := json.Unmarshal(principals, &arrear.Principals); err != nil {
				return nil, err
			}
		}
		arrears = append(arrears, arrear)
	}
	return arrears, rows.Err()
}

// OweLocalAccess records that the panel owes the local half of an access cut,
// for the change that is about to make - or has made - the directory half.
//
// It is written BEFORE the mutating call, never after: an obligation written
// afterwards is missing in exactly the window it exists for, which is the one
// where the replica stopped. Writing it twice is the same obligation and not a
// second one, so the change is the key.
func (s *Store) OweLocalAccess(ctx context.Context, changeID, uid, reason string,
	principals []AccessPrincipal) error {
	if changeID == "" || uid == "" {
		return fmt.Errorf("an access cut owed by nobody names no change or no account")
	}
	if principals == nil {
		principals = []AccessPrincipal{}
	}
	encoded, err := json.Marshal(principals)
	if err != nil {
		return err
	}
	const query = `
		insert into local_access_arrears (change_id, directory_uid, principals, reason)
		values ($1, $2, $3::jsonb, $4)
		on conflict (change_id) do nothing`
	if _, err := s.pool.Exec(ctx, query, changeID, uid, encoded, reason); err != nil {
		return fmt.Errorf("recording the panel access the change %s owes: %w", changeID, err)
	}
	return nil
}

// ClaimLocalAccess takes the due arrears for one replica, oldest arrears first
// so the longest-standing obligation goes first. The claim is the row's own and
// lapses on its own, so a row whose replica stopped is taken again rather than
// staying claimed by nobody.
func (s *Store) ClaimLocalAccess(ctx context.Context, holder string, limit int) ([]LocalAccessArrear, error) {
	if limit <= 0 || limit > 200 {
		limit = arrearBatch
	}
	token := uuid.NewString()
	const query = `
		with due as (
		    select id from local_access_arrears
		     where state = 'outstanding' and next_attempt_at <= now()
		       and (claim_expires_at is null or claim_expires_at < now())
		     order by created_at
		       for update skip locked
		     limit $3
		)
		update local_access_arrears a
		   set claimed_by = $1, claim_token = $2::uuid,
		       claim_expires_at = now() + make_interval(secs => $4::double precision),
		       attempts = attempts + 1, updated_at = now()
		  from due
		 where a.id = due.id
		returning a.id, a.change_id, a.directory_uid, a.principals, a.reason, a.state, a.attempts,
		          a.created_at, extract(epoch from (now() - a.created_at))::double precision,
		          a.next_attempt_at, a.last_error, a.settled_at, a.updated_at,
		          coalesce(a.claimed_by, ''), coalesce(a.claim_token::text, '')`
	rows, err := s.pool.Query(ctx, query, holder, token, limit, ArrearClaimTerm.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanArrears(rows)
}

// ErrAccessNotConfirmed means the effects of the local half were not read back
// as done, so the obligation stays owed. It is not an error of the attempt: it
// is the attempt's answer.
var ErrAccessNotConfirmed = errors.New("the panel access of the account is not confirmed to be gone")

// SettleLocalAccess settles the obligation, and only on the effects it names.
// The confirmation is part of the statement that settles it: every subject the
// cut names is either denied or unknown to the panel, and none of them holds a
// live session. A settlement written because a call returned without an error
// is a row claiming an effect nobody read back - which is how the obligation
// inside the change's phases came to be marked succeeded over a denial that had
// failed.
//
// It answers ErrAccessNotConfirmed where the effects are not there, or where
// the row is no longer this claim's.
func (s *Store) SettleLocalAccess(ctx context.Context, arrear LocalAccessArrear) error {
	if arrear.claimToken == "" {
		return fmt.Errorf("the obligation %s names no claim, so it was not settled", arrear.ID)
	}
	subjects, principalIDs := arrear.targets()
	const query = `
		update local_access_arrears a
		   set state = 'settled', settled_at = now(), last_error = '',
		       claimed_by = null, claim_token = null, claim_expires_at = null,
		       updated_at = now()
		 where a.id = $1 and a.state = 'outstanding'
		   and a.claimed_by = $2 and a.claim_token = $3::uuid
		   and not exists (select 1 from principals p
		                    where p.subject = any($4::text[]) and p.denied_at is null)
		   and not exists (select 1 from web_sessions w
		                    where w.principal_id = any($5::uuid[]) and w.revoked_at is null)`
	tag, err := s.pool.Exec(ctx, query, arrear.ID, arrear.claimedBy, arrear.claimToken,
		subjects, principalIDs)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAccessNotConfirmed
	}
	return nil
}

// HoldLocalAccess puts the obligation back with the pause before the next
// attempt and what the last one said. The claim is part of the condition: a
// replica whose claim lapsed does not write over the attempt that replaced it.
func (s *Store) HoldLocalAccess(ctx context.Context, arrear LocalAccessArrear,
	backoff time.Duration, cause string) error {
	const query = `
		update local_access_arrears
		   set next_attempt_at = now() + make_interval(secs => $4::double precision),
		       last_error = $5, claimed_by = null, claim_token = null,
		       claim_expires_at = null, updated_at = now()
		 where id = $1 and state = 'outstanding'
		   and claimed_by = $2 and claim_token = $3::uuid`
	_, err := s.pool.Exec(ctx, query, arrear.ID, arrear.claimedBy, arrear.claimToken,
		backoff.Seconds(), cause)
	return err
}

// OpenLocalAccess reads what is still owed, longest arrears first, so the panel
// shows how long an access cut has been outstanding and what the last attempt
// said about it.
func (s *Store) OpenLocalAccess(ctx context.Context, limit int) ([]LocalAccessArrear, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, arrearColumns+
		fmt.Sprintf("where state = 'outstanding' order by created_at limit %d", limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanArrears(rows)
}

// LocalAccessOf reads the obligation of one change, settled or not, so the
// change's own view can say whether the panel still owes anything.
func (s *Store) LocalAccessOf(ctx context.Context, changeID string) (*LocalAccessArrear, error) {
	rows, err := s.pool.Query(ctx, arrearColumns+"where change_id = $1", changeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	arrears, err := scanArrears(rows)
	if err != nil {
		return nil, err
	}
	if len(arrears) == 0 {
		return nil, ErrNotFound
	}
	return &arrears[0], nil
}

// targets splits the kept identities into the two lists the statements take.
// Both are non-nil, because any($1) over a null array matches nothing and would
// make an unconfirmed cut read as confirmed.
func (a LocalAccessArrear) targets() ([]string, []string) {
	subjects := make([]string, 0, len(a.Principals))
	principalIDs := make([]string, 0, len(a.Principals))
	for _, principal := range a.Principals {
		if principal.Subject != "" {
			subjects = append(subjects, principal.Subject)
		}
		if principal.PrincipalID != "" {
			principalIDs = append(principalIDs, principal.PrincipalID)
		}
	}
	return subjects, principalIDs
}

// ArrearBackoff is the pause before the next attempt at the local half:
// doubling from the base and capped, so a provider that is down is not asked
// every five seconds for ever and an access cut is not left for an hour.
func ArrearBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	backoff := ArrearBaseBackoff << uint(min(attempts-1, 16))
	if backoff > ArrearMaxBackoff || backoff <= 0 {
		return ArrearMaxBackoff
	}
	return backoff
}

// LocalAccessExecutor carries out the local half of an access cut that is still
// owed. It is a second executor and not a branch of the first on purpose: the
// change that owes this is terminal, so the executor of changes will never look
// at it again.
//
// It touches the panel only. It does not retry the preserve, it does not ask
// the directory anything, and it resolves nothing from a directory read - the
// identities it works on were written down before the directory was touched.
type LocalAccessExecutor struct {
	store    *Store
	sessions SessionRevoker
	provider ProviderLogout
	log      *slog.Logger
	interval time.Duration
	// The seams: the three effects, each replaceable on its own, and the holder
	// this replica claims as.
	localDeny func(ctx context.Context, subject, reason string, denied bool) (int64, error)
	revoke    func(ctx context.Context, principalID, reason string) (int64, error)
	// settle and hold are the two ways an attempt ends; nil means the store's
	// own statements, whose conditions are what actually decide.
	settle func(ctx context.Context, arrear LocalAccessArrear) error
	hold   func(ctx context.Context, arrear LocalAccessArrear, backoff time.Duration,
		cause string) error
	holder string
}

func NewLocalAccessExecutor(store *Store, sessions SessionRevoker, log *slog.Logger,
	interval time.Duration) *LocalAccessExecutor {
	if interval <= 0 {
		interval = arrearPoll
	}
	return &LocalAccessExecutor{store: store, sessions: sessions, log: log, interval: interval}
}

// WithProviderLogout makes the retry end the user's sessions at the identity
// provider as well, the way the change itself does.
func (e *LocalAccessExecutor) WithProviderLogout(provider ProviderLogout) *LocalAccessExecutor {
	e.provider = provider
	return e
}

// Run carries the outstanding obligations out until the context is closed.
func (e *LocalAccessExecutor) Run(ctx context.Context) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.tick(ctx)
		}
	}
}

func (e *LocalAccessExecutor) tick(ctx context.Context) {
	arrears, err := e.store.ClaimLocalAccess(ctx, e.instance(), arrearBatch)
	if err != nil {
		e.log.Error("the outstanding panel access cuts were not read", "err", err)
		return
	}
	for _, arrear := range arrears {
		e.pay(ctx, arrear)
	}
}

func (e *LocalAccessExecutor) instance() string {
	if e.holder != "" {
		return e.holder
	}
	return jobs.InstanceID()
}

// pay carries the local half out and settles the obligation only where the
// effects come back confirmed. Everything else puts the row back with the pause
// and the sentence of what happened, so the arrears go on growing where the
// panel can see them rather than the obligation disappearing.
func (e *LocalAccessExecutor) pay(ctx context.Context, arrear LocalAccessArrear) {
	reason := firstNonEmpty(arrear.Reason, "the account's access was cut")
	cause := ""
	for _, principal := range arrear.Principals {
		if principal.Subject != "" {
			if _, err := e.deny(ctx, principal.Subject, reason); err != nil &&
				!errors.Is(err, ErrNoPrincipal) {
				// An identity the panel no longer knows is an access that is not
				// there; anything else is an attempt that did not land.
				cause = "denying " + principal.Subject + ": " + err.Error()
			}
		}
		if principal.PrincipalID != "" {
			if _, err := e.revokeSessions(ctx, principal.PrincipalID, reason); err != nil {
				cause = "revoking the sessions of " + principal.Subject + ": " + err.Error()
			}
		}
	}
	// The provider's sessions are aimed at the subject the panel knows the
	// person by, which is what was written down - not at the directory account
	// name, which is a different string wherever the login qualifies it.
	if e.provider != nil {
		for _, principal := range arrear.Principals {
			if principal.Subject == "" {
				continue
			}
			if err := e.provider.LogoutSubject(ctx, principal.Subject); err != nil {
				// The provider cannot be read back here, so it never settles the
				// obligation on its own and never holds it open either: the
				// denial and the revocation are the effects this confirms.
				e.log.Warn("the sessions at the identity provider were not ended",
					"change_id", arrear.ChangeID, "subject", principal.Subject, "err", err)
			}
		}
	}

	err := e.settleArrear(ctx, arrear)
	if err == nil {
		metrics.LocalAccessArrears.Inc("settled")
		e.log.Info("the panel access of the account was cut off",
			"change_id", arrear.ChangeID, "uid", arrear.DirectoryUID,
			"attempts", arrear.Attempts, "arrears_seconds", arrear.ArrearsSeconds)
		return
	}
	if !errors.Is(err, ErrAccessNotConfirmed) {
		cause = "settling the obligation: " + err.Error()
	}
	if cause == "" {
		// Nothing failed and nothing confirmed: the row is somebody else's now,
		// or a session appeared between the revocation and the read-back. Either
		// way the obligation stands, which is the honest answer.
		cause = "the denial and the revocation were not read back as done"
	}
	metrics.LocalAccessArrears.Inc("outstanding")
	backoff := ArrearBackoff(arrear.Attempts)
	if err := e.holdArrear(ctx, arrear, backoff, cause); err != nil {
		e.log.Error("the outstanding panel access cut was not put back",
			"change_id", arrear.ChangeID, "err", err)
		return
	}
	e.log.Warn("the panel access of the account is still owed",
		"change_id", arrear.ChangeID, "uid", arrear.DirectoryUID,
		"attempts", arrear.Attempts, "arrears_seconds", arrear.ArrearsSeconds,
		"retry_in", backoff, "err", cause)
}

func (e *LocalAccessExecutor) settleArrear(ctx context.Context, arrear LocalAccessArrear) error {
	if e.settle != nil {
		return e.settle(ctx, arrear)
	}
	return e.store.SettleLocalAccess(ctx, arrear)
}

func (e *LocalAccessExecutor) holdArrear(ctx context.Context, arrear LocalAccessArrear,
	backoff time.Duration, cause string) error {
	if e.hold != nil {
		return e.hold(ctx, arrear, backoff, cause)
	}
	return e.store.HoldLocalAccess(ctx, arrear, backoff, cause)
}

func (e *LocalAccessExecutor) deny(ctx context.Context, subject, reason string) (int64, error) {
	if e.localDeny != nil {
		return e.localDeny(ctx, subject, reason, true)
	}
	return e.store.SetLocalDeny(ctx, subject, reason, true)
}

func (e *LocalAccessExecutor) revokeSessions(ctx context.Context, principalID,
	reason string) (int64, error) {
	if e.revoke != nil {
		return e.revoke(ctx, principalID, reason)
	}
	if e.sessions == nil {
		return 0, fmt.Errorf("the panel sessions cannot be ended, so it is not known whose are left")
	}
	return e.sessions.RevokeSessionsOf(ctx, principalID, reason)
}
