package budgets

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/opspec"
)

const (
	// defaultLease is the term of the tokens. Shorter than the longest operation,
	// because a lease is renewed for as long as the work lives.
	defaultLease = 2 * time.Minute
	// waiterAge says how long a waiting entry that is no longer refreshed counts
	// towards the share.
	waiterAge = 30 * time.Second
	// sweepInterval sets how often expired rows are removed.
	sweepInterval = time.Minute
)

// Store is the authoritative state of the grants. It lives in the database,
// not in process memory, because there can be more than one orchestrator.
type Store struct {
	pool  *pgxpool.Pool
	log   *slog.Logger
	lease time.Duration
}

func NewStore(pool *pgxpool.Pool, log *slog.Logger) *Store {
	return &Store{pool: pool, log: log, lease: defaultLease}
}

// Acquire grants every need or none of them.
func (s *Store) Acquire(ctx context.Context, owner, claimant string, class Class,
	needs []Need) (Refusal, error) {
	return s.AcquireFenced(ctx, owner, claimant, class, needs, 0)
}

// AcquireFenced grants the needs like Acquire and writes the caller's fencing
// token on every lease it records.
func (s *Store) AcquireFenced(ctx context.Context, owner, claimant string, class Class,
	needs []Need, token int64) (Refusal, error) {
	if len(needs) == 0 {
		return Refusal{}, nil
	}
	ordered := make([]Need, len(needs))
	copy(ordered, needs)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Key < ordered[j].Key
	})

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Refusal{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	capacities, err := s.capacities(ctx, tx, ordered)
	if err != nil {
		return Refusal{}, err
	}

	granted := make([]Need, 0, len(ordered))
	for _, need := range ordered {
		capacity, described := capacities[need.Key]
		if !described {
			// An unconfigured budget is not a zero budget. It does not stop
			// the work, but it does not pretend to guard anything either.
			continue
		}
		refusal, err := s.check(ctx, tx, owner, claimant, class, need, capacity)
		if err != nil {
			return Refusal{}, err
		}
		if !refusal.Empty() {
			if err := s.recordWaiter(ctx, tx, need.Key, claimant, class); err != nil {
				return Refusal{}, err
			}
			// The waiting entry has to survive the refusal: without it nobody
			// computes the share or promotes the waiter by age.
			if err := tx.Commit(ctx); err != nil {
				return Refusal{}, err
			}
			return refusal, nil
		}
		granted = append(granted, need)
	}

	for _, need := range granted {
		if err := s.recordLease(ctx, tx, need, owner, claimant, token); err != nil {
			return Refusal{}, err
		}
	}
	// A grant ends the wait.
	rows, err := tx.Query(ctx,
		`delete from budget_waiters where claimant = $1 and key = any($2)
		 returning key, extract(epoch from now() - since)::float8`,
		claimant, keysOf(granted))
	if err != nil {
		return Refusal{}, err
	}
	var waits []waitedFor
	for rows.Next() {
		var w waitedFor
		if err := rows.Scan(&w.key, &w.seconds); err != nil {
			rows.Close()
			return Refusal{}, err
		}
		waits = append(waits, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Refusal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Refusal{}, err
	}
	for _, w := range waits {
		metrics.BudgetWait.Observe(w.seconds, string(class), siteOf(w.key))
	}
	return Refusal{}, nil
}

// waitedFor is one finished wait for a budget.
type waitedFor struct {
	key     string
	seconds float64
}

// siteOf takes the site out of a budget key.
func siteOf(key string) string {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) == 3 && parts[0] == "site" {
		return parts[1]
	}
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return "unknown"
}

// capacities reads and locks the capacity rows for the whole set of needs.
func (s *Store) capacities(ctx context.Context, tx pgx.Tx,
	needs []Need) (map[string]int, error) {
	wanted := make([]string, 0, 2*len(needs))
	for _, need := range needs {
		wanted = append(wanted, need.Key)
		if pattern := Pattern(need.Key); pattern != "" {
			wanted = append(wanted, pattern)
		}
	}
	// The locking order is fixed by the key, so two orchestrators take the
	// same rows in the same order.
	rows, err := tx.Query(ctx,
		`select key, capacity from budget_limits where key = any($1) order by key for update`,
		wanted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	source := map[string]int{}
	for rows.Next() {
		var key string
		var capacity int
		if err := rows.Scan(&key, &capacity); err != nil {
			return nil, err
		}
		source[key] = capacity
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := map[string]int{}
	for _, need := range needs {
		if capacity, ok := source[need.Key]; ok {
			result[need.Key] = capacity
			continue
		}
		if capacity, ok := source[Pattern(need.Key)]; ok {
			result[need.Key] = capacity
		}
	}
	return result, nil
}

// check decides one budget: capacity first, then the fair share.
func (s *Store) check(ctx context.Context, tx pgx.Tx, owner, claimant string,
	class Class, need Need, capacity int) (Refusal, error) {
	// Our own earlier hold on the same key must not count twice: retrying a
	// task is not new load.
	const usage = `
		select coalesce(sum(weight), 0),
		       coalesce(sum(weight) filter (where claimant = $2), 0)
		  from budget_leases
		 where key = $1 and lease_until > now() and owner <> $3`
	var used, mine int
	if err := tx.QueryRow(ctx, usage, need.Key, claimant, owner).
		Scan(&used, &mine); err != nil {
		return Refusal{}, err
	}

	waiting, err := s.waitingTime(ctx, tx, need.Key, claimant)
	if err != nil {
		return Refusal{}, err
	}
	if used+need.Weight > capacity {
		return Refusal{Key: need.Key, Reason: ReasonCapacity,
			Used: used, Capacity: capacity, Waiting: waiting}, nil
	}

	// The share is computed only once there is capacity.
	claimants, err := s.claimants(ctx, tx, need.Key)
	if err != nil {
		return Refusal{}, err
	}
	share := capacity / max(claimants, 1)
	if share < 1 {
		share = 1
	}
	if mine+need.Weight > share && waiting < class.PromotionAge() {
		return Refusal{Key: need.Key, Reason: ReasonFairShare, Used: used,
			Capacity: capacity, Share: share, Held: mine, Waiting: waiting}, nil
	}
	return Refusal{}, nil
}

// claimants counts the claimants that hold tokens or ask for them.
func (s *Store) claimants(ctx context.Context, tx pgx.Tx, key string) (int, error) {
	const query = `
		select count(*) from (
		    select claimant from budget_leases where key = $1 and lease_until > now()
		    union
		    select claimant from budget_waiters
		     where key = $1 and seen_at > now() - make_interval(secs => $2)
		) as asking`
	var count int
	err := tx.QueryRow(ctx, query, key, waiterAge.Seconds()).Scan(&count)
	return count, err
}

// waitingTime says how long the claimant has been waiting for this budget.
func (s *Store) waitingTime(ctx context.Context, tx pgx.Tx,
	key, claimant string) (time.Duration, error) {
	var seconds *float64
	const query = `
		select extract(epoch from (now() - since))::float8 from budget_waiters
		 where key = $1 and claimant = $2`
	if err := tx.QueryRow(ctx, query, key, claimant).Scan(&seconds); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	if seconds == nil {
		return 0, nil
	}
	return time.Duration(*seconds * float64(time.Second)), nil
}

func (s *Store) recordWaiter(ctx context.Context, tx pgx.Tx,
	key, claimant string, class Class) error {
	// since stays from the first request: it is the basis of the promotion.
	// seen_at says whether anyone still asks for this budget.
	const query = `
		insert into budget_waiters (key, claimant, class)
		values ($1, $2, $3)
		on conflict (key, claimant) do update set seen_at = now(), class = excluded.class`
	_, err := tx.Exec(ctx, query, key, claimant, string(class))
	return err
}

func (s *Store) recordLease(ctx context.Context, tx pgx.Tx, need Need,
	owner, claimant string, token int64) error {
	// A lease taken again by the same owner - a task retried, a target claimed
	// once more - carries the token of the newest claim: the older claim is the
	// one that must not be able to touch it.
	const query = `
		insert into budget_leases (key, owner, claimant, weight, lease_until, fencing_token)
		values ($1, $2, $3, $4, now() + make_interval(secs => $5), $6)
		on conflict (key, owner) do update
		   set claimant = excluded.claimant, weight = excluded.weight,
		       lease_until = excluded.lease_until, fencing_token = excluded.fencing_token`
	_, err := tx.Exec(ctx, query, need.Key, owner, claimant,
		need.Weight, s.lease.Seconds(), token)
	return err
}

// Renew extends the leases of work that is still running.
func (s *Store) Renew(ctx context.Context, owners []string) error {
	if len(owners) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx,
		`update budget_leases set lease_until = now() + make_interval(secs => $2)
		  where owner = any($1)`, owners, s.lease.Seconds())
	return err
}

// Fenced names one lease by its owner and the fencing token the caller
// holds for it.
type Fenced struct {
	Owner string
	Token int64
}

// RenewFenced extends the leases the caller still holds under its tokens.
func (s *Store) RenewFenced(ctx context.Context, leases []Fenced) error {
	if len(leases) == 0 {
		return nil
	}
	owners := make([]string, 0, len(leases))
	tokens := make([]int64, 0, len(leases))
	for _, lease := range leases {
		owners = append(owners, lease.Owner)
		tokens = append(tokens, lease.Token)
	}
	_, err := s.pool.Exec(ctx, `
		update budget_leases l
		   set lease_until = now() + make_interval(secs => $3)
		  from unnest($1::text[], $2::bigint[]) as held (owner, token)
		 where l.owner = held.owner and l.fencing_token = held.token`,
		owners, tokens, s.lease.Seconds())
	return err
}

// Release returns the tokens of one piece of work.
func (s *Store) Release(ctx context.Context, owner string) error {
	_, err := s.pool.Exec(ctx, `delete from budget_leases where owner = $1`, owner)
	return err
}

// ReleaseFenced returns the tokens of one piece of work only while the lease
// still carries the caller's token.
func (s *Store) ReleaseFenced(ctx context.Context, owner string, token int64) error {
	_, err := s.pool.Exec(ctx,
		`delete from budget_leases where owner = $1 and fencing_token = $2`, owner, token)
	return err
}

// ReleaseIn returns the tokens of one piece of work inside the caller's
// transaction.
func ReleaseIn(ctx context.Context, tx pgx.Tx, owner string) error {
	_, err := tx.Exec(ctx, `delete from budget_leases where owner = $1`, owner)
	return err
}

// ReleaseClaimant returns everything one campaign holds.
func (s *Store) ReleaseClaimant(ctx context.Context, claimant string) error {
	if _, err := s.pool.Exec(ctx,
		`delete from budget_leases where claimant = $1`, claimant); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `delete from budget_waiters where claimant = $1`, claimant)
	return err
}

// Run sweeps expired leases and abandoned waiting entries.
func (s *Store) Run(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.sweep(ctx); err != nil {
				s.log.Error("budget sweep failed", "err", err)
			}
		}
	}
}

func (s *Store) sweep(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx,
		`delete from budget_leases where lease_until < now() - make_interval(secs => $1)`,
		(10 * time.Minute).Seconds()); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`delete from budget_waiters where seen_at < now() - make_interval(secs => $1)`,
		(10 * time.Minute).Seconds())
	return err
}

// SetCapacity writes the capacity policy of one budget. The key may be exact
// ('site:warsaw:packages') or a pattern ('site:*:packages').
func (s *Store) SetCapacity(ctx context.Context, key string, capacity int,
	note string) error {
	const query = `
		insert into budget_limits (key, capacity, note)
		values ($1, $2, $3)
		on conflict (key) do update
		   set capacity = excluded.capacity, note = excluded.note, updated_at = now()`
	_, err := s.pool.Exec(ctx, query, key, capacity, note)
	return err
}

// State describes one budget for the operator's screen.
type State struct {
	Key       string `json:"key"`
	Capacity  int    `json:"capacity"`
	Used      int    `json:"used"`
	Claimants int    `json:"claimants"`
	// WaitingJobs counts the single-host jobs standing in the queue for this
	// budget.
	WaitingJobs int `json:"waiting_jobs"`
	// WaitingTargets counts the hosts of running campaigns that stand in
	// awaiting_budget for this budget.
	WaitingTargets int `json:"waiting_targets"`
	// Holders lists the live leases, newest first, at most holdersShown of them.
	Holders []Holder `json:"holders"`
	// ByClass is the weight of the tokens in use per class of work.
	ByClass map[string]int `json:"by_class"`
}

// Holder is one live lease of a budget.
type Holder struct {
	// Owner is the piece of work that holds the tokens: job:<id> for a job,
	// a target id for a campaign host, fanout:<id> for a fan-out read.
	Owner string `json:"owner"`
	// Claimant is the unit of fairness the lease counts under: the
	// campaign, or the identity that ordered the job.
	Claimant string `json:"claimant"`
	Class    string `json:"class"`
	Tokens   int    `json:"tokens"`
	// Since is when the lease was first taken; a renewal keeps it.
	Since time.Time `json:"since"`
}

// holdersShown bounds the holders listed per budget.
const holdersShown = 50

// States returns the picture of the budgets that hold anything or have anyone
// asking.
func (s *Store) States(ctx context.Context) ([]State, error) {
	const query = `
		select l.key, l.capacity,
		       coalesce((select sum(weight) from budget_leases d
		                  where d.key = l.key and d.lease_until > now()), 0),
		       (select count(*) from (
		            select claimant from budget_leases d
		             where d.key = l.key and d.lease_until > now()
		            union
		            select claimant from budget_waiters w
		             where w.key = l.key and w.seen_at > now() - make_interval(secs => $1)
		       ) as asking),
		       (select count(*) from jobs j
		         where j.state = 'queued' and j.wait_reason like $2::text || '%'
		           and (substr(j.wait_reason, length($2::text) + 1) = l.key
		                or (split_part(l.key, ':', 2) = '*'
		                    and split_part(substr(j.wait_reason, length($2::text) + 1), ':', 1) = split_part(l.key, ':', 1)
		                    and split_part(substr(j.wait_reason, length($2::text) + 1), ':', 3) = split_part(l.key, ':', 3)
		                    and not exists (select 1 from budget_limits e
		                                     where e.key = substr(j.wait_reason, length($2::text) + 1)))))
		  from budget_limits l
		 order by l.key`
	// A job waits on the exact key of its site; the row on the screen may be the
	// pattern that gave the site its capacity.
	rows, err := s.pool.Query(ctx, query, waiterAge.Seconds(), WaitReasonPrefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	states := []State{}
	for rows.Next() {
		state := State{Holders: []Holder{}, ByClass: map[string]int{}}
		if err := rows.Scan(&state.Key, &state.Capacity, &state.Used, &state.Claimants,
			&state.WaitingJobs); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(states) == 0 {
		return states, nil
	}

	// The leases and the waiting targets name the exact key of their site; they
	// land on the row of that key, or on the pattern's row when no exact row took
	// the site out from under it - the same attribution the waiting jobs get
	rowOf := map[string]int{}
	for i, state := range states {
		rowOf[state.Key] = i
	}
	resolve := func(key string) (int, bool) {
		if i, ok := rowOf[key]; ok {
			return i, true
		}
		i, ok := rowOf[Pattern(key)]
		return i, ok
	}
	if err := s.collectHolders(ctx, states, resolve); err != nil {
		return nil, err
	}
	if err := s.countWaitingTargets(ctx, states, resolve); err != nil {
		return nil, err
	}
	return states, nil
}

// collectHolders reads the live leases into the states: the newest few as
// holders, all of them into the per-class sum.
func (s *Store) collectHolders(ctx context.Context, states []State,
	resolve func(string) (int, bool)) error {
	// The class of a job's lease is the job's; the owner names the job, and its
	// row says with what class it asked.
	const query = `
		select l.key, l.owner, l.claimant, l.weight, l.acquired_at,
		       j.action_type, j.created_by, j.budget_class
		  from budget_leases l
		  left join jobs j on j.id = case when l.owner ~ '^job:[0-9a-f-]{36}$'
		                                  then substr(l.owner, 5)::uuid end
		 where l.lease_until > now()
		 order by l.acquired_at desc, l.key, l.owner`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var holder Holder
		var action, createdBy, stated *string
		if err := rows.Scan(&key, &holder.Owner, &holder.Claimant, &holder.Tokens,
			&holder.Since, &action, &createdBy, &stated); err != nil {
			return err
		}
		var job *JobFacts
		if action != nil && createdBy != nil && stated != nil {
			job = &JobFacts{Action: opspec.ActionType(*action), CreatedBy: *createdBy,
				Stated: Class(*stated)}
		}
		holder.Class = LeaseClass(holder.Owner, holder.Claimant, job)
		i, ok := resolve(key)
		if !ok {
			// A lease under a key nobody configured any more: it holds
			// nothing that binds, and there is no row to show it on.
			continue
		}
		states[i].ByClass[holder.Class] += holder.Tokens
		if len(states[i].Holders) < holdersShown {
			states[i].Holders = append(states[i].Holders, holder)
		}
	}
	return rows.Err()
}

// countWaitingTargets adds up the campaign hosts waiting on each budget.
func (s *Store) countWaitingTargets(ctx context.Context, states []State,
	resolve func(string) (int, bool)) error {
	const query = `
		select t.message, count(*)
		  from campaign_targets t
		  join campaigns c on c.id = t.campaign_id
		 where t.state = 'awaiting_budget' and c.state in ('canary', 'running')
		 group by t.message`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var message *string
		var count int
		if err := rows.Scan(&message, &count); err != nil {
			return err
		}
		if message == nil {
			continue
		}
		key := DescribedKey(*message)
		if key == "" {
			continue
		}
		if i, ok := resolve(key); ok {
			states[i].WaitingTargets += count
		}
	}
	return rows.Err()
}

func keysOf(needs []Need) []string {
	result := make([]string, 0, len(needs))
	for _, need := range needs {
		result = append(result, need.Key)
	}
	return result
}

// FailureDomains reads the failure domain of every given host.
func (s *Store) FailureDomains(ctx context.Context, hostIDs []string) (map[string]string, error) {
	if len(hostIDs) == 0 {
		return map[string]string{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`select id::text, failure_domain from hosts
		  where id = any($1::uuid[]) and failure_domain is not null`, hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	domains := map[string]string{}
	for rows.Next() {
		var id, domain string
		if err := rows.Scan(&id, &domain); err != nil {
			return nil, err
		}
		if domain != "" {
			domains[id] = domain
		}
	}
	return domains, rows.Err()
}

// SessionGateway names the gateway the host's open session is on; empty means
// the host has no open session, and so no gateway to load.
func (s *Store) SessionGateway(ctx context.Context, hostID string) (string, error) {
	var gateway string
	err := s.pool.QueryRow(ctx, `
		select gateway_id from agent_sessions
		 where host_id = $1::uuid and ended_at is null
		 order by epoch desc limit 1`, hostID).Scan(&gateway)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return gateway, nil
}
