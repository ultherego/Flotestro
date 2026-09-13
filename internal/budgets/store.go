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
)

const (
	// defaultLease is the term of the tokens. Shorter than the longest
	// operation, because a lease is renewed for as long as the work lives. An
	// orchestrator failure has to free capacity after a moment, not after an
	// hour.
	defaultLease = 2 * time.Minute
	// waiterAge says how long a waiting entry that is no longer refreshed
	// counts towards the share. A campaign that stopped asking must not keep
	// shrinking everyone else's share forever.
	waiterAge = 30 * time.Second
	// sweepInterval sets how often expired rows are removed.
	sweepInterval = time.Minute
)

// Store is the authoritative state of the grants.
//
// It lives in the database, not in process memory, because there can be more
// than one orchestrator. A limit enforced in the memory of each of them is not
// a fleet limit but an instance limit - and with two instances it means twice
// what it promised.
type Store struct {
	pool  *pgxpool.Pool
	log   *slog.Logger
	lease time.Duration
}

func NewStore(pool *pgxpool.Pool, log *slog.Logger) *Store {
	return &Store{pool: pool, log: log, lease: defaultLease}
}

// Acquire grants every need or none of them.
//
// A partial grant would be worse than a refusal: a global token held while
// waiting for a site token lowers the fleet capacity for everyone else without
// bringing this work any closer to starting. That is why the whole set goes in
// one transaction, and the capacity rows are locked in a fixed order - without
// that two orchestrators could deadlock.
//
// An empty refusal means success. The owner is the identifier of the work (for
// us: a campaign target), the claimant is the unit of fairness, that is the
// whole campaign.
func (s *Store) Acquire(ctx context.Context, owner, claimant string, class Class,
	needs []Need) (Refusal, error) {
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
		if err := s.recordLease(ctx, tx, need, owner, claimant); err != nil {
			return Refusal{}, err
		}
	}
	// A grant ends the wait. The waiting entries say how long it took, and
	// that is measured here - a wait that never ends in a grant is visible
	// as the current waits, not as a duration.
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

// siteOf takes the site out of a budget key. A fleet-wide or backend
// budget has no site; it is reported under the class of the key instead of
// an empty label.
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
//
// An exact key wins over a pattern: an installation may describe one site
// differently from all the others.
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

	// The share is computed only once there is capacity. Free tokens are
	// divided between those who ask for them: a campaign covering a thousand
	// hosts gets a portion, not everything that happens to be free.
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
	owner, claimant string) error {
	const query = `
		insert into budget_leases (key, owner, claimant, weight, lease_until)
		values ($1, $2, $3, $4, now() + make_interval(secs => $5))
		on conflict (key, owner) do update
		   set claimant = excluded.claimant, weight = excluded.weight,
		       lease_until = excluded.lease_until`
	_, err := tx.Exec(ctx, query, need.Key, owner, claimant,
		need.Weight, s.lease.Seconds())
	return err
}

// Renew extends the leases of work that is still running.
//
// Without renewal long operations - a package transaction can take a quarter
// of an hour - would free capacity halfway through, and the system would start
// more than it can really carry.
func (s *Store) Renew(ctx context.Context, owners []string) error {
	if len(owners) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx,
		`update budget_leases set lease_until = now() + make_interval(secs => $2)
		  where owner = any($1)`, owners, s.lease.Seconds())
	return err
}

// Release returns the tokens of one piece of work.
func (s *Store) Release(ctx context.Context, owner string) error {
	_, err := s.pool.Exec(ctx, `delete from budget_leases where owner = $1`, owner)
	return err
}

// ReleaseClaimant returns everything one campaign holds.
//
// Cancelling does not go through closing every host one by one: the campaign
// is stopped with a single write, and its hosts get no further round in which
// they could give anything back. Without this the tokens stayed until the
// lease expired and the next campaign waited for capacity nobody was using.
func (s *Store) ReleaseClaimant(ctx context.Context, claimant string) error {
	if _, err := s.pool.Exec(ctx,
		`delete from budget_leases where claimant = $1`, claimant); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `delete from budget_waiters where claimant = $1`, claimant)
	return err
}

// Run sweeps expired leases and abandoned waiting entries.
//
// An expired lease does not count towards usage anyway, so the sweep changes
// no decision - it keeps the tables tidy and makes sure that a waiting entry
// left after a failure does not shrink the share forever.
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

// SetCapacity writes the capacity policy of one budget.
//
// The key may be exact ('site:warsaw:packages') or a pattern
// ('site:*:packages'). A pattern changes the default policy for the sites
// nobody described separately; an exact key takes one of them out from under
// that policy.
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
}

// States returns the picture of the budgets that hold anything or have anyone
// asking.
//
// A budget that stops nobody does not have to be on the screen. A budget that
// stops someone must be - otherwise a campaign stands with no reason given.
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
		       ) as asking)
		  from budget_limits l
		 order by l.key`
	rows, err := s.pool.Query(ctx, query, waiterAge.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	states := []State{}
	for rows.Next() {
		var state State
		if err := rows.Scan(&state.Key, &state.Capacity, &state.Used, &state.Claimants); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func keysOf(needs []Need) []string {
	result := make([]string, 0, len(needs))
	for _, need := range needs {
		result = append(result, need.Key)
	}
	return result
}
