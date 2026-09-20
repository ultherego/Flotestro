//go:build integration

package integration

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/monitoring"
)

// The lease is taken for long enough that the panel's own evaluator cannot
// slip between the steps of the test and judge the fleet under a third token.
const fencingLeaseTerm = 5 * time.Minute

// TestAStaleEvaluatorCannotWriteOverTheNewLeader: the leader that lost the
// lease finds the host reporting again and would write over its successor.
func TestAStaleEvaluatorCannotWriteOverTheNewLeader(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.enrollSyntheticHost(t)
	rule := h.quietHostRule(t, host.ID, "integration: quiet for more than five minutes")
	h.freeTheEvaluatorLease(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	options := monitoring.Options{EvaluatorLease: fencingLeaseTerm}
	leader := monitoring.NewStore(pool, logger, options)
	successor := monitoring.NewStore(pool, logger, options)

	// The host has been quiet for half an hour, so the rule holds and the first
	// leader opens the episode under its own token.
	h.setLastSample(t, host.ID, 30*time.Minute)
	first := takeEvaluatorLease(ctx, t, leader)
	if err := leader.EvaluateUnder(ctx, time.Now(), first); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	state, token := openEpisode(ctx, t, pool, rule.ID, host.ID)
	if state != "firing" {
		t.Fatalf("the rule did not fire on the quiet host; the episode is %q", state)
	}
	if token == nil || *token != first.Token {
		t.Fatalf("the episode carries token %v, the lease that wrote it %d", token, first.Token)
	}

	// The term runs out where the first leader stands: it is still in its pass,
	// still holds its own copy of the lease, and the row is nobody's but its own.
	h.expireTheEvaluatorLease(t)
	second := takeEvaluatorLease(ctx, t, successor)
	if second.Token <= first.Token {
		t.Fatalf("the successor took the lease on token %d, the predecessor held %d",
			second.Token, first.Token)
	}

	// The successor judges the same host, which has been quiet longer still, and
	// the episode becomes its own.
	h.setLastSample(t, host.ID, 90*time.Minute)
	if err := successor.EvaluateUnder(ctx, time.Now(), second); err != nil {
		t.Fatalf("the successor's pass: %v", err)
	}
	state, token = openEpisode(ctx, t, pool, rule.ID, host.ID)
	if state != "firing" || token == nil || *token != second.Token {
		t.Fatalf("after the successor's pass the episode is %q on token %v", state, token)
	}

	// The host reports again, and the stale leader carries on where it was: it
	// would resolve an episode that is not its own any more.
	h.setLastSample(t, host.ID, 0)
	err := leader.EvaluateUnder(ctx, time.Now(), first)
	if !errors.Is(err, monitoring.ErrFenceStale) {
		t.Fatalf("the stale leader's pass ended with %v; the fence refused nothing", err)
	}
	if !errors.Is(err, monitoring.ErrLeaseLost) {
		t.Fatalf("the refusal is not a lost lease, so the pass would not stop: %v", err)
	}
	state, token = openEpisode(ctx, t, pool, rule.ID, host.ID)
	if state != "firing" {
		t.Fatalf("the stale leader moved the episode to %q", state)
	}
	if token == nil || *token != second.Token {
		t.Fatalf("the episode carries token %v after the stale write; the successor wrote %d",
			token, second.Token)
	}

	// The leader that holds the lease resolves it, and the same pass is the one
	// that may.
	if err := successor.EvaluateUnder(ctx, time.Now(), second); err != nil {
		t.Fatalf("the successor's closing pass: %v", err)
	}
	if state, _ := openEpisode(ctx, t, pool, rule.ID, host.ID); state != "" {
		t.Fatalf("the episode is still open as %q after the leader resolved it", state)
	}
	if err := successor.ReleaseEvaluatorLease(ctx, second); err != nil {
		t.Fatalf("giving the lease back: %v", err)
	}
}

// TestAnEpisodeFromThePreviousReleaseStaysWritable: during a rolling upgrade a
// panel that knows nothing of the fence writes rows with no token on them.
func TestAnEpisodeFromThePreviousReleaseStaysWritable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.enrollSyntheticHost(t)
	rule := h.quietHostRule(t, host.ID, "integration: quiet, written by the previous release")
	h.freeTheEvaluatorLease(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := monitoring.NewStore(pool, logger, monitoring.Options{EvaluatorLease: fencingLeaseTerm})

	h.setLastSample(t, host.ID, 30*time.Minute)
	lease := takeEvaluatorLease(ctx, t, store)
	if err := store.EvaluateUnder(ctx, time.Now(), lease); err != nil {
		t.Fatalf("the pass that opened the episode: %v", err)
	}
	if state, _ := openEpisode(ctx, t, pool, rule.ID, host.ID); state != "firing" {
		t.Fatalf("the rule did not fire on the quiet host; the episode is %q", state)
	}

	// As a panel of the previous release would have left it: an open episode
	// with nothing on it saying who wrote it.
	if _, err := pool.Exec(ctx, `
		update alerts set fencing_token = null
		 where rule_id = $1::uuid and host_id = $2::uuid and state <> 'resolved'`,
		rule.ID, host.ID); err != nil {
		t.Fatalf("unstamping the episode: %v", err)
	}

	h.setLastSample(t, host.ID, 90*time.Minute)
	if err := store.EvaluateUnder(ctx, time.Now(), lease); err != nil {
		t.Fatalf("the new panel refused to touch an episode of the previous release: %v", err)
	}
	state, token := openEpisode(ctx, t, pool, rule.ID, host.ID)
	if state != "firing" {
		t.Fatalf("the episode is %q after the refreshing pass", state)
	}
	if token == nil || *token != lease.Token {
		t.Fatalf("the episode carries token %v; the pass that wrote it held %d", token, lease.Token)
	}
	if err := store.ReleaseEvaluatorLease(ctx, lease); err != nil {
		t.Fatalf("giving the lease back: %v", err)
	}
}

// quietHostRule creates a rule that holds while the host says nothing, scoped
// to that host alone, and takes the rule away again when the test ends.
func (h *harness) quietHostRule(t *testing.T, hostID, name string) alertRuleView {
	t.Helper()
	var rule alertRuleView
	h.do(http.MethodPost, "/api/v1/monitoring/rules", map[string]any{
		"name": name, "metric": "host_offline", "operator": "gt",
		"threshold": 5, "for_minutes": 0, "severity": "info",
		"selector": map[string]any{"host_ids": []string{hostID}},
	}, &rule, http.StatusCreated)
	if rule.ID == "" {
		t.Fatalf("the rule came back as %+v", rule)
	}
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/monitoring/rules/"+rule.ID, nil, nil, 0)
	})
	return rule
}

// setLastSample says how long ago the host last reported; the rule on a quiet
// host reads nothing else.
func (h *harness) setLastSample(t *testing.T, hostID string, ago time.Duration) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.database(ctx).Exec(ctx, `
		update hosts set last_metrics_at = now() - make_interval(secs => $2::double precision)
		 where id = $1::uuid`, hostID, ago.Seconds()); err != nil {
		t.Fatalf("setting the last sample of the host: %v", err)
	}
}

// freeTheEvaluatorLease takes the lease out of whoever's hands it is in before
// the test starts, and clears it the same way once the test ends.
func (h *harness) freeTheEvaluatorLease(t *testing.T) {
	t.Helper()
	release := func() {
		ctx := context.Background()
		if _, err := h.database(ctx).Exec(ctx, `
			update monitoring_leases set holder = null, lease_until = null, updated_at = now()
			 where name = 'alert_evaluator'`); err != nil {
			t.Logf("the lease of the alert evaluator was not given back: %v", err)
		}
	}
	release()
	t.Cleanup(release)
}

// expireTheEvaluatorLease ends the term where the holder stands, without
// telling it: the holder still has its own copy and still believes in it.
func (h *harness) expireTheEvaluatorLease(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.database(ctx).Exec(ctx, `
		update monitoring_leases set lease_until = now() - interval '1 second'
		 where name = 'alert_evaluator'`); err != nil {
		t.Fatalf("ending the term of the lease: %v", err)
	}
}

// takeEvaluatorLease waits for the lease, which the panel's own evaluator takes
// for a term of its own between the tests.
func takeEvaluatorLease(ctx context.Context, t *testing.T, store *monitoring.Store) monitoring.Lease {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		lease, held, err := store.TakeEvaluatorLease(ctx)
		if err != nil {
			t.Fatalf("taking the lease of the alert evaluator: %v", err)
		}
		if held {
			return lease
		}
		if time.Now().After(deadline) {
			t.Fatal("the lease of the alert evaluator did not come free")
		}
		time.Sleep(2 * time.Second)
	}
}

// openEpisode reads the open episode of a rule on a host: its state and the
// token of the lease that last wrote it, or an empty state when none is open.
func openEpisode(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	ruleID, hostID string) (string, *int64) {
	t.Helper()
	var state string
	var token *int64
	err := pool.QueryRow(ctx, `
		select state, fencing_token from alerts
		 where rule_id = $1::uuid and host_id = $2::uuid and state <> 'resolved'`,
		ruleID, hostID).Scan(&state, &token)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		t.Fatalf("reading the episode of rule %s on host %s: %v", ruleID, hostID, err)
	}
	return state, token
}
