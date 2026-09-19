//go:build integration

package integration

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/monitoring"
)

// noDataLeaseTerm keeps the panel's own evaluator out of the pass while the
// test judges the fleet itself.
const noDataLeaseTerm = 5 * time.Minute

// TestAHostThatStopsReportingRaisesANoDataEpisode: the chapter's case. Two
// rules watch the same metric on the same host; the host stops reporting. The
func TestAHostThatStopsReportingRaisesANoDataEpisode(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.enrollSyntheticHost(t)
	h.freeTheEvaluatorLease(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := monitoring.NewStore(pool, logger, monitoring.Options{EvaluatorLease: noDataLeaseTerm})

	// The lease is taken before the rules exist: while the test holds it the
	// panel's own evaluator judges nothing, so the only pass over these two
	// rules is the one the test makes.
	lease := takeEvaluatorLease(ctx, t, store)
	t.Cleanup(func() {
		if err := store.ReleaseEvaluatorLease(context.Background(), lease); err != nil {
			t.Logf("giving the lease back: %v", err)
		}
	})

	// A condition that always holds while there are readings, so the only
	// thing the two rules disagree about is what a gap means.
	told := h.cadenceRule(t, store, host.ID, "integration: cpu, told about gaps", monitoring.NoDataAlert)
	quiet := h.cadenceRule(t, store, host.ID, "integration: cpu, gaps ignored", monitoring.NoDataIgnore)

	// The host reported twenty minutes ago and has said nothing since: well
	// past the two minutes both rules allow.
	h.writeSample(t, host.ID, 20*time.Minute)
	if err := store.EvaluateUnder(ctx, time.Now(), lease); err != nil {
		t.Fatalf("the pass over the quiet host: %v", err)
	}

	state, token := openEpisode(ctx, t, pool, told.ID, host.ID)
	if state != "no_data" {
		t.Fatalf("the rule that asked to be told about gaps stands at %q, not no_data", state)
	}
	if token == nil || *token != lease.Token {
		t.Fatalf("the no-data episode carries token %v; the pass that wrote it held %d",
			token, lease.Token)
	}
	if state, _ := openEpisode(ctx, t, pool, quiet.ID, host.ID); state != "" {
		t.Fatalf("the rule that ignores gaps opened an episode in %q", state)
	}

	// The episode is on the on-call board beside the firing ones, and it is
	// in the trail the notification queue reads.
	var fleet fleetMonitoringView
	h.get("/api/v1/monitoring", &fleet)
	onBoard := false
	for _, alert := range fleet.Firing {
		if alert.HostID == host.ID && alert.RuleID == told.ID {
			onBoard = true
			if alert.State != "no_data" {
				t.Errorf("the board shows the gap as %q", alert.State)
			}
			if alert.Detail == "" {
				t.Error("the gap on the board says nothing about how long the readings are missing")
			}
		}
		if alert.RuleID == quiet.ID {
			t.Error("the rule that ignores gaps put an episode on the board")
		}
	}
	if !onBoard {
		t.Errorf("the no-data episode is not on the on-call board: %+v", fleet.Firing)
	}
	if announced := alertEvents(ctx, t, pool, told.ID, "alert.no_data"); announced != 1 {
		t.Errorf("the gap reached the notification queue %d times", announced)
	}
	if announced := alertEvents(ctx, t, pool, quiet.ID, "alert.no_data"); announced != 0 {
		t.Errorf("a rule that ignores gaps announced %d of them", announced)
	}

	// The host reports again: the episode leaves no_data for the state the
	// readings say, and the rule that ignored the gap opens its own.
	h.writeSample(t, host.ID, 0)
	if err := store.EvaluateUnder(ctx, time.Now(), lease); err != nil {
		t.Fatalf("the pass over the host that came back: %v", err)
	}
	if state, _ := openEpisode(ctx, t, pool, told.ID, host.ID); state != "firing" {
		t.Fatalf("the episode stands at %q after the readings came back", state)
	}
	if state, _ := openEpisode(ctx, t, pool, quiet.ID, host.ID); state != "firing" {
		t.Fatalf("the rule that ignores gaps stands at %q on a host that reports", state)
	}
}

// cadenceRule writes a rule that holds whenever there is a reading at all, on
// one host, with the no-data policy under test, and removes it with the test.
func (h *harness) cadenceRule(t *testing.T, store *monitoring.Store,
	hostID, name, policy string) monitoring.Rule {
	t.Helper()
	ctx := context.Background()
	rule, err := store.CreateRule(ctx, monitoring.Rule{
		Name:                   name,
		Metric:                 monitoring.MetricCPUPercent,
		Operator:               "gt",
		Threshold:              -1,
		ForMinutes:             0,
		Severity:               "info",
		CreatedBy:              "integration",
		Selector:               monitoring.Selector{HostIDs: []string{hostID}},
		Enabled:                true,
		ExpectedCadenceSeconds: 60,
		MaxGapSeconds:          120,
		NoDataPolicy:           policy,
	})
	if err != nil {
		t.Fatalf("writing the rule %q: %v", name, err)
	}
	if !rule.Enabled || rule.NoDataPolicy != policy || rule.MaxGapSeconds != 120 {
		t.Fatalf("the rule came back as %+v", rule)
	}
	t.Cleanup(func() {
		if err := store.DeleteRule(context.Background(), rule.ID); err != nil {
			t.Logf("removing the rule %q: %v", name, err)
		}
	})
	return *rule
}

// writeSample puts one reading on the host, dated the given time ago, and sets
// the moment the host row carries with it.
func (h *harness) writeSample(t *testing.T, hostID string, ago time.Duration) {
	t.Helper()
	ctx := context.Background()
	pool := h.database(ctx)
	if _, err := pool.Exec(ctx, `
		insert into host_metrics (host_id, at, cpu_percent, load1, load5, load15,
		    memory_total, memory_used, memory_available, swap_total, swap_used,
		    uptime_seconds)
		values ($1::uuid, now() - make_interval(secs => $2::double precision),
		        7, 0.5, 0.5, 0.5, 1000, 400, 600, 0, 0, 3600)
		on conflict (host_id, at) do nothing`, hostID, ago.Seconds()); err != nil {
		t.Fatalf("writing a reading for the host: %v", err)
	}
	h.setLastSample(t, hostID, ago)
}

// alertEvents counts the events of one type the trail holds for a rule.
func alertEvents(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	ruleID, eventType string) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `
		select count(*) from outbox_events
		 where aggregate_type = 'alert' and event_type = $2
		   and payload->>'rule_id' = $1`, ruleID, eventType).Scan(&count); err != nil {
		t.Fatalf("reading the trail of rule %s: %v", ruleID, err)
	}
	return count
}
