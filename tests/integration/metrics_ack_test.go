//go:build integration

package integration

// The identity of a resource sample and what the panel does with a second
// delivery of it (security remediation, chapters 12 and 16).

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/monitoring"
)

// awaitMetricsAck waits for the panel's answer to a sample.
func (s *syntheticSession) awaitMetricsAck(limit time.Duration) *agentv1.MetricsAck {
	deadline := time.After(limit)
	for {
		select {
		case message, ok := <-s.server:
			if !ok {
				return nil
			}
			if ack := message.GetMetricsAck(); ack != nil {
				return ack
			}
		case <-deadline:
			return nil
		}
	}
}

// syntheticSample is one reading of a host that does not exist: enough
// numbers for the panel to store it and to roll it up.
func syntheticSample(bootID string, sequence uint64, at time.Time) *agentv1.MetricsSample {
	return &agentv1.MetricsSample{
		BootId:          bootID,
		Sequence:        sequence,
		SampledAtUnix:   at.Unix(),
		CpuPercent:      float64(10 + sequence),
		Load1:           0.5,
		Load5:           0.4,
		Load15:          0.3,
		MemoryTotal:     8 << 30,
		MemoryUsed:      2 << 30,
		MemoryAvailable: 6 << 30,
		UptimeSeconds:   4242,
	}
}

func TestASampleDeliveredTwiceIsStoredOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host, identity := h.enrollSyntheticHostWithIdentity(t)
	gateway := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)

	bootID := uuid.NewString()
	session, err := openSyntheticSession(ctx, gateway, identity, bootID)
	if err != nil {
		t.Fatalf("the synthetic host did not open a session: %v", err)
	}
	defer session.close()

	// A moment inside a quarter-hour that has already finished, so the rollup may
	// compute it: forty minutes back is at least one whole quarter behind the one
	// running now.
	taken := time.Now().UTC().Add(-40 * time.Minute).Truncate(time.Second)
	sample := syntheticSample(bootID, 1, taken)

	if err := session.stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_MetricsSample{MetricsSample: sample},
	}); err != nil {
		t.Fatalf("the sample was not sent: %v", err)
	}
	ack := session.awaitMetricsAck(30 * time.Second)
	if ack == nil {
		t.Fatal("the panel did not answer the sample; the host would carry it for ever")
	}
	if ack.GetStatus() != agentv1.MetricsAck_STATUS_PERSISTED {
		t.Fatalf("the first delivery was answered %s (%s)", ack.GetStatus(), ack.GetReasonCode())
	}
	if ack.GetBootId() != bootID || ack.GetSequence() != 1 {
		t.Fatalf("the answer names %s/%d instead of the sample it was for",
			ack.GetBootId(), ack.GetSequence())
	}

	// The same sample again, exactly as the agent would resend it from its
	// spool after a broken stream.
	if err := session.stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_MetricsSample{MetricsSample: syntheticSample(bootID, 1, taken)},
	}); err != nil {
		t.Fatalf("the resend was not sent: %v", err)
	}
	ack = session.awaitMetricsAck(30 * time.Second)
	if ack == nil || ack.GetStatus() != agentv1.MetricsAck_STATUS_DUPLICATE {
		t.Fatalf("the resend was answered %v; a sample the panel holds has to be answered "+
			"all the same, so the host may drop its copy", ack)
	}

	// A sequence the panel already holds, carrying another moment: the host's
	// clock moved between the deliveries, which is exactly what identity by the
	// clock could not survive.
	moved := taken.Add(7 * time.Minute)
	if err := session.stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_MetricsSample{MetricsSample: syntheticSample(bootID, 1, moved)},
	}); err != nil {
		t.Fatalf("the third delivery was not sent: %v", err)
	}
	ack = session.awaitMetricsAck(30 * time.Second)
	if ack == nil || ack.GetStatus() != agentv1.MetricsAck_STATUS_DUPLICATE {
		t.Fatalf("a sample under a sequence the panel holds was answered %v", ack)
	}

	var readings, identities int
	if err := pool.QueryRow(ctx,
		`select count(*) from host_metrics where host_id = $1::uuid`, host.ID).Scan(&readings); err != nil {
		t.Fatal(err)
	}
	if readings != 1 {
		t.Fatalf("three deliveries of one sample left %d readings on the host", readings)
	}
	if err := pool.QueryRow(ctx,
		`select count(*) from metric_samples where host_id = $1::uuid`, host.ID).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if identities != 1 {
		t.Fatalf("the panel holds %d identities for one sample", identities)
	}
	var stored time.Time
	if err := pool.QueryRow(ctx,
		`select at from host_metrics where host_id = $1::uuid`, host.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !stored.UTC().Equal(taken) {
		t.Fatalf("the stored reading sits at %s instead of the moment of the first delivery %s",
			stored.UTC(), taken)
	}
}

func TestALateSampleIsRolledUpIntoItsOwnQuarter(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host, identity := h.enrollSyntheticHostWithIdentity(t)
	gateway := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)

	bootID := uuid.NewString()
	session, err := openSyntheticSession(ctx, gateway, identity, bootID)
	if err != nil {
		t.Fatalf("the synthetic host did not open a session: %v", err)
	}
	defer session.close()

	// The store the test drives the rollup with is the panel's own, on the
	// panel's own database: the rollup runs every quarter of an hour in the
	// control plane, which is longer than this test may take, so the same code is
	store := monitoring.NewStore(pool, slog.New(slog.NewTextHandler(io.Discard, nil)), monitoring.Options{})

	taken := time.Now().UTC().Add(-40 * time.Minute).Truncate(time.Second)
	sendSample := func(sequence uint64, at time.Time) {
		t.Helper()
		if err := session.stream.Send(&agentv1.AgentMessage{
			Payload: &agentv1.AgentMessage_MetricsSample{MetricsSample: syntheticSample(bootID, sequence, at)},
		}); err != nil {
			t.Fatalf("the sample %d was not sent: %v", sequence, err)
		}
		ack := session.awaitMetricsAck(30 * time.Second)
		if ack == nil || ack.GetStatus() != agentv1.MetricsAck_STATUS_PERSISTED {
			t.Fatalf("the sample %d was answered %v", sequence, ack)
		}
	}

	sendSample(1, taken)
	if err := store.Rollup(ctx); err != nil {
		t.Fatalf("the rollup did not run: %v", err)
	}

	bucket := quarterOf(taken)
	var counted int
	if err := pool.QueryRow(ctx,
		`select samples from host_metrics_15m where host_id = $1::uuid and at = $2`,
		host.ID, bucket).Scan(&counted); err != nil {
		t.Fatalf("the quarter of the first reading was not rolled up: %v", err)
	}
	if counted != 1 {
		t.Fatalf("the quarter was rolled up over %d readings, expected one", counted)
	}

	// The mark is the host's own. A global one would already have moved
	// past this quarter for every other host of the fleet.
	var mark time.Time
	if err := pool.QueryRow(ctx,
		`select complete_through from metric_rollup_watermarks where host_id = $1::uuid`,
		host.ID).Scan(&mark); err != nil {
		t.Fatalf("the host has no rollup mark of its own: %v", err)
	}
	if !mark.After(bucket) {
		t.Fatalf("the mark of the host stands at %s, not past the quarter %s it rolled up",
			mark.UTC(), bucket)
	}

	// A second reading of the same quarter, arriving after that quarter was
	// declared finished: a relay draining its spool, or a host whose link came
	// back.
	sendSample(2, taken.Add(time.Minute))

	var owed, already int
	if err := pool.QueryRow(ctx,
		`select count(*) from metric_rollup_dirty where host_id = $1::uuid and bucket_at = $2`,
		host.ID, bucket).Scan(&owed); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`select samples from host_metrics_15m where host_id = $1::uuid and at = $2`,
		host.ID, bucket).Scan(&already); err != nil {
		t.Fatal(err)
	}
	// The panel's own quarter-hourly pass may have drained the mark already,
	// recomputing the quarter on its way: the recomputation is what is proved
	// here, and the queue is how it happens.
	if owed == 0 && already < 2 {
		t.Fatal("the late reading neither marked its quarter for recomputation nor was folded into one")
	}
	if err := store.Rollup(ctx); err != nil {
		t.Fatalf("the second rollup did not run: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`select samples from host_metrics_15m where host_id = $1::uuid and at = $2`,
		host.ID, bucket).Scan(&counted); err != nil {
		t.Fatal(err)
	}
	if counted != 2 {
		t.Fatalf("the quarter still counts %d readings; the late one was not folded in", counted)
	}
	if err := pool.QueryRow(ctx,
		`select count(*) from metric_rollup_dirty where host_id = $1::uuid`,
		host.ID).Scan(&owed); err != nil {
		t.Fatal(err)
	}
	if owed != 0 {
		t.Fatalf("%d quarters are still marked after the rollup cleared them", owed)
	}
}

// quarterOf is the start of the quarter-hour a moment falls in, as the
// panel computes it.
func quarterOf(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), at.Day(), at.Hour(), at.Minute()/15*15, 0, 0, time.UTC)
}

// TestOnlyOneInstanceJudgesTheRules proves the lease: an instance that finds
// it held evaluates nothing at all, rather than judging the same fleet a
// second time and relying on a unique index to swallow the parts of its
func TestOnlyOneInstanceJudgesTheRules(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	store := monitoring.NewStore(pool, slog.New(slog.NewTextHandler(io.Discard, nil)),
		monitoring.Options{})

	// Another instance holds the lease. It is written straight into the database
	// because that is all one control-plane instance ever knows about another.
	stranger := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		update monitoring_leases
		   set holder = $1::uuid, token = token + 1,
		       lease_until = now() + interval '20 seconds', updated_at = now()
		 where name = 'alert_evaluator'`, stranger); err != nil {
		t.Fatalf("the lease of the evaluator could not be taken for the test: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `
			update monitoring_leases set holder = null, lease_until = null, updated_at = now()
			 where name = 'alert_evaluator' and holder = $1::uuid`, stranger); err != nil {
			t.Logf("the lease of the evaluator was not given back: %v", err)
		}
	})

	if err := store.EvaluateLeased(ctx, time.Now()); err != nil {
		t.Fatalf("an instance without the lease answered with an error instead of standing aside: %v", err)
	}
	lease, err := store.EvaluatorLease(ctx)
	if err != nil {
		t.Fatalf("the lease of the evaluator could not be read: %v", err)
	}
	if lease.Holder != stranger {
		t.Fatalf("the lease is held by %s; an instance that found it held took it anyway", lease.Holder)
	}
}
