//go:build integration

package integration

// A hole in the data must not read like a healthy host (security
// remediation, chapters 12.3 and 16.1).

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/monitoring"
)

// metricGapView is a stretch of a chart window with no reading, as the API
// returns it.
type metricGapView struct {
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`
	Steps          int       `json:"steps"`
	Reason         string    `json:"reason"`
	RefusedSamples int64     `json:"refused_samples"`
}

type metricSeriesView struct {
	Points []struct {
		At time.Time `json:"at"`
	} `json:"points"`
	Gaps []metricGapView `json:"gaps"`
}

type refusalView struct {
	Reason        string    `json:"reason"`
	Samples       int64     `json:"samples"`
	FirstSampleAt time.Time `json:"first_sample_at"`
	LastSampleAt  time.Time `json:"last_sample_at"`
}

type hostGapReportView struct {
	LastSampleAt      *time.Time    `json:"last_sample_at"`
	Refused           []refusalView `json:"refused"`
	ClockSubstitution *struct {
		Reason     string `json:"reason"`
		SkewMillis int64  `json:"skew_millis"`
		Samples    int64  `json:"samples"`
	} `json:"clock_substitution"`
}

// sendMetricsSample delivers one reading and returns the panel's answer.
func sendMetricsSample(t *testing.T, session *syntheticSession, bootID string,
	sequence uint64, at time.Time) *agentv1.MetricsAck {
	t.Helper()
	if err := session.stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_MetricsSample{
			MetricsSample: syntheticSample(bootID, sequence, at),
		},
	}); err != nil {
		t.Fatalf("the sample %d was not sent: %v", sequence, err)
	}
	ack := session.awaitMetricsAck(30 * time.Second)
	if ack == nil {
		t.Fatalf("the panel did not answer the sample %d", sequence)
	}
	return ack
}

// TestARefusedSampleIsVisibleAsAGapAndNotAsAQuietHost is the negative the
// change exists for. Two hosts end the test with no reading in the chart
// window. One of them sent readings the panel would not store; the other
// never sent anything. Before this change both answers looked the same -
// no points, nothing else - and an operator reading the second chart during
// an incident had no way to learn that the first host had been talking all
// along and was being refused.
func TestARefusedSampleIsVisibleAsAGapAndNotAsAQuietHost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	gateway := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)

	refusedHost, refusedIdentity := h.enrollSyntheticHostWithIdentity(t)
	quietHost, _ := h.enrollSyntheticHostWithIdentity(t)

	bootID := uuid.NewString()
	session, err := openSyntheticSession(ctx, gateway, refusedIdentity, bootID)
	if err != nil {
		t.Fatalf("the synthetic host did not open a session: %v", err)
	}
	defer session.close()

	// Two days back: past the lateness budget of the installation, which is a
	// day. This is what a relay that was cut off over a weekend delivers.
	tooOld := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	ack := sendMetricsSample(t, session, bootID, 1, tooOld)
	if ack.GetStatus() != agentv1.MetricsAck_STATUS_REJECTED_TOO_OLD {
		t.Fatalf("a reading two days old was answered %s (%s)", ack.GetStatus(), ack.GetReasonCode())
	}
	if ack.GetReasonCode() != monitoring.ErrorSampleTooOld {
		t.Fatalf("the refusal carries the reason %q; the panel answers with typed codes",
			ack.GetReasonCode())
	}
	// A second refusal of the same day shares the row: a drained spool must
	// not cost a row per reading to say one thing.
	sendMetricsSample(t, session, bootID, 2, tooOld.Add(time.Minute))

	// The refusal outlives the process that answered it.
	var reason string
	var samples int64
	var first, last time.Time
	if err := pool.QueryRow(ctx, `
		select reason, samples, first_sample_at, last_sample_at
		from metric_gaps where host_id = $1::uuid`, refusedHost.ID).
		Scan(&reason, &samples, &first, &last); err != nil {
		t.Fatalf("the panel refused two readings and wrote nothing down: %v", err)
	}
	if reason != monitoring.ErrorSampleTooOld {
		t.Fatalf("the refusal was recorded under %q rather than a typed code", reason)
	}
	if samples != 2 {
		t.Fatalf("the two refusals were counted as %d", samples)
	}
	if !first.UTC().Equal(tooOld) || !last.UTC().Equal(tooOld.Add(time.Minute)) {
		t.Fatalf("the refused readings span %s..%s, not the moments the host claimed",
			first.UTC(), last.UTC())
	}

	// The API answer for the two hosts. Neither has a reading to draw.
	var refusedReport, quietReport hostGapReportView
	h.get(fmt.Sprintf("/api/v1/hosts/%s/monitoring", refusedHost.ID), &refusedReport)
	h.get(fmt.Sprintf("/api/v1/hosts/%s/monitoring", quietHost.ID), &quietReport)
	if refusedReport.LastSampleAt != nil {
		t.Fatalf("a refused reading was stored after all; the host reports as of %s",
			refusedReport.LastSampleAt)
	}
	if len(quietReport.Refused) != 0 {
		t.Fatalf("a host that never sent anything carries %d refusals", len(quietReport.Refused))
	}
	if len(refusedReport.Refused) == 0 {
		t.Fatal("the host the panel refused is indistinguishable from the host that was simply quiet")
	}
	if refusedReport.Refused[0].Reason != monitoring.ErrorSampleTooOld ||
		refusedReport.Refused[0].Samples != 2 {
		t.Fatalf("the refusal reaches the operator as %+v", refusedReport.Refused[0])
	}

	// And the chart window says the same thing: a hole with a cause on one
	// host, a hole with none on the other.
	var refusedSeries, quietSeries metricSeriesView
	h.get(fmt.Sprintf("/api/v1/hosts/%s/metrics?range=30d", refusedHost.ID), &refusedSeries)
	h.get(fmt.Sprintf("/api/v1/hosts/%s/metrics?range=30d", quietHost.ID), &quietSeries)
	if len(refusedSeries.Gaps) == 0 {
		t.Fatal("a window with no reading at all came back without a hole in it")
	}
	if refusedSeries.Gaps[0].Reason != monitoring.ErrorSampleTooOld {
		t.Fatalf("the hole of the refused host carries the reason %q", refusedSeries.Gaps[0].Reason)
	}
	if len(quietSeries.Gaps) == 0 || quietSeries.Gaps[0].Reason != "" {
		t.Fatalf("the hole of the quiet host was given a cause it does not have: %+v", quietSeries.Gaps)
	}
}

// TestAnOutageBetweenTwoReadingsIsAHoleInTheAnswer: the series used to
// return only the rows that exist, so two readings an outage apart arrived
// side by side and the chart drew a line straight through the outage.
func TestAnOutageBetweenTwoReadingsIsAHoleInTheAnswer(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	host, identity := h.enrollSyntheticHostWithIdentity(t)
	gateway := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)

	bootID := uuid.NewString()
	session, err := openSyntheticSession(ctx, gateway, identity, bootID)
	if err != nil {
		t.Fatalf("the synthetic host did not open a session: %v", err)
	}
	defer session.close()

	now := time.Now().UTC().Truncate(time.Second)
	// Late, but inside the lateness budget: a reading that waited in a spool
	// keeps the moment it was taken, which is what makes the hole visible.
	early := now.Add(-2*time.Hour - 30*time.Minute)
	if ack := sendMetricsSample(t, session, bootID, 1, early); ack.GetStatus() != agentv1.MetricsAck_STATUS_PERSISTED {
		t.Fatalf("a reading two and a half hours old was answered %s (%s)",
			ack.GetStatus(), ack.GetReasonCode())
	}
	if ack := sendMetricsSample(t, session, bootID, 2, now); ack.GetStatus() != agentv1.MetricsAck_STATUS_PERSISTED {
		t.Fatalf("a fresh reading was answered %s (%s)", ack.GetStatus(), ack.GetReasonCode())
	}

	var series metricSeriesView
	h.get(fmt.Sprintf("/api/v1/hosts/%s/metrics?range=3h", host.ID), &series)
	if len(series.Points) != 2 {
		t.Fatalf("the window holds %d readings, expected the two that were sent", len(series.Points))
	}
	var outage *metricGapView
	for i := range series.Gaps {
		if series.Gaps[i].From.UTC().Equal(early) {
			outage = &series.Gaps[i]
		}
	}
	if outage == nil {
		t.Fatalf("two readings two and a half hours apart came back without the hole between "+
			"them: %+v", series.Gaps)
	}
	if !outage.To.UTC().Equal(now) {
		t.Fatalf("the hole ends at %s rather than at the reading that ended it", outage.To.UTC())
	}
	if outage.Steps < 100 {
		t.Fatalf("the hole swallowed %d steps; two and a half hours of minutes is about 150",
			outage.Steps)
	}
}

// TestTheHostIsToldWhenThePanelUsedItsOwnClock: chapter 16.1 asks the UI to
// say when the gateway's time was substituted, which until now it was not
// told at all.
func TestTheHostIsToldWhenThePanelUsedItsOwnClock(t *testing.T) {
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

	// A machine resumed from a snapshot, or one whose clock was set by hand:
	// half an hour ahead of the panel, well past the skew limit.
	ahead := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)
	if ack := sendMetricsSample(t, session, bootID, 1, ahead); ack.GetStatus() != agentv1.MetricsAck_STATUS_PERSISTED {
		t.Fatalf("a reading from a host half an hour ahead was answered %s (%s)",
			ack.GetStatus(), ack.GetReasonCode())
	}

	var stored time.Time
	if err := pool.QueryRow(ctx,
		`select at from host_metrics where host_id = $1::uuid`, host.ID).Scan(&stored); err != nil {
		t.Fatalf("the reading was not stored: %v", err)
	}
	if !stored.Before(ahead) {
		t.Fatalf("the reading sits at %s, in the future the host claimed", stored.UTC())
	}

	var report hostGapReportView
	h.get(fmt.Sprintf("/api/v1/hosts/%s/monitoring", host.ID), &report)
	if report.ClockSubstitution == nil {
		t.Fatal("the panel supplied the moment of a reading and said nothing about it")
	}
	if report.ClockSubstitution.Reason != monitoring.ErrorClockSubstituted {
		t.Fatalf("the substitution is reported as %q rather than a typed code",
			report.ClockSubstitution.Reason)
	}
	if report.ClockSubstitution.SkewMillis < int64(20*time.Minute/time.Millisecond) {
		t.Fatalf("the skew of the host was measured as %d ms", report.ClockSubstitution.SkewMillis)
	}

	// Freshness is the panel's clock: a host talking now reports now, whatever
	// its own clock says the reading was taken at.
	var freshness time.Time
	if err := pool.QueryRow(ctx,
		`select last_metrics_at from hosts where id = $1::uuid`, host.ID).Scan(&freshness); err != nil {
		t.Fatalf("the host carries no moment of its last sample: %v", err)
	}
	if freshness.After(time.Now().UTC().Add(time.Minute)) {
		t.Fatalf("the freshness of the host stands at %s, taken from the host's own clock",
			freshness.UTC())
	}
}
