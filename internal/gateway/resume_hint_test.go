package gateway

// The one query behind the acknowledgement of a resource sample.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// The hint is a convenience: it tells a host that lost its counter where to
// resume. The acknowledgement it travels on is not a convenience - the host
// frees its spooled copy on it - so the query must not be able to hold the
// acknowledgement up. It ran on context.Background(): no deadline, and no
// cancellation when the session it answers is already gone, so a database that
// stopped answering held the ack path of every duplicate sample.
func TestTheQueryBehindTheAcknowledgementGivesUpAndTheAckGoesOut(t *testing.T) {
	previous := resumeHintTimeout
	resumeHintTimeout = 50 * time.Millisecond
	defer func() { resumeHintTimeout = previous }()

	asked := make(chan context.Context, 1)
	service := &AgentService{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		highestSequence: func(ctx context.Context, _, _ string) (uint64, error) {
			asked <- ctx
			<-ctx.Done()
			return 0, ctx.Err()
		},
	}

	sample := &agentv1.MetricsSample{BootId: "boot-a", Sequence: 3}
	done := make(chan *uint64, 1)
	go func() {
		done <- service.resumeHint(context.Background(), testHostID, sample,
			agentv1.MetricsAck_STATUS_DUPLICATE)
	}()

	select {
	case ctx := <-asked:
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("the query behind the acknowledgement runs without a deadline")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the hint never reached the store")
	}
	select {
	case hint := <-done:
		if hint != nil {
			t.Fatalf("a store that did not answer produced the hint %d", *hint)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the hint waited for a store that does not answer; the acknowledgement waited with it")
	}
}

// A store that answers nothing of interest leaves the field absent, which is
// the host's cue to keep walking its numbering up as it did before.
func TestAStoreThatKnowsNothingOfTheBootLeavesTheHintAbsent(t *testing.T) {
	service := &AgentService{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		highestSequence: func(context.Context, string, string) (uint64, error) {
			return 0, nil
		},
	}
	sample := &agentv1.MetricsSample{BootId: "boot-a", Sequence: 3}
	if hint := service.resumeHint(context.Background(), testHostID, sample,
		agentv1.MetricsAck_STATUS_DUPLICATE); hint != nil {
		t.Fatalf("the hint is %d for a boot the panel holds nothing of", *hint)
	}

	// And a panel with no sample store at all asks nobody.
	bare := &AgentService{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if hint := bare.resumeHint(context.Background(), testHostID, sample,
		agentv1.MetricsAck_STATUS_DUPLICATE); hint != nil {
		t.Fatalf("a panel without the monitoring answered the hint %d", *hint)
	}
}

// Only a refusal by number carries the hint: a sample the panel stored tells
// the host nothing it does not know.
func TestAStoredSampleCarriesNoHint(t *testing.T) {
	service := &AgentService{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		highestSequence: func(context.Context, string, string) (uint64, error) {
			return 0, errors.New("the store must not be asked at all")
		},
	}
	sample := &agentv1.MetricsSample{BootId: "boot-a", Sequence: 3}
	if hint := service.resumeHint(context.Background(), testHostID, sample,
		agentv1.MetricsAck_STATUS_PERSISTED); hint != nil {
		t.Fatalf("a stored sample carried the hint %d", *hint)
	}
}
