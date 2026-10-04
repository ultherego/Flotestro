package agent

import (
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// The case the protocol field exists for: the counter is gone and the spool is
// empty, so this boot renumbers from one into a range the panel already holds.
// Without the hint the host climbs out of that range one refused sample a
// minute; with it, one round trip.
func TestARefusalByNumberMovesTheNumberingPastWhatThePanelHolds(t *testing.T) {
	spool := openSpool(t, t.TempDir(), "boot-a", 50)
	first := &agentv1.MetricsSample{}
	if err := spool.Enqueue(first); err != nil {
		t.Fatal(err)
	}
	if first.GetSequence() != 1 {
		t.Fatalf("the first sample of a boot with no counter is %d, expected 1", first.GetSequence())
	}

	held := uint64(4321)
	spool.Acknowledge(&agentv1.MetricsAck{
		BootId: first.GetBootId(), Sequence: first.GetSequence(),
		Status: agentv1.MetricsAck_STATUS_DUPLICATE, HighestSequenceHeld: &held,
	})

	next := &agentv1.MetricsSample{}
	if err := spool.Enqueue(next); err != nil {
		t.Fatal(err)
	}
	if next.GetSequence() != held+1 {
		t.Fatalf("the next sample is %d; the panel holds up to %d, so it has to be %d",
			next.GetSequence(), held, held+1)
	}
}

// The numbering never goes back: a number this boot used is spent, which is the
// contract the panel relies on to tell one sample from another.
func TestTheNumberingIsNotHandedBackByAnAcknowledgement(t *testing.T) {
	spool := openSpool(t, t.TempDir(), "boot-a", 50)
	for range 5 {
		if err := spool.Enqueue(&agentv1.MetricsSample{}); err != nil {
			t.Fatal(err)
		}
	}
	behind := uint64(2)
	spool.Acknowledge(&agentv1.MetricsAck{
		BootId: spool.bootID, Sequence: 5,
		Status: agentv1.MetricsAck_STATUS_DUPLICATE, HighestSequenceHeld: &behind,
	})
	next := &agentv1.MetricsSample{}
	if err := spool.Enqueue(next); err != nil {
		t.Fatal(err)
	}
	if next.GetSequence() != 6 {
		t.Fatalf("the next sample is %d, expected 6: five were used", next.GetSequence())
	}
}

// A persisted sample says nothing the host does not know, so it must not move
// the numbering even if the field arrives filled in.
func TestAPersistedAcknowledgementDoesNotMoveTheNumbering(t *testing.T) {
	spool := openSpool(t, t.TempDir(), "boot-a", 50)
	if err := spool.Enqueue(&agentv1.MetricsSample{}); err != nil {
		t.Fatal(err)
	}
	held := uint64(900)
	spool.Acknowledge(&agentv1.MetricsAck{
		BootId: spool.bootID, Sequence: 1,
		Status: agentv1.MetricsAck_STATUS_PERSISTED, HighestSequenceHeld: &held,
	})
	next := &agentv1.MetricsSample{}
	if err := spool.Enqueue(next); err != nil {
		t.Fatal(err)
	}
	if next.GetSequence() != 2 {
		t.Fatalf("the next sample is %d, expected 2", next.GetSequence())
	}
}
