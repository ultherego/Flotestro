package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

func openSpool(t *testing.T, dir, bootID string, limit int) *MetricsSpool {
	t.Helper()
	spool, err := OpenMetricsSpool(dir, bootID, limit, quietLog())
	if err != nil {
		t.Fatalf("the spool did not open: %v", err)
	}
	return spool
}

// TestTheSpoolNumbersEverySampleWithinTheBoot proves the identity: the
// sequence starts at one, grows by one, and carries the boot the host is on.
func TestTheSpoolNumbersEverySampleWithinTheBoot(t *testing.T) {
	spool := openSpool(t, t.TempDir(), "boot-a", 10)
	for want := uint64(1); want <= 3; want++ {
		sample := &agentv1.MetricsSample{SampledAtUnix: int64(want)}
		if err := spool.Enqueue(sample); err != nil {
			t.Fatalf("the sample was not spooled: %v", err)
		}
		if sample.GetSequence() != want {
			t.Fatalf("the sample was numbered %d, expected %d", sample.GetSequence(), want)
		}
		if sample.GetBootId() != "boot-a" {
			t.Fatalf("the sample carries the boot %q", sample.GetBootId())
		}
	}
	if spool.Len() != 3 {
		t.Fatalf("the spool holds %d samples, expected 3", spool.Len())
	}
}

// TestTheSpoolKeepsASampleUntilItIsAcknowledged is the whole point of the
// spool: the send is not what frees a reading, the panel's answer is.
func TestTheSpoolKeepsASampleUntilItIsAcknowledged(t *testing.T) {
	spool := openSpool(t, t.TempDir(), "boot-a", 10)
	first := &agentv1.MetricsSample{SampledAtUnix: 100}
	second := &agentv1.MetricsSample{SampledAtUnix: 160}
	for _, sample := range []*agentv1.MetricsSample{first, second} {
		if err := spool.Enqueue(sample); err != nil {
			t.Fatal(err)
		}
	}
	pending := spool.Pending()
	if len(pending) != 2 {
		t.Fatalf("%d samples wait for an answer, expected 2", len(pending))
	}
	if pending[0].GetSequence() != 1 || pending[1].GetSequence() != 2 {
		t.Fatalf("the samples came back out of order: %d, %d",
			pending[0].GetSequence(), pending[1].GetSequence())
	}
	if pending[0].GetSampledAtUnix() != 100 {
		t.Fatalf("the spooled sample did not come back as it went in: %+v", pending[0])
	}

	spool.Acknowledge(&agentv1.MetricsAck{
		BootId: "boot-a", Sequence: 1, Status: agentv1.MetricsAck_STATUS_PERSISTED})
	if spool.Len() != 1 {
		t.Fatalf("the acknowledged sample did not leave the spool; %d remain", spool.Len())
	}
	// A duplicate is an answer as well: the panel holds the reading, so
	// the copy may go.
	spool.Acknowledge(&agentv1.MetricsAck{
		BootId: "boot-a", Sequence: 2, Status: agentv1.MetricsAck_STATUS_DUPLICATE})
	if spool.Len() != 0 {
		t.Fatalf("the spool still holds %d samples after both were answered", spool.Len())
	}
}

// TestAnAcknowledgementOfAnotherBootLeavesTheSpoolAlone: the sequence starts
// again at one on every boot, so an answer that names a boot the spool does
// not hold must not free the sample that happens to share its number.
func TestAnAcknowledgementOfAnotherBootLeavesTheSpoolAlone(t *testing.T) {
	spool := openSpool(t, t.TempDir(), "boot-b", 10)
	if err := spool.Enqueue(&agentv1.MetricsSample{SampledAtUnix: 10}); err != nil {
		t.Fatal(err)
	}
	spool.Acknowledge(&agentv1.MetricsAck{BootId: "boot-a", Sequence: 1})
	if spool.Len() != 1 {
		t.Fatal("an acknowledgement of another boot emptied the spool")
	}
}

// TestTheSpoolSurvivesARestartOfTheAgent: a restart within one boot picks up
// what was not answered and carries on counting.
func TestTheSpoolSurvivesARestartOfTheAgent(t *testing.T) {
	dir := t.TempDir()
	first := openSpool(t, dir, "boot-a", 10)
	for i := 0; i < 3; i++ {
		if err := first.Enqueue(&agentv1.MetricsSample{SampledAtUnix: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	first.Acknowledge(&agentv1.MetricsAck{BootId: "boot-a", Sequence: 2})

	again := openSpool(t, dir, "boot-a", 10)
	pending := again.Pending()
	if len(pending) != 2 {
		t.Fatalf("the restarted agent found %d samples, expected the two unanswered ones", len(pending))
	}
	if pending[0].GetSequence() != 1 || pending[1].GetSequence() != 3 {
		t.Fatalf("the restarted agent found %d and %d",
			pending[0].GetSequence(), pending[1].GetSequence())
	}
	next := &agentv1.MetricsSample{SampledAtUnix: 500}
	if err := again.Enqueue(next); err != nil {
		t.Fatal(err)
	}
	if next.GetSequence() != 4 {
		t.Fatalf("the restarted agent handed out %d again; it must count past every number it used",
			next.GetSequence())
	}
}

// TestARestartCountsPastNumbersNothingIsLeftOf is the case the counter file
// exists for: every sample was acknowledged, so the directory holds nothing to
// learn the last number from.
func TestARestartCountsPastNumbersNothingIsLeftOf(t *testing.T) {
	dir := t.TempDir()
	first := openSpool(t, dir, "boot-a", 10)
	for i := 1; i <= 5; i++ {
		sample := &agentv1.MetricsSample{}
		if err := first.Enqueue(sample); err != nil {
			t.Fatal(err)
		}
		first.Acknowledge(&agentv1.MetricsAck{BootId: "boot-a", Sequence: sample.GetSequence()})
	}
	if first.Len() != 0 {
		t.Fatalf("the spool holds %d samples although every one was answered", first.Len())
	}
	again := openSpool(t, dir, "boot-a", 10)
	sample := &agentv1.MetricsSample{}
	if err := again.Enqueue(sample); err != nil {
		t.Fatal(err)
	}
	if sample.GetSequence() != 6 {
		t.Fatalf("the restarted agent handed out %d, a number the panel already holds",
			sample.GetSequence())
	}
}

// TestARebootStartsANewRunWithoutLosingTheOldOne: the samples of the boot
// before are still worth delivering and are still the older ones.
func TestARebootStartsANewRunWithoutLosingTheOldOne(t *testing.T) {
	dir := t.TempDir()
	before := openSpool(t, dir, "boot-a", 10)
	if err := before.Enqueue(&agentv1.MetricsSample{SampledAtUnix: 10}); err != nil {
		t.Fatal(err)
	}
	after := openSpool(t, dir, "boot-b", 10)
	fresh := &agentv1.MetricsSample{SampledAtUnix: 20}
	if err := after.Enqueue(fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.GetSequence() != 1 {
		t.Fatalf("the new boot started counting at %d instead of one", fresh.GetSequence())
	}
	pending := after.Pending()
	if len(pending) != 2 {
		t.Fatalf("%d samples wait, expected the one from before the reboot and the one after", len(pending))
	}
	if pending[0].GetBootId() != "boot-a" || pending[1].GetBootId() != "boot-b" {
		t.Fatalf("the samples of the two boots came back in the order %q, %q",
			pending[0].GetBootId(), pending[1].GetBootId())
	}
}

// TestTheSpoolIsBounded: a host whose panel has been away for a week costs
// that host the bound, not the week, and what it keeps is the newest.
func TestTheSpoolIsBounded(t *testing.T) {
	dir := t.TempDir()
	spool := openSpool(t, dir, "boot-a", 4)
	for i := 0; i < 10; i++ {
		if err := spool.Enqueue(&agentv1.MetricsSample{SampledAtUnix: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if spool.Len() != 4 {
		t.Fatalf("the spool holds %d samples, expected its bound of 4", spool.Len())
	}
	pending := spool.Pending()
	if pending[0].GetSequence() != 7 || pending[3].GetSequence() != 10 {
		t.Fatalf("the spool kept %d..%d; the newest readings are the ones worth keeping",
			pending[0].GetSequence(), pending[3].GetSequence())
	}
	// The files of the dropped samples are gone from the disk as well: a
	// bound nobody enforces on disk is a full disk on the host.
	listing, err := os.ReadDir(filepath.Join(dir, metricsSpoolDirName))
	if err != nil {
		t.Fatal(err)
	}
	var samples int
	for _, item := range listing {
		if filepath.Ext(item.Name()) == metricsSpoolSuffix {
			samples++
		}
	}
	if samples != 4 {
		t.Fatalf("%d sample files are on disk, expected 4", samples)
	}
}

// TestACorruptSpoolFileIsDiscarded: a reading nobody can decode is not a
// reading, and it must not hold a place the next one could use.
func TestACorruptSpoolFileIsDiscarded(t *testing.T) {
	dir := t.TempDir()
	spool := openSpool(t, dir, "boot-a", 10)
	for i := 0; i < 2; i++ {
		if err := spool.Enqueue(&agentv1.MetricsSample{SampledAtUnix: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, metricsSpoolDirName, spoolName(1, 1))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	again := openSpool(t, dir, "boot-a", 10)
	pending := again.Pending()
	if len(pending) != 1 || pending[0].GetSequence() != 2 {
		t.Fatalf("the corrupt file was not discarded; %d samples came back", len(pending))
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the corrupt file is still on disk")
	}
}

// TestTheSamplerResendsWhatWasNotAcknowledged is the session's half: on a new
// stream the agent sends what the panel never confirmed, oldest first, before
// the reading it is about to take.
func TestTheSamplerResendsWhatWasNotAcknowledged(t *testing.T) {
	dir := t.TempDir()
	spool := openSpool(t, dir, "boot-a", 10)
	for i := 0; i < 3; i++ {
		if err := spool.Enqueue(&agentv1.MetricsSample{SampledAtUnix: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	spool.Acknowledge(&agentv1.MetricsAck{BootId: "boot-a", Sequence: 1})

	sampler := fixtureSampler(t, procFixture(t, "cpu 100 0 50 800 20 0 5 25 0 0"))
	sampler.spool = spool
	sent := make(chan uint64, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A long interval: the run is here for the drain, and the loop after
	// it must not add a reading of its own before the context ends.
	go sampler.Run(ctx, time.Hour, func(sample *agentv1.MetricsSample) error {
		sent <- sample.GetSequence()
		return nil
	}, quietLog())
	var order []uint64
	for range 2 {
		select {
		case sequence := <-sent:
			order = append(order, sequence)
		case <-time.After(5 * time.Second):
			t.Fatalf("the session resent only %v of the two unanswered samples", order)
		}
	}
	cancel()
	if order[0] != 2 || order[1] != 3 {
		t.Fatalf("the session resent %v; expected the two unanswered samples, oldest first", order)
	}
	if spool.Len() != 2 {
		t.Fatal("the resend emptied the spool; only the panel's answer may do that")
	}
}
