package spool

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

var clock = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

// signed builds a message with an envelope of the given session and
// sequence: what a host behind a relay sends.
func signed(payload *agentv1.AgentMessage, session string, sequence uint64) *agentv1.AgentMessage {
	payload.Envelope = &agentv1.RelayedEnvelope{
		SchemaVersion: 2, HostId: "host-1", SessionId: session, Sequence: sequence,
		Nonce: []byte("0123456789abcdef"),
	}
	return payload
}

func result(taskID string) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_TaskResult{
		TaskResult: &agentv1.TaskResult{TaskId: taskID},
	}}
}

func metric(mark int64) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_MetricsSample{
		MetricsSample: &agentv1.MetricsSample{SampledAtUnix: mark},
	}}
}

func inventory(revision string, full bool) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Inventory{
		Inventory: &agentv1.InventoryReport{Revision: revision, Full: full},
	}}
}

func logLines(taskID string) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_TaskLogLines{
		TaskLogLines: &agentv1.TaskLogLines{TaskId: taskID, Lines: []string{"line"}},
	}}
}

func open(t *testing.T, dir string, options Options) *Spool {
	t.Helper()
	if options.Now == nil {
		options.Now = func() time.Time { return clock }
	}
	spool, err := Open(dir, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	return spool
}

func appendMessage(t *testing.T, spool *Spool, hostID string, message *agentv1.AgentMessage) *Record {
	t.Helper()
	record, err := FromMessage("lab", hostID, message, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Append(record); err != nil {
		t.Fatal(err)
	}
	return record
}

// TestARecordSurvivesAReopen guards the point of the spool: what the relay
// took before a restart is what it holds after it, envelope and payload
// as they were.
func TestARecordSurvivesAReopen(t *testing.T) {
	dir := t.TempDir()
	spool := open(t, dir, Options{})
	written := appendMessage(t, spool, "host-1", signed(result("job-1"), "session-a", 7))
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := open(t, dir, Options{})
	records, err := reopened.Next("host-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("%d records came back after the reopen, expected 1", len(records))
	}
	got := records[0]
	if got.ID != written.ID || got.SessionID != "session-a" || got.Sequence != 7 || got.Stream != StreamJobResult {
		t.Fatalf("the record came back as %+v", got)
	}
	message, err := got.Message()
	if err != nil {
		t.Fatal(err)
	}
	if message.GetTaskResult().GetTaskId() != "job-1" || message.GetEnvelope().GetSequence() != 7 {
		t.Fatalf("the message came back as %v", message)
	}
	if got.PayloadHash != written.PayloadHash {
		t.Fatal("the payload hash changed on the way through the disk")
	}
}

// TestAnAcknowledgementDeletesExactlyOnce guards the contract with the
// panel: a record leaves the spool on the acknowledgement of its session
// and sequence, and a second acknowledgement finds nothing.
func TestAnAcknowledgementDeletesExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	spool := open(t, dir, Options{})
	appendMessage(t, spool, "host-1", signed(result("job-1"), "session-a", 1))
	appendMessage(t, spool, "host-1", signed(result("job-2"), "session-a", 2))
	if _, err := spool.Next("host-1", 0); err != nil {
		t.Fatal(err)
	}

	found, err := spool.Ack("host-1", "session-a", 1)
	if err != nil || !found {
		t.Fatalf("the acknowledgement found nothing (%v)", err)
	}
	if found, _ := spool.Ack("host-1", "session-a", 1); found {
		t.Fatal("a second acknowledgement of the same record found it again")
	}
	if stats := spool.Stats(); stats.Items != 1 {
		t.Fatalf("%d items are left, expected 1", stats.Items)
	}
	// A send is not a confirmation: the second record was sent and is
	// still here after a reopen.
	_ = spool.Close()
	reopened := open(t, dir, Options{})
	if stats := reopened.Stats(); stats.Items != 1 {
		t.Fatalf("%d items came back after the reopen, expected the unacknowledged 1", stats.Items)
	}
}

// TestATornLastRecordIsCutOff guards the crash the document names: a
// segment that ends inside a record loses that record and nothing else.
func TestATornLastRecordIsCutOff(t *testing.T) {
	dir := t.TempDir()
	spool := open(t, dir, Options{})
	appendMessage(t, spool, "host-1", signed(result("job-1"), "session-a", 1))
	appendMessage(t, spool, "host-1", signed(result("job-2"), "session-a", 2))
	_ = spool.Close()

	ids, err := listSegments(dir)
	if err != nil || len(ids) != 1 {
		t.Fatalf("segments = %v (%v)", ids, err)
	}
	path := segmentPath(dir, ids[0])
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The second record loses its last twenty bytes: the header says
	// the body is longer than what follows.
	if err := os.WriteFile(path, content[:len(content)-20], 0o600); err != nil {
		t.Fatal(err)
	}

	reopened := open(t, dir, Options{})
	records, err := reopened.Next("host-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Sequence != 1 {
		t.Fatalf("after the torn tail %d records came back (first %+v), expected the first one alone",
			len(records), records)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() >= int64(len(content)-20) {
		t.Fatalf("the torn tail was not cut: %d bytes", info.Size())
	}
	// The spool goes on appending after the cut, at the frame boundary.
	appendMessage(t, reopened, "host-1", signed(result("job-3"), "session-a", 3))
	_ = reopened.Close()
	again := open(t, dir, Options{})
	if stats := again.Stats(); stats.Items != 2 {
		t.Fatalf("%d items after the append past the cut, expected 2", stats.Items)
	}
}

// TestTheSendOrderIsPriorityThenSequence guards the requirement that a
// full stream of metrics does not starve a job result: the result goes
// first whatever arrived before it, and within a class the sequence
// holds.
func TestTheSendOrderIsPriorityThenSequence(t *testing.T) {
	spool := open(t, t.TempDir(), Options{})
	for i := int64(1); i <= 5; i++ {
		appendMessage(t, spool, "host-1", signed(metric(i), "session-a", uint64(i)))
	}
	appendMessage(t, spool, "host-1", signed(result("job-1"), "session-a", 6))
	appendMessage(t, spool, "host-1", signed(inventory("r1", true), "session-a", 7))

	records, err := spool.Next("host-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, record := range records {
		order = append(order, record.Stream)
	}
	if len(order) != 7 || order[0] != StreamJobResult || order[1] != StreamInventory || order[2] != StreamMetric {
		t.Fatalf("the send order was %v", order)
	}
	for i := 3; i < 7; i++ {
		if records[i].Sequence < records[i-1].Sequence {
			t.Fatalf("the metrics came out of sequence: %d after %d", records[i].Sequence, records[i-1].Sequence)
		}
	}
}

// TestInflightIsBoundedAndResentAfterTheTimeout guards the backpressure
// per host and the resend: a record sent and not acknowledged is sent
// again once the timeout passes, and not before.
func TestInflightIsBoundedAndResentAfterTheTimeout(t *testing.T) {
	now := clock
	spool := open(t, t.TempDir(), Options{
		MaxInflightPerHost: 2, AckTimeout: time.Minute,
		Now: func() time.Time { return now },
	})
	for i := uint64(1); i <= 3; i++ {
		appendMessage(t, spool, "host-1", signed(result("job"), "session-a", i))
	}
	first, _ := spool.Next("host-1", 0)
	if len(first) != 2 {
		t.Fatalf("%d records went out, expected the in-flight limit of 2", len(first))
	}
	if again, _ := spool.Next("host-1", 0); len(again) != 0 {
		t.Fatalf("%d more records went out while the limit was full", len(again))
	}
	now = now.Add(2 * time.Minute)
	third, _ := spool.Next("host-1", 0)
	if len(third) != 2 || third[0].Sequence != 1 {
		t.Fatalf("after the timeout %d records went out (first %d), expected the two oldest again", len(third), third[0].Sequence)
	}
}

// TestTheReserveIsKeptForTheDurableClasses guards the quota by class: a
// metrics sample is refused once the room outside the reserve is spent,
// evicting an older sample first, while a job result still fits; and the
// whole quota spent refuses the result as critical.
func TestTheReserveIsKeptForTheDurableClasses(t *testing.T) {
	spool := open(t, t.TempDir(), Options{MaxBytes: 2000, CriticalReserveBytes: 800})
	for i := int64(1); i <= 100; i++ {
		record, _ := FromMessage("lab", "host-1", signed(metric(i), "session-a", uint64(i)), clock)
		if err := spool.Append(record); err != nil {
			t.Fatalf("sample %d was refused although an older one could be evicted: %v", i, err)
		}
	}
	stats := spool.Stats()
	if stats.Items >= 100 || stats.Items == 0 {
		t.Fatalf("%d samples are waiting under a quota of 1200 bytes outside the reserve", stats.Items)
	}
	if stats.BytesUsed > 2000-800 {
		t.Fatalf("the metrics entered the reserve: %d bytes used", stats.BytesUsed)
	}
	if stats.DroppedTotal == 0 {
		t.Fatal("the evicted samples were not counted")
	}
	// The newest samples are the ones kept: drop-oldest, as the document
	// asks.
	records, _ := spool.Next("host-1", 0)
	if len(records) == 0 || records[len(records)-1].Sequence != 100 {
		t.Fatalf("the newest sample was not kept: %+v", records)
	}
	spool.Unsend("host-1")
	// A result goes into the reserve.
	if err := spool.Append(must(FromMessage("lab", "host-1", signed(result("job-1"), "session-a", 200), clock))); err != nil {
		t.Fatalf("a job result was refused while the reserve was free: %v", err)
	}
	// A log line is refused with resource_exhausted rather than evicting
	// anything.
	if err := spool.Append(must(FromMessage("lab", "host-1", signed(logLines("job-1"), "session-a", 201), clock))); err != ErrExhausted {
		t.Fatalf("a log line outside the reserve got %v, expected ErrExhausted", err)
	}
	// Results until the whole quota is spent: the refusal is critical.
	var last error
	for i := uint64(300); i < 400; i++ {
		if last = spool.Append(must(FromMessage("lab", "host-1", signed(result("job"), "session-a", i), clock))); last != nil {
			break
		}
	}
	if last != ErrCritical {
		t.Fatalf("the spent quota refused with %v, expected ErrCritical", last)
	}
	if !spool.Stats().Critical {
		t.Fatal("a spool in its reserve does not say it is critical")
	}
}

// TestAFullInventoryCoalescesTheEarlierOnes guards the policy of the
// inventory class: a full report says everything the earlier waiting
// reports said, so they go and it stays.
func TestAFullInventoryCoalescesTheEarlierOnes(t *testing.T) {
	spool := open(t, t.TempDir(), Options{})
	appendMessage(t, spool, "host-1", signed(inventory("r1", true), "session-a", 1))
	appendMessage(t, spool, "host-1", signed(inventory("r2", false), "session-a", 2))
	appendMessage(t, spool, "host-2", signed(inventory("r1", true), "session-b", 1))
	appendMessage(t, spool, "host-1", signed(inventory("r3", true), "session-a", 3))

	records, _ := spool.Next("host-1", 0)
	if len(records) != 1 || records[0].Sequence != 3 {
		t.Fatalf("host-1 has %d inventory records waiting, expected the full r3 alone", len(records))
	}
	// A partial report after a full one is kept: it may carry what the
	// full one does not.
	appendMessage(t, spool, "host-1", signed(inventory("r4", false), "session-a", 4))
	if stats := spool.Stats(); stats.Items != 3 {
		t.Fatalf("%d items in the spool, expected 3 (r3, r4 and host-2's)", stats.Items)
	}
}

// TestTheIndexIsRebuiltAcrossSegments guards the rebuild over more than
// one segment file, with tombstones in a later segment deleting records
// of an earlier one and a dead segment removed.
func TestTheIndexIsRebuiltAcrossSegments(t *testing.T) {
	dir := t.TempDir()
	spool := open(t, dir, Options{SegmentBytes: 300})
	for i := uint64(1); i <= 6; i++ {
		appendMessage(t, spool, "host-1", signed(result("job"), "session-a", i))
	}
	if _, err := spool.Next("host-1", 0); err != nil {
		t.Fatal(err)
	}
	for i := uint64(1); i <= 4; i++ {
		if found, err := spool.Ack("host-1", "session-a", i); err != nil || !found {
			t.Fatalf("sequence %d was not acknowledged (%v)", i, err)
		}
	}
	before := spool.Stats()
	_ = spool.Close()

	reopened := open(t, dir, Options{SegmentBytes: 300})
	after := reopened.Stats()
	if after.Items != 2 || after.Items != before.Items {
		t.Fatalf("%d items after the rebuild, %d before", after.Items, before.Items)
	}
	records, _ := reopened.Next("host-1", 0)
	if len(records) != 2 || records[0].Sequence != 5 || records[1].Sequence != 6 {
		t.Fatalf("the records after the rebuild are %+v", records)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) >= 6 {
		t.Fatalf("%d segment files remain after four of six records died", len(entries))
	}
}

// TestAnExpiredRecordIsCut guards the lifetime: a sample older than its
// class allows is not delivered as the present.
func TestAnExpiredRecordIsCut(t *testing.T) {
	now := clock
	spool := open(t, t.TempDir(), Options{Now: func() time.Time { return now }})
	appendMessage(t, spool, "host-1", signed(metric(1), "session-a", 1))
	appendMessage(t, spool, "host-1", signed(result("job-1"), "session-a", 2))
	now = now.Add(7 * time.Hour)
	records, _ := spool.Next("host-1", 0)
	if len(records) != 1 || records[0].Stream != StreamJobResult {
		t.Fatalf("after seven hours %d records are due (%+v), expected the result alone", len(records), records)
	}
	if spool.Stats().ExpiredTotal != 1 {
		t.Fatal("the expired sample was not counted")
	}
}

// TestAMessageWithoutAnEnvelopeIsConfirmedByItsIdentifier guards the
// compatibility with an agent from before the envelope: its message has
// no sequence for the panel to acknowledge, and the relay confirms it by
// the record identifier after the send.
func TestAMessageWithoutAnEnvelopeIsConfirmedByItsIdentifier(t *testing.T) {
	spool := open(t, t.TempDir(), Options{})
	record := appendMessage(t, spool, "host-1", result("job-1"))
	if record.Sequence != 0 || record.SessionID != "" {
		t.Fatalf("an unsigned message got a session and a sequence: %+v", record)
	}
	if found, _ := spool.Ack("host-1", "", 0); found {
		t.Fatal("an acknowledgement of sequence zero found the unsigned record")
	}
	if err := spool.Delete(record.ID); err != nil {
		t.Fatal(err)
	}
	if spool.Stats().Items != 0 {
		t.Fatal("the confirmed unsigned record stayed")
	}
}

// TestTheDirectoryIsPrivate guards that the spool is readable by the
// relay alone: it carries the hosts' messages.
func TestTheDirectoryIsPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	open(t, dir, Options{})
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("the spool directory has mode %o, expected 0700", info.Mode().Perm())
	}
}

func must(record *Record, err error) *Record {
	if err != nil {
		panic(err)
	}
	return record
}

// A second identifier is never generated for a record that has one: the
// identifier is what the tombstone names.
func TestARecordKeepsItsIdentifier(t *testing.T) {
	spool := open(t, t.TempDir(), Options{})
	id := uuid.New()
	record := must(FromMessage("lab", "host-1", result("job-1"), clock))
	record.ID = id
	if err := spool.Append(record); err != nil {
		t.Fatal(err)
	}
	records, _ := spool.Next("host-1", 0)
	if len(records) != 1 || records[0].ID != id {
		t.Fatalf("the record came back under another identifier: %+v", records)
	}
}

// TestEveryDurableClassIsOnTheDiskBeforeItIsAccepted guards the promise
// the relay makes when it takes a message of a durable class: the record
// is on the disk before the caller goes on, so a power failure a
// millisecond later costs the site nothing.
//
// The classes written ahead of the live forward are control, job results
// and inventory. An inventory report accepted into the batch of the light
// classes would be a report the relay answers for and does not hold - the
// window is short, and a site that loses its inventory over a power
// failure has no way of telling.
func TestEveryDurableClassIsOnTheDiskBeforeItIsAccepted(t *testing.T) {
	// The batch of the light classes is pushed out of the way, so that
	// what the test observes is the sync of the append and not a tick
	// that happened to arrive.
	spool := open(t, t.TempDir(), Options{FlushInterval: time.Hour})
	durable := []struct {
		name    string
		message *agentv1.AgentMessage
	}{
		{"a control message", &agentv1.AgentMessage{}},
		{"a job result", result("job-1")},
		{"an inventory report", inventory("rev-1", true)},
	}
	for index, c := range durable {
		appendMessage(t, spool, "host-1", signed(c.message, "session-a", uint64(index+1)))
		spool.mu.Lock()
		waiting := spool.dirty
		spool.mu.Unlock()
		if waiting {
			t.Fatalf("%s was accepted with its record still waiting for the batch", c.name)
		}
	}
	// A metrics sample is the light class: one of many, and the next one
	// says more, so it may wait for the batch.
	appendMessage(t, spool, "host-1", signed(metric(1), "session-a", 9))
	spool.mu.Lock()
	waiting := spool.dirty
	spool.mu.Unlock()
	if !waiting {
		t.Fatal("a metrics sample was synced one by one; the batch exists so that it is not")
	}
}

// TestASpoolThatCannotReachTheDiskSaysSo guards what the readiness of the
// relay is built on: a failed sync of the batch is remembered rather than
// swallowed, so a relay whose disk stopped taking writes stops reporting
// itself able to carry the results of the site.
func TestASpoolThatCannotReachTheDiskSaysSo(t *testing.T) {
	spool := open(t, t.TempDir(), Options{FlushInterval: 5 * time.Millisecond})
	appendMessage(t, spool, "host-1", signed(metric(1), "session-a", 1))
	if err := spool.FlushError(); err != nil {
		t.Fatalf("a spool that writes reported %v", err)
	}
	// The file under the active segment is taken away: what a disk that
	// stopped answering does to the next sync.
	spool.mu.Lock()
	_ = spool.active.file.Close()
	spool.dirty = true
	spool.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for spool.FlushError() == nil {
		if time.Now().After(deadline) {
			t.Fatal("a sync that failed left the spool reporting itself healthy")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
