package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helper"
	"github.com/ultherego/flotestro/internal/opspec"
)

// fakeHelper answers requests over a unix socket the way the real helper does,
// so the executor reaches it through the unchanged client.
type fakeHelper struct {
	calls  atomic.Int32
	answer func(*helperv1.HelperRequest) *helperv1.HelperResponse
}

func startFakeHelper(t *testing.T, answer func(*helperv1.HelperRequest) *helperv1.HelperResponse) (*fakeHelper, *HelperClient) {
	t.Helper()
	// A unix socket path has a short limit; the directory of the test is too
	// deep for it on some machines.
	dir, err := os.MkdirTemp("", "fh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "helper.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	fake := &fakeHelper{answer: answer}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var request helperv1.HelperRequest
				if err := helper.ReadMessage(conn, &request); err != nil {
					return
				}
				fake.calls.Add(1)
				response := fake.answer(&request)
				response.Final = true
				_ = helper.WriteMessage(conn, response)
			}()
		}
	}()
	return fake, NewHelperClient(socket)
}

func accepted(*helperv1.HelperRequest) *helperv1.HelperResponse {
	return &helperv1.HelperResponse{Accepted: true, ExitCode: 0}
}

func systemdFacts() Facts {
	return Facts{Capabilities: Capabilities{{Name: CapSystemd, Available: true}}}
}

func restartEnvelope(taskID, key string) *agentv1.TaskEnvelope {
	task := unitEnvelope(taskID, "cron.service")
	task.IdempotencyKey = key
	return task
}

// progressLog records the reports an executor sends, from whichever goroutine
// sends them: the acknowledgement of a task goes out on the goroutine of its
// delivery while the test reads on its own.
type progressLog struct {
	mu      sync.Mutex
	reports []*agentv1.TaskProgress
}

func (l *progressLog) record(p *agentv1.TaskProgress) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reports = append(l.reports, p)
}

// withStage returns the reports of one stage, in the order they were sent.
func (l *progressLog) withStage(stage string) []*agentv1.TaskProgress {
	l.mu.Lock()
	defer l.mu.Unlock()
	var matching []*agentv1.TaskProgress
	for _, p := range l.reports {
		if p.GetStage() == stage {
			matching = append(matching, p)
		}
	}
	return matching
}

// stagesOf lists the stages reported for one attempt, in order.
func (l *progressLog) stagesOf(taskID string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var stages []string
	for _, p := range l.reports {
		if p.GetTaskId() == taskID {
			stages = append(stages, p.GetStage())
		}
	}
	return stages
}

func inFlightFiles(t *testing.T, dir string) []string {
	t.Helper()
	markers, err := filepath.Glob(filepath.Join(dir, "*"+inFlightSuffix))
	if err != nil {
		t.Fatal(err)
	}
	return markers
}

// TestTheMarkerIsDownBeforeTheHelperActsAndGoneWithTheResult: the journal
// says the helper is at the host before it acts, and the result closes it.
func TestTheMarkerIsDownBeforeTheHelperActsAndGoneWithTheResult(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewIdempotencyJournal(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	var seen InFlight
	var found bool
	_, client := startFakeHelper(t, func(request *helperv1.HelperRequest) *helperv1.HelperResponse {
		seen, found = journal.InFlight("key-1")
		return accepted(request)
	})
	executor := NewTaskExecutor(client, journal, systemdFacts, quietLogger())

	result := executor.Execute(context.Background(), restartEnvelope("task-1", "key-1"))
	if result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatalf("status = %s (%s: %s)", result.GetStatus(), result.GetErrorCode(), result.GetMessage())
	}
	if !found {
		t.Fatal("the helper acted without a marker in the journal")
	}
	if seen.TaskID != "task-1" || seen.Action != "unit.restart" || seen.IdempotencyKey != "key-1" {
		t.Errorf("marker = %+v", seen)
	}
	if seen.StartedAt.IsZero() || seen.PlanHash == "" {
		t.Errorf("the marker lacks the start or the plan hash: %+v", seen)
	}

	if _, still := journal.InFlight("key-1"); still {
		t.Error("the marker survived the result")
	}
	if files := inFlightFiles(t, dir); len(files) != 0 {
		t.Errorf("marker files left behind: %v", files)
	}
	if journal.Lookup("key-1") == nil {
		t.Error("the result was not stored")
	}
}

// TestARestartInFlightAnswersWithAnUnknownOutcome is the scenario itself: the
// agent went down between the order and the result, and the task comes back to
// a new process over the same journal.
func TestARestartInFlightAnswersWithAnUnknownOutcome(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewIdempotencyJournal(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC().Add(-3 * time.Minute).Truncate(time.Second)
	if err := journal.MarkInFlight(InFlight{
		IdempotencyKey: "key-1", TaskID: "task-1", Action: "unit.restart",
		StartedAt: started, PlanHash: "abcd",
	}); err != nil {
		t.Fatal(err)
	}

	fake, client := startFakeHelper(t, func(request *helperv1.HelperRequest) *helperv1.HelperResponse {
		t.Errorf("the helper was asked again for %s", request.GetTaskId())
		return accepted(request)
	})
	var startupLog bytes.Buffer
	log := slog.New(slog.NewTextHandler(&startupLog, nil))
	executor := NewTaskExecutor(client, journal, systemdFacts, log)

	for _, want := range []string{"task_id=task-1", "action=unit.restart", "age="} {
		if !strings.Contains(startupLog.String(), want) {
			t.Errorf("the startup log does not name the marker (%s): %s", want, startupLog.String())
		}
	}

	result := executor.Execute(context.Background(), restartEnvelope("task-2", "key-1"))
	if result.GetStatus() != agentv1.TaskResult_STATUS_FAILED || result.GetErrorCode() != RejectOutcomeUnknown {
		t.Fatalf("status = %s, code = %q", result.GetStatus(), result.GetErrorCode())
	}
	if result.GetReplayed() {
		t.Error("the first answer is marked as replayed")
	}
	if result.GetTaskId() != "task-2" {
		t.Errorf("the result does not point at the attempt: %q", result.GetTaskId())
	}
	if !result.GetStartedAt().AsTime().Equal(started) {
		t.Errorf("started_at = %s, the marker says %s", result.GetStartedAt().AsTime(), started)
	}
	if !strings.Contains(result.GetMessage(), "unit.restart") {
		t.Errorf("the message does not name the operation: %q", result.GetMessage())
	}
	var report map[string]any
	if err := json.Unmarshal(result.GetStdout(), &report); err != nil {
		t.Fatalf("the detail is not JSON: %v (%q)", err, result.GetStdout())
	}
	if report["kind"] != "outcome_unknown" || report["action"] != "unit.restart" ||
		report["task_id"] != "task-1" || report["plan_hash"] != "abcd" {
		t.Errorf("report = %v", report)
	}
	if at, _ := time.Parse(time.RFC3339Nano, report["started_at"].(string)); !at.Equal(started) {
		t.Errorf("the report's started_at = %v", report["started_at"])
	}
	if fake.calls.Load() != 0 {
		t.Errorf("the helper was called %d times", fake.calls.Load())
	}
	if files := inFlightFiles(t, dir); len(files) != 0 {
		t.Errorf("the marker was not closed with the outcome: %v", files)
	}

	// The second delivery is a replay of the judgment, not a new one.
	again := executor.Execute(context.Background(), restartEnvelope("task-3", "key-1"))
	if !again.GetReplayed() || again.GetErrorCode() != RejectOutcomeUnknown || again.GetTaskId() != "task-3" {
		t.Errorf("the second delivery: replayed=%v code=%q task=%q",
			again.GetReplayed(), again.GetErrorCode(), again.GetTaskId())
	}
	if fake.calls.Load() != 0 {
		t.Errorf("the helper was called %d times", fake.calls.Load())
	}
}

// TestAnUnknownPackageOutcomeCarriesWhatTheAdapterCanSay: a result that knows
// the state of the package database carries it, one that does not carries none.
func TestAnUnknownPackageOutcomeCarriesWhatTheAdapterCanSay(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe PackageStateProbe
		known bool
	}{
		{name: "known", known: true, probe: func(context.Context) *agentv1.PackageApplyResult {
			return &agentv1.PackageApplyResult{
				Manager: "apt", PackageDatabaseBroken: true, PackagesNeedingAttention: []string{"libc6"},
			}
		}},
		{name: "silent", probe: func(context.Context) *agentv1.PackageApplyResult { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			journal, err := NewIdempotencyJournal(dir, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.MarkInFlight(InFlight{
				IdempotencyKey: "key-1", TaskID: "task-1", Action: "packages.upgrade",
				StartedAt: time.Now().UTC(),
			}); err != nil {
				t.Fatal(err)
			}
			_, client := startFakeHelper(t, func(request *helperv1.HelperRequest) *helperv1.HelperResponse {
				t.Errorf("the helper was asked again for %s", request.GetTaskId())
				return accepted(request)
			})
			executor := NewTaskExecutor(client, journal, systemdFacts, quietLogger())
			executor.packageState = tc.probe

			result := executor.Execute(context.Background(), restartEnvelope("task-2", "key-1"))
			if result.GetErrorCode() != RejectOutcomeUnknown {
				t.Fatalf("code = %q", result.GetErrorCode())
			}
			detail := result.GetPackageApply()
			if tc.known {
				if detail == nil || !detail.GetPackageDatabaseBroken() ||
					len(detail.GetPackagesNeedingAttention()) != 1 {
					t.Fatalf("package detail = %v", detail)
				}
				if !strings.Contains(string(result.GetStdout()), `"packages_needing_attention":["libc6"]`) {
					t.Errorf("the report lacks the attention list: %s", result.GetStdout())
				}
				return
			}
			if detail != nil {
				t.Errorf("a silent adapter produced a package detail: %v", detail)
			}
			if strings.Contains(string(result.GetStdout()), "package_database_broken") {
				t.Errorf("the report claims a database state it does not know: %s", result.GetStdout())
			}
		})
	}
}

// TestAReadLeavesNoMarker guards the boundary of the marker: a read changes
// nothing, so repeating it after a restart is right, and the journal must not
// make it look like an interrupted change.
func TestAReadLeavesNoMarker(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewIdempotencyJournal(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fake, client := startFakeHelper(t, accepted)
	executor := NewTaskExecutor(client, journal, systemdFacts, quietLogger())

	read := &agentv1.TaskEnvelope{
		TaskId: "read-1", IdempotencyKey: "key-read",
		Action: &agentv1.TaskEnvelope_ReadUnitStatus{ReadUnitStatus: &agentv1.ReadUnitStatus{}},
	}
	result := executor.Execute(context.Background(), read)
	if result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatalf("status = %s (%s)", result.GetStatus(), result.GetMessage())
	}
	if files := inFlightFiles(t, dir); len(files) != 0 {
		t.Errorf("a read left a marker: %v", files)
	}
	if fake.calls.Load() != 0 {
		t.Errorf("a read went through the helper %d times", fake.calls.Load())
	}
	if journal.Lookup("key-read") == nil {
		t.Error("the result of the read was not stored")
	}
}

// TestARedeliveryDuringTheOperationIsAcknowledgedNotRefused guards the other
// reading of a marker: while the first delivery is still inside the helper,
// the marker means "in progress here".
func TestARedeliveryDuringTheOperationIsAcknowledgedNotRefused(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewIdempotencyJournal(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	fake, client := startFakeHelper(t, func(request *helperv1.HelperRequest) *helperv1.HelperResponse {
		close(entered)
		<-release
		return accepted(request)
	})
	executor := NewTaskExecutor(client, journal, systemdFacts, quietLogger())
	var reports progressLog
	executor.progress = reports.record

	first := make(chan *agentv1.TaskResult, 1)
	go func() {
		first <- executor.Execute(context.Background(), restartEnvelope("task-1", "key-1"))
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first delivery did not reach the helper")
	}

	second := executor.Execute(context.Background(), restartEnvelope("task-2", "key-1"))
	if second.GetErrorCode() != StatusInProgress || second.GetStatus() != agentv1.TaskResult_STATUS_UNSPECIFIED {
		t.Errorf("the redelivery: status=%s code=%q", second.GetStatus(), second.GetErrorCode())
	}
	if second.GetTaskId() != "task-2" {
		t.Errorf("the placeholder does not point at the attempt: %q", second.GetTaskId())
	}
	// The redelivered attempt is acknowledged as in progress and nothing else: it
	// is neither accepted nor started on its own, the execution it waits on was.
	if stages := reports.stagesOf("task-2"); len(stages) != 1 || stages[0] != StageInProgress {
		t.Fatalf("the redelivery produced the stages %v, expected one in_progress", stages)
	}
	ack := reports.withStage(StageInProgress)[0]
	if ack.GetTaskId() != "task-2" || ack.GetStage() != StageInProgress || ack.GetPreviousTaskId() != "task-1" {
		t.Errorf("the acknowledgement: task=%q stage=%q previous=%q",
			ack.GetTaskId(), ack.GetStage(), ack.GetPreviousTaskId())
	}
	if !strings.Contains(ack.GetMessage(), "still under way") || !strings.Contains(ack.GetMessage(), "started ") {
		t.Errorf("the acknowledgement does not say the operation runs and since when: %q", ack.GetMessage())
	}
	if fake.calls.Load() != 1 {
		t.Errorf("the helper was called %d times before the first delivery ended", fake.calls.Load())
	}

	close(release)
	var result *agentv1.TaskResult
	select {
	case result = <-first:
		if result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
			t.Errorf("the first delivery: %s (%s)", result.GetStatus(), result.GetErrorCode())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first delivery did not finish")
	}

	// The result is owed to both attempts: the one that did the work, and the
	// newest one the panel delivered while it ran.
	copied := executor.RedeliveredCopy(result)
	if copied == nil {
		t.Fatal("no copy of the result for the redelivered attempt")
	}
	if copied.GetTaskId() != "task-2" || !copied.GetReplayed() ||
		copied.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED ||
		copied.GetIdempotencyKey() != "key-1" {
		t.Errorf("the copy: task=%q replayed=%v status=%s key=%q",
			copied.GetTaskId(), copied.GetReplayed(), copied.GetStatus(), copied.GetIdempotencyKey())
	}
	if result.GetTaskId() != "task-1" || result.GetReplayed() {
		t.Errorf("the original was changed by the copy: task=%q replayed=%v",
			result.GetTaskId(), result.GetReplayed())
	}
	if executor.RedeliveredCopy(result) != nil {
		t.Error("the copy is owed once, not on every call")
	}

	// A delivery after the end is an ordinary replay from the journal.
	third := executor.Execute(context.Background(), restartEnvelope("task-3", "key-1"))
	if !third.GetReplayed() || third.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Errorf("the third delivery: replayed=%v status=%s", third.GetReplayed(), third.GetStatus())
	}
	if executor.RedeliveredCopy(third) != nil {
		t.Error("a replay owes no copy: nothing ran while it was answered")
	}
	if fake.calls.Load() != 1 {
		t.Errorf("the helper was called %d times", fake.calls.Load())
	}
	if files := inFlightFiles(t, dir); len(files) != 0 {
		t.Errorf("marker files left behind: %v", files)
	}
}

// TestTheNewestRedeliveredAttemptGetsTheResult: each reclaim closes the
// attempt before it, so the result goes to the newest attempt alone.
func TestTheNewestRedeliveredAttemptGetsTheResult(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewIdempotencyJournal(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	_, client := startFakeHelper(t, func(request *helperv1.HelperRequest) *helperv1.HelperResponse {
		close(entered)
		<-release
		return accepted(request)
	})
	executor := NewTaskExecutor(client, journal, systemdFacts, quietLogger())
	var reports progressLog
	executor.progress = reports.record

	// Nothing runs yet: the session treats the delivery as an ordinary one.
	if executor.Redelivered(restartEnvelope("task-1", "key-1")) {
		t.Fatal("a first delivery was taken for a redelivery")
	}
	first := make(chan *agentv1.TaskResult, 1)
	go func() {
		first <- executor.Execute(context.Background(), restartEnvelope("task-1", "key-1"))
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first delivery did not reach the helper")
	}

	if !executor.Redelivered(restartEnvelope("task-2", "key-1")) {
		t.Fatal("the second delivery was not recognised as a redelivery")
	}
	if !executor.Redelivered(restartEnvelope("task-3", "key-1")) {
		t.Fatal("the third delivery was not recognised as a redelivery")
	}
	// The attempt that started the operation is not a redelivery of itself,
	// and a stray repeat of it must not become the "newest attempt".
	if !executor.Redelivered(restartEnvelope("task-1", "key-1")) {
		t.Fatal("a repeat of the running attempt was not recognised as such")
	}
	acks := reports.withStage(StageInProgress)
	if len(acks) != 3 {
		t.Fatalf("%d acknowledgements, expected one per redelivery", len(acks))
	}
	for _, ack := range acks {
		if ack.GetPreviousTaskId() != "task-1" {
			t.Errorf("acknowledgement %q: previous=%q", ack.GetTaskId(), ack.GetPreviousTaskId())
		}
	}
	// Another key running at the same time is not touched by the bookkeeping.
	if executor.Redelivered(restartEnvelope("task-9", "key-other")) {
		t.Error("a delivery of another key was taken for a redelivery")
	}

	close(release)
	var result *agentv1.TaskResult
	select {
	case result = <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("the first delivery did not finish")
	}
	copied := executor.RedeliveredCopy(result)
	if copied == nil || copied.GetTaskId() != "task-3" {
		t.Fatalf("the copy goes to %v, expected the newest attempt task-3", copied.GetTaskId())
	}
	if executor.Redelivered(restartEnvelope("task-4", "key-1")) {
		t.Error("a delivery after the end was taken for a redelivery; it is a replay from the journal")
	}
}

// TestTheJournalKeepsMarkersApartFromResults guards the file discipline: the
// marker has its own name next to the result, a result closes it, and the list
// at startup sees only markers that are still open.
func TestTheJournalKeepsMarkersApartFromResults(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewIdempotencyJournal(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	open := InFlight{IdempotencyKey: "open", TaskID: "t-open", Action: "unit.stop", StartedAt: time.Now().UTC()}
	closed := InFlight{IdempotencyKey: "closed", TaskID: "t-closed", Action: "unit.start", StartedAt: time.Now().UTC()}
	for _, marker := range []InFlight{open, closed} {
		if err := journal.MarkInFlight(marker); err != nil {
			t.Fatal(err)
		}
	}
	if journal.Lookup("open") != nil {
		t.Error("a marker reads as a result")
	}
	if err := journal.Store("closed", &agentv1.TaskResult{Status: agentv1.TaskResult_STATUS_SUCCEEDED}); err != nil {
		t.Fatal(err)
	}
	if _, still := journal.InFlight("closed"); still {
		t.Error("the result did not close the marker")
	}
	markers := journal.InFlightMarkers()
	if len(markers) != 1 || markers[0].TaskID != "t-open" {
		t.Errorf("markers = %+v", markers)
	}
	// A key without a marker and an empty key are both "nothing in flight".
	if _, found := journal.InFlight("never"); found {
		t.Error("an unknown key has a marker")
	}
	if _, found := journal.InFlight(""); found {
		t.Error("an empty key has a marker")
	}
	if err := journal.MarkInFlight(InFlight{TaskID: "t"}); err == nil {
		t.Error("a marker without a key was accepted")
	}
}

// TestATaskIsAcceptedThenStartedAroundTheModuleCall: "accepted" goes out
// before the wait for the resources, "started" once the task holds them.
func TestATaskIsAcceptedThenStartedAroundTheModuleCall(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewIdempotencyJournal(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var reports progressLog
	var atTheHelper []string
	_, client := startFakeHelper(t, func(request *helperv1.HelperRequest) *helperv1.HelperResponse {
		atTheHelper = reports.stagesOf("task-1")
		return accepted(request)
	})
	executor := NewTaskExecutor(client, journal, systemdFacts, quietLogger())
	executor.progress = reports.record

	var admitted []string
	executor.admit = func(ctx context.Context, task *agentv1.TaskEnvelope, claims []opspec.ResourceClaim,
		waiting func(string)) (func(), string) {
		// The acknowledgement precedes the wait for the resources: a task
		// queued behind a busy lock is on the host, not lost.
		admitted = reports.stagesOf(task.GetTaskId())
		return func() {}, ""
	}

	result := executor.Execute(context.Background(), restartEnvelope("task-1", "key-1"))
	if result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatalf("status = %s (%s: %s)", result.GetStatus(), result.GetErrorCode(), result.GetMessage())
	}
	if len(admitted) != 1 || admitted[0] != StageAccepted {
		t.Errorf("at the wait for the resources the stages were %v, expected accepted alone", admitted)
	}
	if len(atTheHelper) != 2 || atTheHelper[0] != StageAccepted || atTheHelper[1] != StageStarted {
		t.Errorf("at the helper call the stages were %v, expected accepted then started", atTheHelper)
	}
	if after := reports.stagesOf("task-1"); len(after) != 2 {
		t.Errorf("the stages after the result are %v; nothing follows started but the result", after)
	}
	started := reports.withStage(StageStarted)
	if len(started) != 1 || len(started[0].GetClaims()) != 1 || started[0].GetClaims()[0] != opspec.LockUnits {
		t.Errorf("started does not name the claims held: %+v", started)
	}
}

// TestAReadIsAcceptedAndStartedWithoutClaims: a read takes no resource and
// leaves no marker, and still tells the panel where it stands - the dispatch
// lease of a read is as short as any other.
func TestAReadIsAcceptedAndStartedWithoutClaims(t *testing.T) {
	journal, err := NewIdempotencyJournal(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var reports progressLog
	_, client := startFakeHelper(t, accepted)
	executor := NewTaskExecutor(client, journal, systemdFacts, quietLogger())
	executor.progress = reports.record

	task := &agentv1.TaskEnvelope{
		TaskId: "read-1", IdempotencyKey: "read-key",
		Action: &agentv1.TaskEnvelope_ReadUnitStatus{ReadUnitStatus: &agentv1.ReadUnitStatus{}},
	}
	if result := executor.Execute(context.Background(), task); result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatalf("status = %s (%s)", result.GetStatus(), result.GetMessage())
	}
	stages := reports.stagesOf("read-1")
	if len(stages) != 2 || stages[0] != StageAccepted || stages[1] != StageStarted {
		t.Fatalf("the stages of a read were %v, expected accepted then started", stages)
	}
	if claims := reports.withStage(StageStarted)[0].GetClaims(); len(claims) != 0 {
		t.Errorf("a read reports the claims %v; it takes none", claims)
	}
}

// TestAWaitForABusyLockIsReportedBetweenAcceptedAndStarted: the blocker the
// locks name goes to the panel as an awaiting_lock report before started.
func TestAWaitForABusyLockIsReportedBetweenAcceptedAndStarted(t *testing.T) {
	journal, err := NewIdempotencyJournal(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, client := startFakeHelper(t, accepted)
	executor := NewTaskExecutor(client, journal, systemdFacts, quietLogger())
	var reports progressLog
	executor.progress = reports.record

	resources := newLocks()
	releaseHolder, _ := resources.acquire(context.Background(), "holder", "schedule.run_now", exclusiveOn(opspec.LockUnits))
	executor.admit = func(ctx context.Context, task *agentv1.TaskEnvelope, claims []opspec.ResourceClaim,
		waiting func(string)) (func(), string) {
		return acquireResources(ctx, resources, task, claims, waiting)
	}

	done := make(chan *agentv1.TaskResult, 1)
	go func() {
		done <- executor.Execute(context.Background(), restartEnvelope("task-1", "key-1"))
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(reports.withStage(StageAwaitingLock)) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no awaiting_lock report while the lock was held; stages: %v", reports.stagesOf("task-1"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	waiting := reports.withStage(StageAwaitingLock)[0]
	if !strings.Contains(waiting.GetMessage(), "units held by task holder") ||
		!strings.Contains(waiting.GetMessage(), "schedule.run_now") {
		t.Errorf("the blocker is not named: %q", waiting.GetMessage())
	}
	if stages := reports.stagesOf("task-1"); len(stages) != 2 || stages[0] != StageAccepted {
		t.Errorf("the stages while waiting were %v, expected accepted then awaiting_lock", stages)
	}

	releaseHolder()
	select {
	case result := <-done:
		if result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
			t.Fatalf("status = %s (%s: %s)", result.GetStatus(), result.GetErrorCode(), result.GetMessage())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the task did not run after the lock was released")
	}
	stages := reports.stagesOf("task-1")
	if len(stages) != 3 || stages[2] != StageStarted {
		t.Errorf("the stages were %v, expected accepted, awaiting_lock, started", stages)
	}
}

// TestARefusalByTheLockIsNotRemembered: a task that did not get its resource
// is refused for this delivery, not for the key.
func TestARefusalByTheLockIsNotRemembered(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewIdempotencyJournal(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fake, client := startFakeHelper(t, accepted)
	executor := NewTaskExecutor(client, journal, systemdFacts, quietLogger())
	busy := true
	executor.admit = func(ctx context.Context, task *agentv1.TaskEnvelope, claims []opspec.ResourceClaim,
		waiting func(string)) (func(), string) {
		if busy {
			return nil, "the resource units is busy with the operation unit.stop (task other)"
		}
		return func() {}, ""
	}

	refused := executor.Execute(context.Background(), restartEnvelope("task-1", "key-1"))
	if refused.GetStatus() != agentv1.TaskResult_STATUS_REJECTED || refused.GetErrorCode() != RejectResourceBusy {
		t.Fatalf("the refusal: status=%s code=%q", refused.GetStatus(), refused.GetErrorCode())
	}
	if refused.GetTaskId() != "task-1" || refused.GetIdempotencyKey() != "key-1" {
		t.Errorf("the refusal is not addressed: task=%q key=%q", refused.GetTaskId(), refused.GetIdempotencyKey())
	}
	if journal.Lookup("key-1") != nil {
		t.Fatal("the refusal by the lock was stored as the result of the key")
	}
	if files := inFlightFiles(t, dir); len(files) != 0 {
		t.Errorf("a task refused before the host was touched left a marker: %v", files)
	}
	if fake.calls.Load() != 0 {
		t.Errorf("the helper was called %d times for a refused task", fake.calls.Load())
	}

	busy = false
	second := executor.Execute(context.Background(), restartEnvelope("task-2", "key-1"))
	if second.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED || second.GetReplayed() {
		t.Errorf("the second delivery: status=%s replayed=%v code=%q",
			second.GetStatus(), second.GetReplayed(), second.GetErrorCode())
	}
}

// TestAChangedPreconditionAfterTheWaitIsRefusedWithoutTouchingTheHost: the
// preconditions are checked again once the task holds its resources.
func TestAChangedPreconditionAfterTheWaitIsRefusedWithoutTouchingTheHost(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewIdempotencyJournal(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fake, client := startFakeHelper(t, accepted)

	// The facts move while the task waits: the inventory cycle reads a new
	// boot ID once the host is back.
	var factsMu sync.Mutex
	bootID := "boot-before"
	facts := func() Facts {
		factsMu.Lock()
		defer factsMu.Unlock()
		f := systemdFacts()
		f.BootID = bootID
		return f
	}
	executor := NewTaskExecutor(client, journal, facts, quietLogger())
	var reports progressLog
	executor.progress = reports.record

	resources := newLocks()
	releaseHolder, _ := resources.acquire(context.Background(), "holder", "unit.stop", exclusiveOn(opspec.LockUnits))
	executor.admit = func(ctx context.Context, task *agentv1.TaskEnvelope, claims []opspec.ResourceClaim,
		waiting func(string)) (func(), string) {
		return acquireResources(ctx, resources, task, claims, waiting)
	}

	task := restartEnvelope("task-1", "key-1")
	task.Preconditions = &agentv1.Preconditions{ExpectedBootId: "boot-before"}
	done := make(chan *agentv1.TaskResult, 1)
	go func() { done <- executor.Execute(context.Background(), task) }()

	deadline := time.Now().Add(5 * time.Second)
	for len(reports.withStage(StageAwaitingLock)) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the task did not wait for the lock; stages: %v", reports.stagesOf("task-1"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The host reboots under the waiting task.
	factsMu.Lock()
	bootID = "boot-after"
	factsMu.Unlock()
	releaseHolder()

	var result *agentv1.TaskResult
	select {
	case result = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the task did not end after the lock was released")
	}
	if result.GetStatus() != agentv1.TaskResult_STATUS_REJECTED || result.GetErrorCode() != RejectPreconditionChanged {
		t.Fatalf("the refusal: status=%s code=%q message=%q", result.GetStatus(), result.GetErrorCode(), result.GetMessage())
	}
	if !strings.Contains(result.GetMessage(), "restarted") {
		t.Errorf("the refusal does not say what changed: %q", result.GetMessage())
	}
	if fake.calls.Load() != 0 {
		t.Errorf("the helper was called %d times for a task whose ground moved", fake.calls.Load())
	}
	if stages := reports.stagesOf("task-1"); len(stages) != 2 || stages[0] != StageAccepted || stages[1] != StageAwaitingLock {
		t.Errorf("the stages were %v, expected accepted and awaiting_lock and no start", stages)
	}
	if files := inFlightFiles(t, dir); len(files) != 0 {
		t.Errorf("a task refused before the host was touched left a marker: %v", files)
	}
	// The refusal is the answer to this plan, like a precondition refused before
	// the wait: a redelivery of the same plan meets the same host and replays it
	// rather than judging again.
	if stored := journal.Lookup("key-1"); stored == nil || stored.GetErrorCode() != RejectPreconditionChanged {
		t.Errorf("the refusal was not stored as the result of the key: %+v", stored)
	}
	if _, held := resources.held[opspec.LockUnits]; held {
		t.Error("the refused task kept its claim on the units class")
	}

	// The same task on the boot it was planned for runs: the recheck refuses
	// only what changed.
	factsMu.Lock()
	bootID = "boot-before"
	factsMu.Unlock()
	again := executor.Execute(context.Background(), restartEnvelope("task-2", "key-2"))
	if again.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatalf("a task on the planned boot: status=%s code=%q", again.GetStatus(), again.GetErrorCode())
	}
}

// TestAJournalThatCannotTakeTheMarkerStartsNothing is the full disk of the
// scenario list: the helper is never asked, and the refusal is typed.
func TestAJournalThatCannotTakeTheMarkerStartsNothing(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewIdempotencyJournal(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// A file where the journal expects its directory: every write under it fails
	// the way a full or read-only file system fails, whoever runs the test.
	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	journal.dir = filepath.Join(blocked, "journal")

	asked := false
	_, client := startFakeHelper(t, func(request *helperv1.HelperRequest) *helperv1.HelperResponse {
		asked = true
		return accepted(request)
	})
	executor := NewTaskExecutor(client, journal, systemdFacts, quietLogger())

	result := executor.Execute(context.Background(), restartEnvelope("task-1", "key-1"))
	if result.GetStatus() != agentv1.TaskResult_STATUS_FAILED || result.GetErrorCode() != RejectJournalUnavailable {
		t.Fatalf("status = %s, code = %s (%s); want failed with %s",
			result.GetStatus(), result.GetErrorCode(), result.GetMessage(), RejectJournalUnavailable)
	}
	if asked {
		t.Fatal("the helper was asked although the marker was not written")
	}

	// The journal comes back: the same key runs, and nothing from the
	// refused delivery stands in its way.
	journal.dir = dir
	result = executor.Execute(context.Background(), restartEnvelope("task-2", "key-1"))
	if result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED || result.GetReplayed() {
		t.Fatalf("after the journal came back: status = %s (%s), replayed = %v",
			result.GetStatus(), result.GetErrorCode(), result.GetReplayed())
	}
	if !asked {
		t.Fatal("the helper was not asked once the journal could write")
	}
}
