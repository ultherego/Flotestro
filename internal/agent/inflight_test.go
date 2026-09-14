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
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helper"
)

// fakeHelper answers requests over a unix socket the way the real helper
// does, so the executor reaches it through the unchanged client. The answer
// is decided by the test, which lets it look at the journal at the exact
// moment the helper would be acting on the host.
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

func inFlightFiles(t *testing.T, dir string) []string {
	t.Helper()
	markers, err := filepath.Glob(filepath.Join(dir, "*"+inFlightSuffix))
	if err != nil {
		t.Fatal(err)
	}
	return markers
}

// TestTheMarkerIsDownBeforeTheHelperActsAndGoneWithTheResult guards the
// order the scenario depends on: at the moment the helper is touching the
// host the journal already says so, and once the result is stored nothing
// is left that could be judged as a restart.
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
// agent went down between the order and the result, and the task comes back
// to a new process over the same journal. The answer names what was started
// and when, the helper is not asked again, and the next delivery replays the
// same answer instead of judging the host once more.
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

// TestAnUnknownPackageOutcomeCarriesWhatTheAdapterCanSay guards the panel's
// view of the package database: a result that knows the state carries it
// under the same field as a transaction would, and a result that does not
// carries no package detail at all.
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
// nothing, so repeating it after a restart is right, and the journal must
// not make it look like an interrupted change.
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

// TestARedeliveryDuringTheOperationWaitsInsteadOfJudging guards the other
// reading of a marker: while the first delivery is still inside the helper,
// the marker means "in progress here", and the task is told to come back -
// neither run again nor declared unknown.
func TestARedeliveryDuringTheOperationWaitsInsteadOfJudging(t *testing.T) {
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
	if second.GetStatus() != agentv1.TaskResult_STATUS_REJECTED || second.GetErrorCode() != RejectResourceBusy {
		t.Errorf("the redelivery: status=%s code=%q", second.GetStatus(), second.GetErrorCode())
	}
	if second.GetTaskId() != "task-2" {
		t.Errorf("the refusal does not point at the attempt: %q", second.GetTaskId())
	}

	close(release)
	select {
	case result := <-first:
		if result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
			t.Errorf("the first delivery: %s (%s)", result.GetStatus(), result.GetErrorCode())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first delivery did not finish")
	}
	third := executor.Execute(context.Background(), restartEnvelope("task-3", "key-1"))
	if !third.GetReplayed() || third.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Errorf("the third delivery: replayed=%v status=%s", third.GetReplayed(), third.GetStatus())
	}
	if fake.calls.Load() != 1 {
		t.Errorf("the helper was called %d times", fake.calls.Load())
	}
}

// TestTheJournalKeepsMarkersApartFromResults guards the file discipline: the
// marker has its own name next to the result, a result closes it, and the
// list at startup sees only markers that are still open.
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
