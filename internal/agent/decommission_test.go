package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// fakeStream stands in for the stream to the panel: it keeps what the agent
// sent and hands out the FinalReady once it arrives.
type fakeStream struct {
	mu   sync.Mutex
	sent []*agentv1.AgentMessage
	seen chan *agentv1.AgentMessage
}

func newFakeStream() *fakeStream {
	return &fakeStream{seen: make(chan *agentv1.AgentMessage, 8)}
}

func (f *fakeStream) send(msg *agentv1.AgentMessage) error {
	f.mu.Lock()
	f.sent = append(f.sent, msg)
	f.mu.Unlock()
	f.seen <- msg
	return nil
}

func (f *fakeStream) next(t *testing.T) *agentv1.AgentMessage {
	t.Helper()
	select {
	case msg := <-f.seen:
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("the agent sent nothing")
		return nil
	}
}

// TestFinalTaskWaitsForTheRunningWorkAndRefusesNewWork guards the first step
// of the handshake: what runs finishes, nothing new starts, and FinalReady
// goes out once the host is idle, with the leases dropped.
func TestFinalTaskWaitsForTheRunningWorkAndRefusesNewWork(t *testing.T) {
	handshake := newFinalHandshake()
	stream := newFakeStream()
	if !handshake.start("task-running") {
		t.Fatal("a task was refused before the final task")
	}

	done := make(chan error, 1)
	go func() {
		done <- answerFinalTask(context.Background(),
			&agentv1.FinalTask{Reason: "handed over", GraceSeconds: 30}, handshake, stream.send, quietLogger())
	}()

	// The host is leaving: the next task is refused, not started.
	deadline := time.Now().Add(5 * time.Second)
	for !handshake.isLeaving() {
		if time.Now().After(deadline) {
			t.Fatal("the final task did not mark the host as leaving")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if handshake.start("task-late") {
		t.Fatal("a task started after the final task")
	}
	refusal := refuseRetiring("task-late")
	if refusal.GetStatus() != agentv1.TaskResult_STATUS_REJECTED || refusal.GetErrorCode() != RejectRetiring {
		t.Fatalf("refusal = %s %s", refusal.GetStatus(), refusal.GetErrorCode())
	}

	// Nothing goes out while the running task is under way.
	select {
	case msg := <-stream.seen:
		t.Fatalf("FinalReady went out before the running task finished: %v", msg)
	case <-time.After(100 * time.Millisecond):
	}

	handshake.finish("task-running")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ready := stream.next(t).GetFinalReady()
	if ready == nil {
		t.Fatal("the answer is not FinalReady")
	}
	if len(ready.GetRunningTasks()) != 0 || !ready.GetLeasesDropped() {
		t.Fatalf("FinalReady = %+v", ready)
	}
}

// TestFinalTaskReportsWhatIsStillRunningAfterTheGrace guards that a task
// which outlives the grace is neither interrupted nor hidden: the panel
// hears its identifier.
func TestFinalTaskReportsWhatIsStillRunningAfterTheGrace(t *testing.T) {
	handshake := newFinalHandshake()
	stream := newFakeStream()
	handshake.start("task-slow")

	if err := answerFinalTask(context.Background(),
		&agentv1.FinalTask{Reason: "handed over", GraceSeconds: 1}, handshake, stream.send, quietLogger()); err != nil {
		t.Fatal(err)
	}
	ready := stream.next(t).GetFinalReady()
	if len(ready.GetRunningTasks()) != 1 || ready.GetRunningTasks()[0] != "task-slow" {
		t.Fatalf("running tasks = %v", ready.GetRunningTasks())
	}
	if !ready.GetLeasesDropped() {
		t.Fatal("the leases were not dropped")
	}
	// A repeated final task is not answered twice.
	if err := answerFinalTask(context.Background(),
		&agentv1.FinalTask{Reason: "again"}, handshake, stream.send, quietLogger()); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-stream.seen:
		t.Fatalf("a repeated final task was answered: %v", msg)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestFinalCommitWipesThroughTheHelperAndEndsTheAgent guards the second
// step: the wipe goes to the helper, and a wipe that went through ends the
// agent with the decommission as the reason.
func TestFinalCommitWipesThroughTheHelperAndEndsTheAgent(t *testing.T) {
	handshake := newFinalHandshake()
	handshake.begin("handed over")

	var reasons []string
	wipe := func(_ context.Context, reason string) (*helperv1.HelperResponse, error) {
		reasons = append(reasons, reason)
		return &helperv1.HelperResponse{Accepted: true, FinalWipeResult: &helperv1.FinalWipeResult{
			Removed: []string{"/var/lib/flotestro-agent/identity"}, ServiceDisabled: true,
		}}, nil
	}
	err := applyFinalCommit(context.Background(),
		&agentv1.FinalCommit{LocalIdentityWipe: true, Reason: "handed over"}, handshake, wipe, quietLogger())
	if !errors.Is(err, ErrDecommissioned) {
		t.Fatalf("err = %v, expected ErrDecommissioned", err)
	}
	if len(reasons) != 1 || reasons[0] != "handed over" {
		t.Fatalf("the helper was called with %v", reasons)
	}
	if !handshake.done.Load() {
		t.Fatal("the handshake is not marked as done")
	}
}

// TestFinalCommitRefusedByTheHelperKeepsTheAgentRunning guards the promise
// of the commit: an agent that could not wipe itself says so and stays,
// rather than leaving with its identity on the disk and nobody the wiser.
func TestFinalCommitRefusedByTheHelperKeepsTheAgentRunning(t *testing.T) {
	handshake := newFinalHandshake()
	handshake.begin("handed over")

	refusing := func(context.Context, string) (*helperv1.HelperResponse, error) {
		return &helperv1.HelperResponse{Accepted: false, ErrorCode: "exec_failed", Message: "no"}, nil
	}
	if err := applyFinalCommit(context.Background(),
		&agentv1.FinalCommit{LocalIdentityWipe: true}, handshake, refusing, quietLogger()); err != nil {
		t.Fatalf("a refused wipe ended the agent: %v", err)
	}
	unreachable := func(context.Context, string) (*helperv1.HelperResponse, error) {
		return nil, errors.New("connecting to the helper: no such file")
	}
	if err := applyFinalCommit(context.Background(),
		&agentv1.FinalCommit{LocalIdentityWipe: true}, handshake, unreachable, quietLogger()); err != nil {
		t.Fatalf("an unreachable helper ended the agent: %v", err)
	}
	if err := applyFinalCommit(context.Background(),
		&agentv1.FinalCommit{LocalIdentityWipe: true}, handshake, nil, quietLogger()); err != nil {
		t.Fatalf("a missing helper ended the agent: %v", err)
	}
	if handshake.done.Load() {
		t.Fatal("the handshake is marked as done after a refusal")
	}
}

// TestFinalCommitWithoutAWipeOnlyEndsTheAgent guards the order without a
// local wipe: nothing touches the helper, the agent ends.
func TestFinalCommitWithoutAWipeOnlyEndsTheAgent(t *testing.T) {
	handshake := newFinalHandshake()
	handshake.begin("handed over")
	called := false
	wipe := func(context.Context, string) (*helperv1.HelperResponse, error) {
		called = true
		return &helperv1.HelperResponse{Accepted: true}, nil
	}
	err := applyFinalCommit(context.Background(),
		&agentv1.FinalCommit{LocalIdentityWipe: false}, handshake, wipe, quietLogger())
	if !errors.Is(err, ErrDecommissioned) || called {
		t.Fatalf("err = %v, helper called = %v", err, called)
	}
}

// TestFinalCommitWithoutAFinalTaskIsIgnored guards against a commit that
// arrives on its own: it is not the handshake and nothing is wiped on it.
func TestFinalCommitWithoutAFinalTaskIsIgnored(t *testing.T) {
	handshake := newFinalHandshake()
	called := false
	wipe := func(context.Context, string) (*helperv1.HelperResponse, error) {
		called = true
		return &helperv1.HelperResponse{Accepted: true}, nil
	}
	if err := applyFinalCommit(context.Background(),
		&agentv1.FinalCommit{LocalIdentityWipe: true}, handshake, wipe, quietLogger()); err != nil || called {
		t.Fatalf("err = %v, helper called = %v", err, called)
	}
}
