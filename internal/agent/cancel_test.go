package agent

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// The answer to a cancel follows the phase the task is in, and nothing
// else: before the start the task is refused and never starts; a read
// with a registered interruption is interrupted; a mutation runs to its
// end; a task that ended is already done, with the digest of its result.
func TestACancelIsAnsweredByThePhaseOfTheTask(t *testing.T) {
	executor := &TaskExecutor{
		log: slog.Default(), cancels: newCancellationTable(), phases: newTaskPhases(), running: newRunningKeys(),
	}
	_, stop := context.WithCancel(context.Background())
	defer stop()

	// Delivered, in its checks.
	stopped := false
	if executor.phases.enter("t-accepted", "k1", func() { stopped = true }) {
		t.Fatal("a fresh delivery was refused")
	}
	outcome, phase, _, interrupt := executor.CancelTask("t-accepted")
	if outcome != agentv1.CancelAck_NOT_STARTED || phase != PhaseAccepted || interrupt == nil {
		t.Fatalf("a task in its checks was answered %s in %q with interrupt %v", outcome, phase, interrupt != nil)
	}
	interrupt()
	if !stopped || !executor.phases.canceledBeforeStart("t-accepted") {
		t.Fatal("the cancel before the start did not stop the task's context or mark it canceled")
	}

	// Waiting for a lock.
	executor.phases.enter("t-lock", "k2", stop)
	executor.phases.move("t-lock", PhaseAwaitingLock)
	if outcome, phase, _, _ := executor.CancelTask("t-lock"); outcome != agentv1.CancelAck_NOT_STARTED || phase != PhaseAwaitingLock {
		t.Fatalf("a task waiting for a lock was answered %s in %q", outcome, phase)
	}

	// A read under way with an interruption registered by its module.
	executor.phases.enter("t-read", "k3", stop)
	executor.phases.move("t-read", PhaseStarted)
	interrupted := false
	release := executor.cancels.register("t-read", func() { interrupted = true })
	defer release()
	outcome, phase, _, interrupt = executor.CancelTask("t-read")
	if outcome != agentv1.CancelAck_INTERRUPTED || phase != PhaseStarted || interrupt == nil {
		t.Fatalf("a preview under way was answered %s in %q", outcome, phase)
	}
	if interrupted {
		t.Fatal("the preview was interrupted before the acknowledgement could go out")
	}
	interrupt()
	if !interrupted {
		t.Fatal("the interruption returned for the preview did nothing")
	}

	// A read under way that registered nothing runs to its (short) end.
	executor.phases.enter("t-plainread", "k4", stop)
	executor.phases.move("t-plainread", PhaseStarted)
	if outcome, _, _, interrupt := executor.CancelTask("t-plainread"); outcome != agentv1.CancelAck_NOT_INTERRUPTIBLE || interrupt != nil {
		t.Fatalf("a read without an interruption was answered %s", outcome)
	}

	// A mutation under way: the helper runs the transaction to its end.
	executor.phases.enter("t-mutation", "k5", stop)
	executor.phases.move("t-mutation", PhaseMutating)
	if outcome, phase, _, interrupt := executor.CancelTask("t-mutation"); outcome != agentv1.CancelAck_NOT_INTERRUPTIBLE || phase != PhaseMutating || interrupt != nil {
		t.Fatalf("a mutation under way was answered %s in %q with interrupt %v", outcome, phase, interrupt != nil)
	}
	if executor.phases.canceledBeforeStart("t-mutation") {
		t.Fatal("a cancel of a mutation under way marked it as canceled before the start")
	}

	// A task that ended: already done, with the digest of the result.
	result := &agentv1.TaskResult{TaskId: "t-done", IdempotencyKey: "k6", Status: agentv1.TaskResult_STATUS_SUCCEEDED, Message: "done"}
	executor.phases.enter("t-done", "k6", stop)
	executor.phases.finish("t-done", result)
	outcome, phase, hash, _ := executor.CancelTask("t-done")
	if outcome != agentv1.CancelAck_ALREADY_DONE || phase != PhaseDone {
		t.Fatalf("a finished task was answered %s in %q", outcome, phase)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(encoded)
	if string(hash) != string(expected[:]) {
		t.Fatal("the digest of the result is not the SHA-256 of its deterministic encoding")
	}

	// A task the previous process left in flight: nothing to interrupt,
	// nothing to promise.
	executor.phases.seed("t-restart", "k7")
	if outcome, phase, _, _ := executor.CancelTask("t-restart"); outcome != agentv1.CancelAck_NOT_INTERRUPTIBLE || phase != PhaseInFlightBeforeRestart {
		t.Fatalf("a task in flight before the restart was answered %s in %q", outcome, phase)
	}
}

// A cancel that names a task the process was never handed is answered as
// not started and remembered: the delivery, should it still arrive, is
// refused without running. A cancel that names a redelivered attempt of
// an operation under way is answered about the execution behind it.
func TestACancelBeforeTheDeliveryRefusesTheDelivery(t *testing.T) {
	executor := &TaskExecutor{
		log: slog.Default(), cancels: newCancellationTable(), phases: newTaskPhases(), running: newRunningKeys(),
	}
	outcome, phase, _, interrupt := executor.CancelTask("t-early")
	if outcome != agentv1.CancelAck_NOT_STARTED || phase != PhaseNotDelivered || interrupt != nil {
		t.Fatalf("an undelivered task was answered %s in %q", outcome, phase)
	}
	if !executor.phases.enter("t-early", "k1", func() {}) {
		t.Fatal("the delivery that followed the cancel was not refused")
	}
	if executor.phases.enter("t-early", "k1", func() {}) {
		t.Fatal("the refusal outlived the delivery it was for")
	}

	// The redelivered attempt of a running execution.
	executor.running.claim("k-running", "t-first", time.Now())
	executor.running.redeliver("k-running", "t-second")
	executor.phases.enter("t-first", "k-running", func() {})
	executor.phases.move("t-first", PhaseMutating)
	if outcome, _, _, _ := executor.CancelTask("t-second"); outcome != agentv1.CancelAck_NOT_INTERRUPTIBLE {
		t.Fatalf("a cancel of the redelivered attempt was answered %s, not about the execution behind it", outcome)
	}

	// An executor without a record - the simulator - answers, and does
	// not crash.
	var none *TaskExecutor
	if outcome, _, _, _ := none.CancelTask("t-any"); outcome != agentv1.CancelAck_NOT_STARTED {
		t.Fatalf("an agent without an executor answered %s", outcome)
	}
}
