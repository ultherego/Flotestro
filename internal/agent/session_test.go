package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// TestAPanicInATaskDoesNotKillTheAgent guards the resilience barrier. An error
// while handling one operation must not take the management of the host away:
// the control plane would then see a broken session instead of information
// about what went wrong.
func TestAPanicInATaskDoesNotKillTheAgent(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	task := &agentv1.TaskEnvelope{TaskId: "task-1"}

	// An executor with an empty journal panics at the first reference.
	empty := &TaskExecutor{log: log}
	result := executeTask(context.Background(), empty, task, log)
	if result == nil {
		t.Fatal("no result after the panic")
	}
	if result.GetStatus() != agentv1.TaskResult_STATUS_FAILED {
		t.Errorf("status = %s, expected FAILED", result.GetStatus())
	}
	if result.GetErrorCode() != RejectInternalError {
		t.Errorf("error code = %q", result.GetErrorCode())
	}
	if result.GetTaskId() != "task-1" {
		t.Errorf("the result does not point at the attempt: %q", result.GetTaskId())
	}
}

// TestAnAgentWithoutAnExecutorRefusesATask checks an agent that by design
// performs no operations. A refusal is an answer, not a failure.
func TestAnAgentWithoutAnExecutorRefusesATask(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	result := executeTask(context.Background(), nil,
		&agentv1.TaskEnvelope{TaskId: "task-2"}, log)

	if result.GetStatus() != agentv1.TaskResult_STATUS_REJECTED {
		t.Errorf("status = %s, expected REJECTED", result.GetStatus())
	}
	if result.GetErrorCode() != RejectUnsupported {
		t.Errorf("error code = %q, expected %q", result.GetErrorCode(), RejectUnsupported)
	}
}
