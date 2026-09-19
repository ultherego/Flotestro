package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The rate limit protects the link and the notification database from a host
// printing megabytes of logs.
func TestTheRateBudgetLimitsTheFlow(t *testing.T) {
	budget := newRateBudget(100)

	if !budget.allows(80) {
		t.Fatal("the first 80 bytes did not fit in a budget of 100")
	}
	if !budget.allows(20) {
		t.Fatal("the next 20 bytes did not fit in the budget")
	}
	if budget.allows(50) {
		t.Error("the budget let data through above the limit")
	}
}

// The budget refills over time: the preview is to keep working and not close
// after the first burst of logs.
func TestTheRateBudgetRefills(t *testing.T) {
	budget := newRateBudget(1000)
	if !budget.allows(1000) {
		t.Fatal("the budget did not let a full second of data through")
	}
	if budget.allows(500) {
		t.Fatal("the budget let data through above the limit")
	}

	// After half a second half of the budget comes back.
	budget.last = budget.last.Add(-500 * time.Millisecond)
	if !budget.allows(400) {
		t.Error("the budget did not refill as time passed")
	}
}

// The budget must not grow without end during silence: a host quiet for an hour
// does not get the right to send an hour of logs at once.
func TestTheRateBudgetDoesNotAccumulateWithoutEnd(t *testing.T) {
	budget := newRateBudget(100)
	budget.last = budget.last.Add(-time.Hour)
	if !budget.allows(100) {
		t.Fatal("the budget did not let a full second of data through")
	}
	if budget.allows(100) {
		t.Error("the budget accumulated above the limit of one second")
	}
}

// Cancellation works where it was declared safe. Cancelling a task that has
// just finished is not an error.
func TestCancellationWorksOnlyForRegisteredTasks(t *testing.T) {
	table := newCancellationTable()
	interrupted := false
	unregister := table.register("task-1", func() { interrupted = true })

	if !table.Cancel("task-1") {
		t.Error("the registered task was not found")
	}
	if !interrupted {
		t.Error("the task was not interrupted")
	}
	if table.Cancel("task-unknown") {
		t.Error("an unknown task was taken for interrupted")
	}

	unregister()
	if table.Cancel("task-1") {
		t.Error("the task was interrupted after it had been unregistered")
	}
}

// The preview arguments are built from typed fields, never from a concatenated
// string.
func TestThePreviewArgumentsHaveLimits(t *testing.T) {
	priority := uint32(3)
	args, err := previewArguments(&opspec.JournalPayload{
		Unit: "cron.service", Lines: 0, MaxPriority: &priority,
	})
	if err != nil {
		t.Fatalf("the arguments were refused: %v", err)
	}

	has := func(value string) bool {
		for _, arg := range args {
			if arg == value {
				return true
			}
		}
		return false
	}
	if !has("--follow") || !has("--lines") {
		t.Errorf("arguments = %v", args)
	}
	// A zero backlog means the default value and not the absence of a limit.
	if !has("50") {
		t.Errorf("the default backlog limit is missing: %v", args)
	}
	if !has("--unit=cron.service") || !has("--priority=3") {
		t.Errorf("the filters did not reach the arguments: %v", args)
	}
}

// A live view takes the narrowing a read takes: the same unit, the same
// priority, the same start of the range and the same boot of the host.
func TestThePreviewTakesTheNarrowingOfARead(t *testing.T) {
	priority := uint32(4)
	args, err := previewArguments(&opspec.JournalPayload{
		Unit: "sshd.service", Lines: 100, MaxPriority: &priority,
		Since: "2026-09-15 10:00:00 UTC", AfterCursor: "s=abc;i=1",
		BootID: "2cd11312-4365-4fe6-b49e-e4d704ea2c5a",
	})
	if err != nil {
		t.Fatalf("the arguments were refused: %v", err)
	}
	line := strings.Join(args, " ")
	for _, want := range []string{
		"--unit=sshd.service", "--priority=4", "--since=2026-09-15 10:00:00 UTC",
		"--after-cursor=s=abc;i=1", "--boot=2cd1131243654fe6b49ee4d704ea2c5a",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the arguments %q do not carry %q", line, want)
		}
	}
	if strings.Contains(line, "--until") {
		t.Errorf("a live view got an end date: %q", line)
	}

	if _, err := previewArguments(&opspec.JournalPayload{Lines: 100, BootID: "the boot of yesterday"}); err == nil {
		t.Error("a boot identifier that is not one passed into the arguments")
	}
}

// What the view could not carry is counted, and it is counted where the
// operator is looking: in the batch that is missing it.
func TestTheDroppedLinesAreCountedInTheBatchAndInTheTotal(t *testing.T) {
	var batches []*agentv1.TaskLogLines
	executor := &TaskExecutor{logLines: func(lines *agentv1.TaskLogLines) {
		batches = append(batches, lines)
	}}

	// The rate budget is far smaller than the text, so the first lines go
	// through and the rest are dropped by the limit.
	long := strings.Repeat("x", 4<<10) + "\n"
	sent, dropped := executor.forwardLines(context.Background(), "task-1",
		strings.NewReader(strings.Repeat(long, 32)))
	if sent == 0 {
		t.Fatal("no line went through")
	}
	if dropped == 0 {
		t.Fatal("the lines above the rate limit were not counted")
	}
	if sent+dropped != 32 {
		t.Errorf("lines sent %d + dropped %d, want 32", sent, dropped)
	}
	var reported int
	for _, batch := range batches {
		reported += int(batch.GetDropped())
	}
	if reported != dropped {
		t.Errorf("the batches report %d dropped lines, the result %d", reported, dropped)
	}
}

// A view that loses nothing says so plainly, and one that does names the
// number: the result is what a panel reads after the view has ended.
func TestThePreviewSummaryNamesTheLostLines(t *testing.T) {
	if summary := previewSummary(12, 0); strings.Contains(summary, "could not carry") {
		t.Errorf("a view that lost nothing reports a loss: %q", summary)
	}
	summary := previewSummary(12, 7)
	if !strings.Contains(summary, "12") || !strings.Contains(summary, "7") {
		t.Errorf("summary = %q, want both numbers in it", summary)
	}
}
