package agent

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/opspec"
)

// The rate limit protects the link and the notification database from a host
// printing megabytes of logs. Without it one host in an error loop would flood
// the panel.
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
	args := previewArguments(&opspec.JournalPayload{
		Unit: "cron.service", Lines: 0, MaxPriority: &priority,
	})

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
	if !has("cron.service") || !has("3") {
		t.Errorf("the filters did not reach the arguments: %v", args)
	}
}
