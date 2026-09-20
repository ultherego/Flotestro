package agent

import (
	"context"
	"encoding/json"
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
	sent, dropped, _ := executor.forwardLines(context.Background(), "task-1",
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
	if summary := previewSummary(12, 0, hostSuppression{}); strings.Contains(summary, "could not carry") {
		t.Errorf("a view that lost nothing reports a loss: %q", summary)
	}
	summary := previewSummary(12, 7, hostSuppression{})
	if !strings.Contains(summary, "12") || !strings.Contains(summary, "7") {
		t.Errorf("summary = %q, want both numbers in it", summary)
	}
}

// What the host silenced is a different fact from what the view could not
// carry, so the summary names the two apart.
func TestThePreviewSummaryKeepsTheHostGapApartFromTheViewGap(t *testing.T) {
	summary := previewSummary(12, 7, hostSuppression{messages: 4213})
	if !strings.Contains(summary, "lines the view could not carry: 7") ||
		!strings.Contains(summary, "messages the host never recorded: 4213") {
		t.Errorf("summary = %q, want both gaps named apart", summary)
	}
	quiet := previewSummary(12, 0, hostSuppression{})
	if strings.Contains(quiet, "never recorded") {
		t.Errorf("a host that suppressed nothing is spoken of: %q", quiet)
	}
	// A filter that hides journald's notice makes the number unknown, and
	// unknown is said out loud rather than shown as a zero.
	hidden := previewSummary(12, 0, hostSuppression{unknown: "priority_filter"})
	if !strings.Contains(hidden, "unknown") || strings.Contains(hidden, "never recorded: 0") {
		t.Errorf("summary = %q, want the unknown count named", hidden)
	}
}

// journald counts what it dropped at the source; the agent reads that count
// and leaves the notice in the stream where the operator can see it.
func TestTheSuppressionOfJournaldIsCountedApartFromTheDroppedLines(t *testing.T) {
	var batches []*agentv1.TaskLogLines
	executor := &TaskExecutor{logLines: func(lines *agentv1.TaskLogLines) {
		batches = append(batches, lines)
	}}

	const notice = "2026-09-20T12:00:03+0200 web-1 systemd-journald[412]: Suppressed 4213 messages from unit-x.service"
	stream := "2026-09-20T12:00:01+0200 web-1 unit-x[900]: work\n" + notice + "\n"
	sent, dropped, suppressed := executor.forwardLines(context.Background(), "task-1",
		strings.NewReader(stream))
	if sent != 2 || dropped != 0 {
		t.Fatalf("lines sent %d, dropped %d, want 2 and 0", sent, dropped)
	}
	if suppressed != 4213 {
		t.Errorf("the host suppressed %d messages, want 4213", suppressed)
	}
	var carried int
	for _, batch := range batches {
		carried += len(batch.GetLines())
		if batch.GetDropped() != 0 {
			t.Errorf("what the host silenced was counted as a line the view lost: %v", batch)
		}
	}
	if carried != 2 {
		t.Errorf("the batches carry %d lines, want both of them", carried)
	}
}

// The notice is written at priority info. A view filtered below it never sees
// the notice, so the count is unknown there and must not travel as a zero.
func TestTheSuppressionCountIsUnknownWhenTheFilterHidesTheNotice(t *testing.T) {
	strict := uint32(3)
	if reason := suppressionHiddenBy(&opspec.JournalPayload{MaxPriority: &strict}); reason != "priority_filter" {
		t.Errorf("reason = %q, want priority_filter", reason)
	}
	debug := uint32(7)
	if reason := suppressionHiddenBy(&opspec.JournalPayload{MaxPriority: &debug}); reason != "" {
		t.Errorf("a view that sees the notice reports %q", reason)
	}
	if reason := suppressionHiddenBy(&opspec.JournalPayload{}); reason != "" {
		t.Errorf("a view without a priority filter reports %q", reason)
	}
}

// An unknown count leaves the field out of the summary. An agent one release
// behind leaves it out too, and both mean the same thing to the panel: not a
// quiet host, but a number nobody could read.
func TestAnUnknownSuppressionCountLeavesTheFieldOutOfTheSummary(t *testing.T) {
	hidden, err := json.Marshal(newFollowSummary(12, 0,
		hostSuppression{unknown: "priority_filter"}, 5*time.Minute))
	if err != nil {
		t.Fatalf("the summary was not written: %v", err)
	}
	if strings.Contains(string(hidden), "\"host_suppressed\"") {
		t.Errorf("summary = %s, want no count where none could be read", hidden)
	}
	if !strings.Contains(string(hidden), "\"host_suppressed_unknown_reason\":\"priority_filter\"") {
		t.Errorf("summary = %s, want the reason in place of the count", hidden)
	}

	// A view that could see the notice and saw none reports a real zero.
	seen, err := json.Marshal(newFollowSummary(12, 0, hostSuppression{}, 5*time.Minute))
	if err != nil {
		t.Fatalf("the summary was not written: %v", err)
	}
	if !strings.Contains(string(seen), "\"host_suppressed\":0") {
		t.Errorf("summary = %s, want the zero the view really observed", seen)
	}
}

// A backlog larger than the limit is refused. Trimming it in silence would
// answer a question the operator did not ask.
func TestABacklogAboveTheLimitIsRefusedAndNotTrimmed(t *testing.T) {
	if _, err := previewArguments(&opspec.JournalPayload{Lines: maxBacklog + 1}); err == nil {
		t.Error("a backlog above the limit passed into the arguments")
	}
	args, err := previewArguments(&opspec.JournalPayload{Lines: maxBacklog})
	if err != nil {
		t.Fatalf("the backlog at the limit was refused: %v", err)
	}
	if !strings.Contains(strings.Join(args, " "), "--lines 500") {
		t.Errorf("arguments = %v, want the backlog that was asked for", args)
	}
}
