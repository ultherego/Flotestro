package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/modules/logs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The limits of the live preview.
const (
	// maxPreviewRate limits the amount of data per second.
	maxPreviewRate = 32 << 10
	// batchInterval collects the lines before sending them. Sending each of them
	// separately would cost one notification per journal line.
	batchInterval = 250 * time.Millisecond
	// maxBatch limits a single message. A notification in the database has its
	// own size limit, so a batch has to fit in it with room to spare.
	maxBatch = 6 << 10
	// defaultPreviewTime applies when the operator gives none of their own.
	defaultPreviewTime = 5 * time.Minute
	// defaultBacklog applies when the request names no past of its own.
	defaultBacklog = 50
	// maxBacklog bounds the past a live view opens with. More than this is
	// refused, not trimmed: a view that answers a different question than the
	// one asked has to say so.
	maxBacklog = 500
)

// cancellations holds the functions that interrupt the tasks which can be
// interrupted safely.
type cancellations struct {
	mu      sync.Mutex
	actions map[string]context.CancelFunc
}

func newCancellationTable() *cancellations {
	return &cancellations{actions: map[string]context.CancelFunc{}}
}

func (c *cancellations) register(taskID string, cancel context.CancelFunc) func() {
	c.mu.Lock()
	c.actions[taskID] = cancel
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.actions, taskID)
		c.mu.Unlock()
	}
}

// Cancel interrupts a task if it can be interrupted.
func (c *cancellations) Cancel(taskID string) bool {
	c.mu.Lock()
	cancel, known := c.actions[taskID]
	c.mu.Unlock()
	if known {
		cancel()
	}
	return known
}

// followJournal streams the journal to the control plane.
func (e *TaskExecutor) followJournal(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.JournalPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "the preview payload is missing")
	}
	if e.logLines == nil {
		// Without a receiver the preview makes no sense and there is no reason to
		// start a process on the host.
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectUnsupported,
			"the agent has no open session to pass the preview through")
	}

	duration := time.Duration(payload.FollowSeconds) * time.Second
	if duration <= 0 || duration > 15*time.Minute {
		duration = defaultPreviewTime
	}
	followCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	// The operator can close the preview earlier. Cancelling a read breaks
	// nothing, so here it is carried out and not only recorded.
	if e.cancels != nil {
		defer e.cancels.register(task.GetTaskId(), cancel)()
	}

	args, err := previewArguments(payload)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, err.Error())
	}
	cmd := exec.CommandContext(followCtx, journalctlPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	if err := cmd.Start(); err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}

	sent, dropped, suppressed := e.forwardLines(followCtx, task.GetTaskId(), stdout)
	_ = cmd.Wait()

	host := hostSuppression{messages: uint32(suppressed), unknown: suppressionHiddenBy(payload)}
	// The end of the preview is a success: the stream was meant to end.
	summary, err := json.Marshal(newFollowSummary(sent, dropped, host, duration))
	if err != nil {
		summary = nil
	}
	return &agentv1.TaskResult{
		TaskId:  task.GetTaskId(),
		Status:  agentv1.TaskResult_STATUS_SUCCEEDED,
		Message: previewSummary(sent, dropped, host),
		Stdout:  summary,
	}
}

// followSummary is what a live view leaves behind once it has ended: how much
// of the journal reached the panel, how much the view could not carry and how
// much the host never recorded.
type followSummary struct {
	Kind         string `json:"kind"`
	LinesSent    uint32 `json:"lines_sent"`
	LinesDropped uint32 `json:"lines_dropped"`
	// HostSuppressed counts what journald dropped at the source. It is absent,
	// never zero, when the view could not have seen journald's notice: a zero
	// here would read as a quiet host.
	HostSuppressed *uint32 `json:"host_suppressed,omitempty"`
	// HostSuppressedUnknownReason says why the count is absent.
	HostSuppressedUnknownReason string `json:"host_suppressed_unknown_reason,omitempty"`
	Seconds                     uint32 `json:"follow_seconds"`
}

// hostSuppression is what the host says it never recorded, or the reason that
// number could not be read at all.
type hostSuppression struct {
	messages uint32
	// unknown names the filter that hid journald's notice; empty when the
	// count stands for the whole view.
	unknown string
}

// suppressionHiddenBy names the filter of the view that keeps journald's
// rate-limit notice out of it. The notice is written at priority info, so a
// stricter priority drops it and the count cannot be read from this view.
func suppressionHiddenBy(payload *opspec.JournalPayload) string {
	if priority := payload.MaxPriority; priority != nil && *priority < logs.SuppressionNoticePriority {
		return "priority_filter"
	}
	return ""
}

// suppressionReasonText spells a reason for the operator, who reads the
// message and not the code beside it.
func suppressionReasonText(reason string) string {
	if reason == "priority_filter" {
		return "the priority filter hides journald's own notice"
	}
	return "the filters of the view hide journald's own notice"
}

// newFollowSummary builds what the panel reads after the view: a count the
// panel can trust, or a reason in its place.
func newFollowSummary(sent, dropped int, host hostSuppression, duration time.Duration) followSummary {
	summary := followSummary{
		Kind:         "journal_follow",
		LinesSent:    uint32(sent),
		LinesDropped: uint32(dropped),
		Seconds:      uint32(duration.Seconds()),
	}
	if host.unknown != "" {
		summary.HostSuppressedUnknownReason = host.unknown
		return summary
	}
	counted := host.messages
	summary.HostSuppressed = &counted
	return summary
}

// forwardLines reads the output and sends it in batches at a limited rate.
// What journald suppressed at the source is counted apart from what the view
// could not carry: one is a gap in the host's journal, the other in the view.
func (e *TaskExecutor) forwardLines(ctx context.Context, taskID string,
	output interface{ Read([]byte) (int, error) }) (sent, dropped, suppressed int) {
	lines := make(chan string, 256)
	var overflow atomic.Uint64
	var suppressedByHost atomic.Uint64
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 0, 16<<10), 256<<10)
		for scanner.Scan() {
			line := scanner.Text()
			// The notice is counted as it is read, before the view decides whether
			// it can carry it: a dropped notice is still a fact about the host.
			if messages, notice := logs.SuppressedMessages(line); notice {
				suppressedByHost.Add(uint64(messages))
			}
			select {
			case lines <- line:
			default:
				// A full channel means the host produces faster than we manage to send.
				// The line is lost, but the number of lost ones travels on.
				overflow.Add(1)
			}
		}
	}()

	rate := newRateBudget(maxPreviewRate)
	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	batch := make([]string, 0, 32)
	size := 0
	droppedInBatch := 0

	flush := func() {
		// The lines the reader lost since the last batch belong to this one: a
		// number that waits for the end of the view is a gap the operator reads as a
		// quiet host.
		droppedInBatch += int(overflow.Swap(0))
		if len(batch) == 0 && droppedInBatch == 0 {
			return
		}
		e.logLines(&agentv1.TaskLogLines{
			TaskId:  taskID,
			Lines:   append([]string(nil), batch...),
			Dropped: uint32(droppedInBatch),
		})
		sent += len(batch)
		dropped += droppedInBatch
		batch = batch[:0]
		size = 0
		droppedInBatch = 0
	}

	finish := func() (int, int, int) {
		flush()
		return sent, dropped, int(suppressedByHost.Load())
	}

	for {
		select {
		case <-ctx.Done():
			return finish()
		case <-ticker.C:
			flush()
		case line, open := <-lines:
			if !open {
				return finish()
			}
			if !rate.allows(len(line) + 1) {
				droppedInBatch++
				continue
			}
			batch = append(batch, line)
			size += len(line) + 1
			if size >= maxBatch {
				flush()
			}
		}
	}
}

// rateBudget limits the amount of data per second.
type rateBudget struct {
	perSecond int
	available int
	last      time.Time
}

func newRateBudget(perSecond int) *rateBudget {
	return &rateBudget{perSecond: perSecond, available: perSecond, last: time.Now()}
}

func (b *rateBudget) allows(bytes int) bool {
	now := time.Now()
	elapsed := now.Sub(b.last)
	b.last = now
	b.available += int(float64(b.perSecond) * elapsed.Seconds())
	if b.available > b.perSecond {
		b.available = b.perSecond
	}
	if b.available < bytes {
		return false
	}
	b.available -= bytes
	return true
}

// previewArguments assembles the invocation from typed fields, never from a
// concatenated string.
func previewArguments(payload *opspec.JournalPayload) ([]string, error) {
	args := []string{"--follow", "--no-pager", "--output=short-iso"}
	backlog := payload.Lines
	if backlog > maxBacklog {
		return nil, fmt.Errorf("a live view opens with at most %d lines of the past, %d were asked for",
			maxBacklog, backlog)
	}
	if backlog == 0 {
		backlog = defaultBacklog
	}
	args = append(args, "--lines", number(backlog))
	filters, err := journalFilters(payload)
	if err != nil {
		return nil, err
	}
	return append(args, filters...), nil
}

func previewSummary(sent, dropped int, host hostSuppression) string {
	text := "the preview ended, lines: " + number(uint32(sent))
	if dropped > 0 {
		text += ", lines the view could not carry: " + number(uint32(dropped))
	}
	switch {
	case host.unknown != "":
		text += ", messages the host never recorded: unknown, " + suppressionReasonText(host.unknown)
	case host.messages > 0:
		text += ", messages the host never recorded: " + number(host.messages)
	}
	return text
}

// number turns a counter into the text of an argument.
func number(value uint32) string {
	return strconv.FormatUint(uint64(value), 10)
}
