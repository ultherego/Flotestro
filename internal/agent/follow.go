package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The limits of the live preview.
//
// The preview is the only operation that keeps a process on the host for as
// long as somebody is watching - and for as long as nobody is watching, once
// the operator closes the tab. That is why every dimension of it has an upper
// bound: the duration, the rate and the size of a single batch.
const (
	// maxPreviewRate limits the amount of data per second. A host printing
	// megabytes of logs must not load either the link or the notification
	// database because of it.
	maxPreviewRate = 32 << 10
	// batchInterval collects the lines before sending them. Sending each of them
	// separately would cost one notification per journal line.
	batchInterval = 250 * time.Millisecond
	// maxBatch limits a single message. A notification in the database has its
	// own size limit, so a batch has to fit in it with room to spare.
	maxBatch = 6 << 10
	// defaultPreviewTime applies when the operator gives none of their own.
	defaultPreviewTime = 5 * time.Minute
)

// cancellations holds the functions that interrupt the tasks which can be
// interrupted safely. Not every system operation is one of those - a package
// transaction must not be cut in half - but a journal preview is a read and
// interrupting it breaks nothing.
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

// Cancel interrupts a task if it can be interrupted. It returns whether there
// was anything to interrupt - cancelling an unknown task is not an error,
// because it may have just finished.
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

	sent, dropped := e.forwardLines(followCtx, task.GetTaskId(), stdout)
	_ = cmd.Wait()

	// The end of the preview is a success: the stream was meant to end. The
	// result says how many lines went through and how many were dropped, because
	// a silent loss would make the operator believe they saw everything. The
	// same two numbers travel as a document on stdout, so a panel reading the
	// job afterwards finds them where every other counted answer is.
	summary, err := json.Marshal(followSummary{
		Kind:         "journal_follow",
		LinesSent:    uint32(sent),
		LinesDropped: uint32(dropped),
		Seconds:      uint32(duration.Seconds()),
	})
	if err != nil {
		summary = nil
	}
	return &agentv1.TaskResult{
		TaskId:  task.GetTaskId(),
		Status:  agentv1.TaskResult_STATUS_SUCCEEDED,
		Message: previewSummary(sent, dropped),
		Stdout:  summary,
	}
}

// followSummary is what a live view leaves behind once it has ended: how
// much of the journal reached the panel and how much the view could not
// carry. The count is part of the answer, not a note in a message: a gap
// nobody names reads as a quiet host.
type followSummary struct {
	Kind         string `json:"kind"`
	LinesSent    uint32 `json:"lines_sent"`
	LinesDropped uint32 `json:"lines_dropped"`
	Seconds      uint32 `json:"follow_seconds"`
}

// forwardLines reads the output and sends it in batches at a limited rate.
//
// Two things take a line away: the reader outrunning the sender, which
// fills the channel, and the rate limit. Both are counted and both travel
// in the batch they belong to, so the operator sees the gap while they are
// watching and not only in the result. The reader counts in an atomic: it
// runs in a goroutine of its own and its number is read here while it is
// still reading.
func (e *TaskExecutor) forwardLines(ctx context.Context, taskID string,
	output interface{ Read([]byte) (int, error) }) (sent, dropped int) {
	lines := make(chan string, 256)
	var overflow atomic.Uint64
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 0, 16<<10), 256<<10)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			default:
				// A full channel means the host produces faster than we manage
				// to send. The line is lost, but the number of lost ones travels
				// on.
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
		// The lines the reader lost since the last batch belong to this one:
		// a number that waits for the end of the view is a gap the operator
		// reads as a quiet host.
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

	for {
		select {
		case <-ctx.Done():
			flush()
			return sent, dropped
		case <-ticker.C:
			flush()
		case line, open := <-lines:
			if !open {
				flush()
				return sent, dropped
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
//
// The backlog and the "--follow" belong to a live view alone; everything
// that narrows it - the unit, the priority, the start of the range, the
// cursor, the boot - is the narrowing of a read, built by one function for
// both, because watching a unit and reading it are the same question asked
// twice.
func previewArguments(payload *opspec.JournalPayload) ([]string, error) {
	args := []string{"--follow", "--no-pager", "--output=short-iso"}
	backlog := payload.Lines
	if backlog == 0 || backlog > 500 {
		backlog = 50
	}
	args = append(args, "--lines", number(backlog))
	filters, err := journalFilters(payload)
	if err != nil {
		return nil, err
	}
	return append(args, filters...), nil
}

func previewSummary(sent, dropped int) string {
	if dropped == 0 {
		return "the preview ended, lines: " + number(uint32(sent))
	}
	return "the preview ended, lines: " + number(uint32(sent)) +
		", lines the view could not carry: " + number(uint32(dropped))
}

// number turns a counter into the text of an argument.
func number(value uint32) string {
	return strconv.FormatUint(uint64(value), 10)
}
