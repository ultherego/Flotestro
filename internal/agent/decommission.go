package agent

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// ErrDecommissioned ends the agent after the final commit of the panel.
var ErrDecommissioned = errors.New("the host was decommissioned by the panel")

// errLeasesDropped is the answer to a secret asked for after the final task.
var errLeasesDropped = errors.New("the host is leaving the fleet; its secret leases were dropped")

// RejectRetiring marks a task delivered after the final task.
const RejectRetiring = "host_retiring"

// defaultFinalGrace is how long the agent waits for the tasks under way
// before it answers the final task anyway, when the panel names no limit.
const defaultFinalGrace = 90 * time.Second

// finalWipeTimeout bounds the call to the helper at the commit.
const finalWipeTimeout = 60 * time.Second

// finalHandshake is the agent's side of the decommission handshake.
type finalHandshake struct {
	mu       sync.Mutex
	leaving  bool
	reason   string
	running  map[string]struct{}
	idle     chan struct{}
	idleOnce sync.Once
	// done is set once the commit went through.
	done atomic.Bool
}

func newFinalHandshake() *finalHandshake {
	return &finalHandshake{running: map[string]struct{}{}, idle: make(chan struct{})}
}

// start registers an attempt about to run. It answers false when the host
// is leaving: the attempt is then refused rather than started.
func (f *finalHandshake) start(taskID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.leaving {
		return false
	}
	f.running[taskID] = struct{}{}
	return true
}

// finish unregisters an attempt. Once the host is leaving and nothing runs,
// the handshake is told so.
func (f *finalHandshake) finish(taskID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.running, taskID)
	f.signalIfIdle()
}

// begin marks the host as leaving. It answers false when the final task was
// already seen: a repeated one changes nothing and is not waited for twice.
func (f *finalHandshake) begin(reason string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.leaving {
		return false
	}
	f.leaving = true
	f.reason = reason
	f.signalIfIdle()
	return true
}

// isLeaving says whether the final task has arrived.
func (f *finalHandshake) isLeaving() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.leaving
}

// runningTasks lists the attempts still under way, in a stable order.
func (f *finalHandshake) runningTasks() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	tasks := make([]string, 0, len(f.running))
	for taskID := range f.running {
		tasks = append(tasks, taskID)
	}
	sort.Strings(tasks)
	return tasks
}

// signalIfIdle closes the idle channel once nothing runs on a leaving host.
// Called with the lock held.
func (f *finalHandshake) signalIfIdle() {
	if f.leaving && len(f.running) == 0 {
		f.idleOnce.Do(func() { close(f.idle) })
	}
}

// wait blocks until the running attempts finish or the grace passes, and
// returns what is still running then.
func (f *finalHandshake) wait(ctx context.Context, grace time.Duration) []string {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-f.idle:
	case <-timer.C:
	case <-ctx.Done():
	}
	return f.runningTasks()
}

// refuseRetiring is the answer to a task delivered after the final task.
func refuseRetiring(taskID string) *agentv1.TaskResult {
	refusal := rejected(agentv1.TaskResult_STATUS_REJECTED, RejectRetiring,
		"the host is leaving the fleet and starts no new operation")
	refusal.TaskId = taskID
	return refusal
}

// answerFinalTask carries the agent's side of the first step out: nothing new
// starts, the secret leases are dropped, the running work gets its grace, and
// FinalReady goes back with what was still running.
func answerFinalTask(ctx context.Context, task *agentv1.FinalTask, handshake *finalHandshake,
	send func(*agentv1.AgentMessage) error, log *slog.Logger) error {
	if !handshake.begin(task.GetReason()) {
		log.Info("a repeated final task; the host is already leaving")
		return nil
	}
	grace := time.Duration(task.GetGraceSeconds()) * time.Second
	if grace <= 0 {
		grace = defaultFinalGrace
	}
	log.Warn("the panel is decommissioning this host; no new operation starts",
		"reason", task.GetReason(), "local_identity_wipe", task.GetLocalIdentityWipe(),
		"running", len(handshake.runningTasks()), "grace", grace.String())

	stillRunning := handshake.wait(ctx, grace)
	if len(stillRunning) > 0 {
		log.Warn("operations were still running when the grace passed; reporting them",
			"task_ids", stillRunning)
	}
	return send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_FinalReady{FinalReady: &agentv1.FinalReady{
			RunningTasks: stillRunning, LeasesDropped: true,
		}},
	})
}

// finalWiper asks the root helper to remove what makes this host a member of
// the fleet.
type finalWiper func(ctx context.Context, commit *agentv1.FinalCommit) (*helperv1.HelperResponse, error)

// helperWiper builds the wiper over the real helper client. The proof travels
// from the commit into the request untouched: the agent does not vouch for the
// wipe, the panel does, and the helper checks it.
func helperWiper(client *HelperClient) finalWiper {
	if client == nil {
		return nil
	}
	return func(ctx context.Context, commit *agentv1.FinalCommit) (*helperv1.HelperResponse, error) {
		taskID := commit.GetTaskId()
		if taskID == "" {
			// A panel from before the proof existed. The helper decides what to
			// make of a wipe without one.
			taskID = "final-wipe"
		}
		return client.Call(ctx, &helperv1.HelperRequest{
			TaskId:              taskID,
			TimeoutSeconds:      uint32(finalWipeTimeout.Seconds()),
			CanonicalPayload:    commit.GetCanonicalPayload(),
			Capability:          commit.GetCapability(),
			CapabilitySignature: commit.GetCapabilitySignature(),
			Action: &helperv1.HelperRequest_FinalWipe{
				FinalWipe: &helperv1.FinalWipeRequest{Reason: commit.GetReason()},
			},
		}, finalWipeTimeout)
	}
}

// applyFinalCommit carries the second step out.
func applyFinalCommit(ctx context.Context, commit *agentv1.FinalCommit, handshake *finalHandshake,
	wipe finalWiper, log *slog.Logger) error {
	if !handshake.isLeaving() {
		// A commit without a final task before it is not the handshake; the panel
		// does not send one, so this is either an old panel or a message meant for
		// somebody else.
		log.Warn("a final commit arrived without a final task; ignored")
		return nil
	}
	if !commit.GetLocalIdentityWipe() {
		log.Warn("the panel committed the decommission without a local wipe; the agent ends",
			"reason", commit.GetReason())
		handshake.done.Store(true)
		return ErrDecommissioned
	}
	if wipe == nil {
		log.Error("the panel committed the decommission, but this agent has no helper to wipe the identity with; " +
			"the agent keeps running with a revoked certificate")
		return nil
	}
	wipeCtx, cancel := context.WithTimeout(ctx, finalWipeTimeout)
	defer cancel()
	response, err := wipe(wipeCtx, commit)
	if err != nil {
		log.Error("the helper did not answer the final wipe; the agent keeps running", "err", err)
		return nil
	}
	if !response.GetAccepted() {
		log.Error("the helper refused the final wipe; the agent keeps running",
			"code", response.GetErrorCode(), "message", response.GetMessage())
		return nil
	}
	result := response.GetFinalWipeResult()
	log.Warn("the identity of this host was wiped; the agent ends",
		"reason", commit.GetReason(), "removed", result.GetRemoved(),
		"service_disabled", result.GetServiceDisabled(), "stop_scheduled", result.GetStopScheduled())
	handshake.done.Store(true)
	return ErrDecommissioned
}
