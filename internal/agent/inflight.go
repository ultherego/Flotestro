package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// InFlight is the record of a mutation the host has been told to carry out and
// has not reported on yet.
type InFlight struct {
	IdempotencyKey string    `json:"idempotency_key"`
	TaskID         string    `json:"task_id"`
	Action         string    `json:"action"`
	StartedAt      time.Time `json:"started_at"`
	// PlanHash names the approved plan the operation was carrying out, as a hex
	// digest.
	PlanHash string `json:"plan_hash,omitempty"`
}

// PackageStateProbe reads what the package adapter can say about the host
// without root and without running a transaction.
type PackageStateProbe func(ctx context.Context) *agentv1.PackageApplyResult

// runningKeys is the set of idempotency keys inside Execute right now.
type runningKeys struct {
	mu   sync.Mutex
	keys map[string]*execution
	// followUps holds, by the attempt that finished, the attempt its result is
	// also owed to.
	followUps map[string]string
}

// execution is one operation under way: the attempt that started it and
// the newest attempt delivered for the same key since.
type execution struct {
	taskID    string
	startedAt time.Time
	latest    string
}

// origin returns the attempt that is doing the work behind a task id: the id
// itself when it is the running one, the running one when the id is a
// redelivery of it, and "" when nothing is under way for it.
func (r *runningKeys) origin(taskID string) string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.keys {
		if x.taskID == taskID || x.latest == taskID {
			return x.taskID
		}
	}
	return ""
}

func newRunningKeys() *runningKeys {
	return &runningKeys{keys: map[string]*execution{}, followUps: map[string]string{}}
}

// claim takes the key for the duration of one Execute. An empty key is not
// tracked: it cannot be redelivered under the same name either.
func (r *runningKeys) claim(key, taskID string, started time.Time) (execution, bool) {
	// A nil set belongs to an executor assembled by hand in a test; it has
	// no session to redeliver anything.
	if r == nil || key == "" {
		return execution{}, true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if current, busy := r.keys[key]; busy {
		current.note(taskID)
		return *current, false
	}
	r.keys[key] = &execution{taskID: taskID, startedAt: started}
	return execution{}, true
}

// redeliver records a delivery of a key that is running and returns the
// execution it waits on.
func (r *runningKeys) redeliver(key, taskID string) (execution, bool) {
	if r == nil || key == "" {
		return execution{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, busy := r.keys[key]
	if !busy {
		return execution{}, false
	}
	current.note(taskID)
	return *current, true
}

// note remembers the newest attempt delivered for the execution.
func (x *execution) note(taskID string) {
	if taskID != "" && taskID != x.taskID {
		x.latest = taskID
	}
}

// release ends the execution of a key.
func (r *runningKeys) release(key string) {
	if r == nil || key == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, busy := r.keys[key]
	if !busy {
		return
	}
	delete(r.keys, key)
	if current.latest != "" {
		r.followUps[current.taskID] = current.latest
	}
}

// followUp takes the attempt owed a copy of the result of the given
// attempt. Empty means nobody: no redelivery arrived while it ran.
func (r *runningKeys) followUp(taskID string) string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	latest, owed := r.followUps[taskID]
	if owed {
		delete(r.followUps, taskID)
	}
	return latest
}

// markInFlight writes the marker for a mutation about to start.
func (e *TaskExecutor) markInFlight(task *agentv1.TaskEnvelope, action opspec.ActionType,
	payload opspec.Payload, started time.Time) error {
	key := task.GetIdempotencyKey()
	if key == "" || !action.Mutating() {
		return nil
	}
	planHash := hex.EncodeToString(task.GetPayloadHash())
	if planHash == "" {
		// A task without a hash from the panel still has a plan: the digest is
		// computed over the payload as delivered, the way the check of the envelope
		// would compute it.
		if computed, err := opspec.PayloadHash(action, opspec.ActionVersion, payload); err == nil {
			planHash = hex.EncodeToString(computed)
		}
	}
	return e.journal.MarkInFlight(InFlight{
		IdempotencyKey: key,
		TaskID:         task.GetTaskId(),
		Action:         string(action),
		StartedAt:      started,
		PlanHash:       planHash,
	})
}

// outcomeUnknown is the answer for a marker without a result: the previous
// process of the agent went down while the host was carrying the operation.
func (e *TaskExecutor) outcomeUnknown(ctx context.Context, marker InFlight) *agentv1.TaskResult {
	result := rejected(agentv1.TaskResult_STATUS_FAILED, RejectOutcomeUnknown,
		fmt.Sprintf("the agent restarted while the host was carrying %s started at %s; "+
			"the outcome is unknown - read the host state (packages.list, unit.status) before ordering again",
			marker.Action, marker.StartedAt.Format(time.RFC3339)))
	report := map[string]any{
		"kind":       "outcome_unknown",
		"action":     marker.Action,
		"task_id":    marker.TaskID,
		"started_at": marker.StartedAt.Format(time.RFC3339Nano),
	}
	if marker.PlanHash != "" {
		report["plan_hash"] = marker.PlanHash
	}

	// The panel reads the state of the package database out of every result that
	// knows it.
	if opspec.ActionType(marker.Action).LockClass() == opspec.LockPackages && e.packageState != nil {
		if state := e.packageState(ctx); state != nil {
			result.Detail = &agentv1.TaskResult_PackageApply{PackageApply: state}
			report["package_database_broken"] = state.GetPackageDatabaseBroken()
			report["packages_needing_attention"] = state.GetPackagesNeedingAttention()
		}
	}

	if encoded, err := json.Marshal(report); err == nil {
		result.Stdout = encoded
	}
	return result
}

// reportInFlight names, at start, every operation the previous process left in
// flight.
func (e *TaskExecutor) reportInFlight() {
	now := time.Now().UTC()
	for _, marker := range e.journal.InFlightMarkers() {
		// A cancel of such a task is answered from the marker: nothing
		// runs that could be interrupted, and nothing is promised.
		e.phases.seed(marker.TaskID, marker.IdempotencyKey)
		e.log.Warn("an operation was in flight when the previous process of the agent stopped; "+
			"its outcome is unknown until the host state is read",
			"task_id", marker.TaskID, "action", marker.Action,
			"started_at", marker.StartedAt.Format(time.RFC3339),
			"age", now.Sub(marker.StartedAt).Round(time.Second).String())
	}
}

// attentionReader is the part of a package adapter that can name the packages
// blocking a transaction without root and without running the manager: apt
// reads the dpkg status file.
type attentionReader interface {
	PackagesNeedingAttention(ctx context.Context) []string
}

// packageStateNow reads the state of the package database the cheap way.
func packageStateNow(ctx context.Context) *agentv1.PackageApplyResult {
	manager, err := packages.Detect()
	if err != nil {
		return nil
	}
	reader, ok := manager.(attentionReader)
	if !ok {
		return nil
	}
	attention := reader.PackagesNeedingAttention(ctx)
	return &agentv1.PackageApplyResult{
		Manager:                  manager.Name(),
		PackageDatabaseBroken:    len(attention) > 0,
		PackagesNeedingAttention: attention,
	}
}

// The phases of a task on the host, as the cancel protocol names them in the
// acknowledgement (CancelAck.
const (
	// PhaseAccepted: the task was delivered and is going through the
	// checks and the wait for the host's resources; nothing ran.
	PhaseAccepted = "accepted"
	// PhaseAwaitingLock: the task waits for a resource of the host that
	// another task holds; nothing ran.
	PhaseAwaitingLock = "awaiting_lock"
	// PhaseStarted: a read is under way.
	PhaseStarted = "started"
	// PhaseMutating: the in-flight marker is down and the helper may be changing
	// the host.
	PhaseMutating = "mutating"
	// PhaseDone: the task ended and its result is in the journal.
	PhaseDone = "done"
	// PhaseNotDelivered: the cancel named a task this process was never
	// handed. It will not start: a delivery that follows is refused.
	PhaseNotDelivered = "not_delivered"
	// PhaseInFlightBeforeRestart: the previous process of the agent left the task
	// in flight; the helper may have finished it, and the answer to its
	// redelivery is outcome_unknown.
	PhaseInFlightBeforeRestart = "in_flight_before_restart"
)

// taskPhase is where one attempt stands on the host.
type taskPhase struct {
	idempotencyKey string
	phase          string
	// stop cancels the context the checks and the wait for the host's resources
	// run under.
	stop context.CancelFunc
	// canceled says a cancel reached the task before it started; the
	// executor refuses to start it and answers with STATUS_CANCELED.
	canceled bool
	// resultHash is the digest of the result the journal holds, once the
	// task ended.
	resultHash []byte
}

// taskPhases is the record, per attempt this process was handed, of the phase
// the attempt is in - the record the cancel protocol answers from.
type taskPhases struct {
	mu      sync.Mutex
	entries map[string]*taskPhase
	// order is the sequence the entries were made in, for the bound.
	order   []string
	refused map[string]bool
}

// maxRememberedPhases bounds the record. A host carries a handful of
// tasks at a time; the bound is for the finished ones kept behind them.
const maxRememberedPhases = 512

func newTaskPhases() *taskPhases {
	return &taskPhases{entries: map[string]*taskPhase{}, refused: map[string]bool{}}
}

// enter records a task handed to this process, in the accepted phase, with the
// function that stops it before the start.
func (p *taskPhases) enter(taskID, idempotencyKey string, stop context.CancelFunc) (refused bool) {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	refused = p.refused[taskID]
	delete(p.refused, taskID)
	p.entries[taskID] = &taskPhase{idempotencyKey: idempotencyKey, phase: PhaseAccepted, stop: stop, canceled: refused}
	p.order = append(p.order, taskID)
	p.trim()
	return refused
}

// seed records a task the previous process left in flight: the marker
// names the attempt, and a cancel of it is answered as not interruptible.
func (p *taskPhases) seed(taskID, idempotencyKey string) {
	if p == nil || taskID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, known := p.entries[taskID]; known {
		return
	}
	p.entries[taskID] = &taskPhase{idempotencyKey: idempotencyKey, phase: PhaseInFlightBeforeRestart}
	p.order = append(p.order, taskID)
	p.trim()
}

// move records the phase the task entered.
func (p *taskPhases) move(taskID, phase string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry, known := p.entries[taskID]; known {
		entry.phase = phase
	}
}

// finish records the end of the task with the digest of its result: the
// SHA-256 of the deterministic encoding, the same bytes on every computation
// of the same result.
func (p *taskPhases) finish(taskID string, result *agentv1.TaskResult) {
	if p == nil {
		return
	}
	var hash []byte
	if result != nil {
		options := proto.MarshalOptions{Deterministic: true}
		if encoded, err := options.Marshal(result); err == nil {
			sum := sha256.Sum256(encoded)
			hash = sum[:]
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, known := p.entries[taskID]
	if !known {
		entry = &taskPhase{}
		p.entries[taskID] = entry
		p.order = append(p.order, taskID)
		p.trim()
	}
	entry.phase = PhaseDone
	entry.stop = nil
	entry.resultHash = hash
}

// canceledBeforeStart says whether a cancel reached the task before it
// started. The executor asks before every step that would touch the host.
func (p *taskPhases) canceledBeforeStart(taskID string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, known := p.entries[taskID]
	return known && entry.canceled
}

// answer decides what a cancel of the task finds and what it does.
func (p *taskPhases) answer(taskID string, interruptible func(string) (context.CancelFunc, bool)) (
	outcome agentv1.CancelAck_Outcome, phase string, hash []byte, stop context.CancelFunc) {
	if p == nil {
		return agentv1.CancelAck_NOT_STARTED, PhaseNotDelivered, nil, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, known := p.entries[taskID]
	if !known {
		p.refused[taskID] = true
		if len(p.refused) > maxRememberedPhases {
			p.refused = map[string]bool{taskID: true}
		}
		return agentv1.CancelAck_NOT_STARTED, PhaseNotDelivered, nil, nil
	}
	switch entry.phase {
	case PhaseDone:
		return agentv1.CancelAck_ALREADY_DONE, PhaseDone, entry.resultHash, nil
	case PhaseAccepted, PhaseAwaitingLock:
		// Nothing ran: the task is refused at its next step, and the wait
		// it may be in is cut so that the refusal is answered now.
		entry.canceled = true
		return agentv1.CancelAck_NOT_STARTED, entry.phase, nil, entry.stop
	case PhaseStarted:
		if interruptible != nil {
			if cancel, registered := interruptible(taskID); registered {
				return agentv1.CancelAck_INTERRUPTED, entry.phase, nil, cancel
			}
		}
		return agentv1.CancelAck_NOT_INTERRUPTIBLE, entry.phase, nil, nil
	default:
		return agentv1.CancelAck_NOT_INTERRUPTIBLE, entry.phase, nil, nil
	}
}

// trim drops the oldest finished entries beyond the bound. An entry of
// a task still under way is never dropped: a cancel of it has to find it.
func (p *taskPhases) trim() {
	for len(p.order) > maxRememberedPhases {
		dropped := false
		for i, id := range p.order {
			entry, known := p.entries[id]
			if !known || entry.phase == PhaseDone || entry.phase == PhaseInFlightBeforeRestart {
				delete(p.entries, id)
				p.order = append(p.order[:i], p.order[i+1:]...)
				dropped = true
				break
			}
		}
		if !dropped {
			return
		}
	}
}
