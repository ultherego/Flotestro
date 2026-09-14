package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// InFlight is the record of a mutation the host has been told to carry out
// and has not reported on yet.
//
// The helper finishes a transaction on its own even when the agent that
// ordered it dies, so a marker without a result is not "nothing happened":
// it is "something happened and nobody wrote down how it ended". The record
// carries what the agent knew before it called the helper, and nothing it
// would have to guess.
type InFlight struct {
	IdempotencyKey string    `json:"idempotency_key"`
	TaskID         string    `json:"task_id"`
	Action         string    `json:"action"`
	StartedAt      time.Time `json:"started_at"`
	// PlanHash names the approved plan the operation was carrying out, as a
	// hex digest. It lets the operator match the unknown outcome with the
	// approval, and it is empty for a task delivered without a hash.
	PlanHash string `json:"plan_hash,omitempty"`
}

// PackageStateProbe reads what the package adapter can say about the host
// without root and without running a transaction. Nil means the adapter
// cannot say anything cheaply - and then the result says nothing rather than
// "sound".
type PackageStateProbe func(ctx context.Context) *agentv1.PackageApplyResult

// runningKeys is the set of idempotency keys inside Execute right now.
//
// A redelivery can arrive while the first delivery is still inside the
// helper: the lease ran out before the transaction did. That delivery has no
// result to replay and no restart to report, and the marker on disk must not
// make it look like one. The set is the difference between "still running
// here" and "left behind by a process that is gone".
type runningKeys struct {
	mu   sync.Mutex
	keys map[string]struct{}
}

func newRunningKeys() *runningKeys {
	return &runningKeys{keys: map[string]struct{}{}}
}

// claim takes the key for the duration of one Execute. An empty key is not
// tracked: it cannot be redelivered under the same name either.
func (r *runningKeys) claim(key string) bool {
	// A nil set belongs to an executor assembled by hand in a test; it has
	// no session to redeliver anything.
	if r == nil || key == "" {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, busy := r.keys[key]; busy {
		return false
	}
	r.keys[key] = struct{}{}
	return true
}

func (r *runningKeys) release(key string) {
	if r == nil || key == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.keys, key)
}

// markInFlight writes the marker for a mutation about to start. A read is
// never marked: repeating it costs nothing and changes nothing, so a restart
// in the middle of one has no outcome to lose.
//
// The marker goes down before the dispatch rather than right before the
// helper call, because the call sits in every module separately. The cost
// is that a crash during the checks a module does first - the recomputed
// package plan, say - is also reported as unknown. That is the honest side
// to err on: the agent that comes back has no way to tell those checks from
// the transaction that follows them.
func (e *TaskExecutor) markInFlight(task *agentv1.TaskEnvelope, action opspec.ActionType,
	payload opspec.Payload, started time.Time) error {
	key := task.GetIdempotencyKey()
	if key == "" || !action.Mutating() {
		return nil
	}
	planHash := hex.EncodeToString(task.GetPayloadHash())
	if planHash == "" {
		// A task without a hash from the panel still has a plan: the digest
		// is computed over the payload as delivered, the way the check of the
		// envelope would compute it.
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
//
// The task is not run again - the helper may have finished it - and the
// result is not invented either. What the agent can say is said: when the
// operation started, what it was, and, for a package operation, what the
// adapter reads off the host now. The rest is for the operator to read from
// the host before ordering anything.
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

	// The panel reads the state of the package database out of every result
	// that knows it. A result that knows nothing must carry no package detail
	// at all: an empty detail would read as "the database is sound".
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

// reportInFlight names, at start, every operation the previous process left
// in flight. Each of them is answered when its task comes back; the line is
// for the person reading the log of a host that has just restarted, who
// otherwise learns of the interruption only from the panel.
func (e *TaskExecutor) reportInFlight() {
	now := time.Now().UTC()
	for _, marker := range e.journal.InFlightMarkers() {
		e.log.Warn("an operation was in flight when the previous process of the agent stopped; "+
			"its outcome is unknown until the host state is read",
			"task_id", marker.TaskID, "action", marker.Action,
			"started_at", marker.StartedAt.Format(time.RFC3339),
			"age", now.Sub(marker.StartedAt).Round(time.Second).String())
	}
}

// attentionReader is the part of a package adapter that can name the
// packages blocking a transaction without root and without running the
// manager: apt reads the dpkg status file. The other adapters answer only by
// verifying the whole database, which is not a cost to pay on the way to a
// refusal - so they stay silent, and silence is reported as silence.
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
