package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// HostClaim is a claim on the whole host.
const HostClaim = opspec.ClaimHost

// resourceWaitLimit ends the wait for a busy resource.
const resourceWaitLimit = 2 * time.Minute

// lockWaitReportInterval spaces the reports of a task waiting for a busy
// resource.
const lockWaitReportInterval = 10 * time.Second

// locks serialize the operations on the resources of the host.
type locks struct {
	mu   sync.Mutex
	held map[string][]holder
	// change is closed at every release. A waiter wakes up and checks once
	// more instead of polling in a loop.
	change chan struct{}
}

// holder says who holds a resource and how.
type holder struct {
	task      string
	operation string
	mode      opspec.ClaimMode
	weight    int
}

func newLocks() *locks {
	return &locks{held: map[string][]holder{}, change: make(chan struct{})}
}

// acquire takes all the claims of a task or waits until that becomes possible.
// It returns a release function and an empty reason.
func (l *locks) acquire(ctx context.Context, task, operation string,
	claims []opspec.ResourceClaim) (func(), string) {
	return l.acquireReporting(ctx, task, operation, claims, nil)
}

// acquireReporting is acquire that tells the caller about the wait: waiting is
// called with the blocker when the task first finds a resource busy and then
// at most every lockWaitReportInterval for as long as the wait lasts.
func (l *locks) acquireReporting(ctx context.Context, task, operation string,
	claims []opspec.ResourceClaim, waiting func(blocker string)) (func(), string) {
	if len(claims) == 0 {
		return func() {}, ""
	}
	var lastReport time.Time
	for {
		l.mu.Lock()
		resource, who, collides := l.collision(claims)
		if !collides {
			for _, claim := range claims {
				l.held[claim.Class] = append(l.held[claim.Class],
					holder{task: task, operation: operation, mode: claim.Mode, weight: claimWeight(claim)})
			}
			l.mu.Unlock()
			return func() { l.release(task, claims) }, ""
		}
		wait := l.change
		l.mu.Unlock()

		if waiting != nil && (lastReport.IsZero() || time.Since(lastReport) >= lockWaitReportInterval) {
			waiting(describeBlocker(resource, who))
			lastReport = time.Now()
		}
		// The timer wakes the loop when nothing is released for a while, so
		// that the wait is reported as going on rather than as vanished.
		again := time.NewTimer(lockWaitReportInterval)
		select {
		case <-wait:
		case <-again.C:
		case <-ctx.Done():
			again.Stop()
			return nil, describeCollision(resource, who)
		}
		again.Stop()
	}
}

// claimWeight is the weight a claim counts against the capacity of its class.
func claimWeight(claim opspec.ResourceClaim) int {
	if claim.Weight < 1 {
		return 1
	}
	return claim.Weight
}

// collision says whether any claim of the set cannot be taken now, and by
// whom.
func (l *locks) collision(claims []opspec.ResourceClaim) (resource string, who holder, collides bool) {
	if holders := l.held[HostClaim]; len(holders) > 0 {
		return HostClaim, holders[0], true
	}
	for _, claim := range claims {
		if claim.Class == HostClaim {
			for class, holders := range l.held {
				if len(holders) > 0 {
					return class, holders[0], true
				}
			}
		}
		holders := l.held[claim.Class]
		if len(holders) == 0 {
			continue
		}
		if claim.Mode != opspec.ClaimShared {
			// An exclusive claim waits for every holder of the class, the shared ones
			// included: a change under a read that is still looking would leave the
			// read with a state nobody planned.
			return claim.Class, holders[0], true
		}
		for _, holding := range holders {
			if holding.mode != opspec.ClaimShared {
				return claim.Class, holding, true
			}
		}
		// Shared claims coexist up to the capacity of the class.
		capacity := opspec.SharedCapacity(claim.Class)
		if capacity == 0 {
			continue
		}
		carried := 0
		for _, holding := range holders {
			carried += holding.weight
		}
		if carried+claimWeight(claim) > capacity {
			return claim.Class, holders[0], true
		}
	}
	return "", holder{}, false
}

// release gives back the claims of one task. Only the holdings of that task
// go: another task sharing the class keeps its place.
func (l *locks) release(task string, claims []opspec.ResourceClaim) {
	l.mu.Lock()
	for _, claim := range claims {
		kept := l.held[claim.Class][:0]
		for _, holding := range l.held[claim.Class] {
			if holding.task != task {
				kept = append(kept, holding)
			}
		}
		if len(kept) == 0 {
			delete(l.held, claim.Class)
		} else {
			l.held[claim.Class] = kept
		}
	}
	// Every release wakes all the waiters: which of them goes on is decided by
	// the repeated check and not by the order in which they fell asleep.
	close(l.change)
	l.change = make(chan struct{})
	l.mu.Unlock()
}

// describeBlocker names what a waiting task waits on, in the form the panel
// shows under the host: the resource and the task holding it.
func describeBlocker(resource string, who holder) string {
	description := resource
	if who.task != "" {
		description += " held by task " + who.task
	}
	if who.operation != "" {
		description += " (" + who.operation + ")"
	}
	return description
}

func describeCollision(resource string, who holder) string {
	description := fmt.Sprintf("the resource %s is busy", resource)
	if who.operation != "" {
		description += fmt.Sprintf(" with the operation %s", who.operation)
	}
	if who.task != "" {
		description += fmt.Sprintf(" (task %s)", who.task)
	}
	return description
}

// taskClaims lists the resources a task takes, as the operation contract
// declares them.
func taskClaims(task *agentv1.TaskEnvelope) []opspec.ResourceClaim {
	action, payload, err := decodeAction(task)
	if err != nil {
		return nil
	}

	declared := action.Contract().ResourceClaims
	if len(declared) == 0 && action.Mutating() {
		declared = fallbackClaims(action)
	}

	claims := make([]opspec.ResourceClaim, 0, len(declared))
	for _, claim := range declared {
		if claim.Class == opspec.ClaimFile {
			if path := filePath(action, payload); path != "" {
				claim.Class = opspec.ClaimFile + ":" + path
			}
		}
		claims = append(claims, claim)
	}
	// The order is fixed so that the description of a collision and the tests
	// are repeatable.
	sort.Slice(claims, func(i, j int) bool { return claims[i].Class < claims[j].Class })
	return claims
}

// fallbackClaims is what a mutation takes when its contract declares no claim
// at all.
func fallbackClaims(action opspec.ActionType) []opspec.ResourceClaim {
	set := map[string]bool{}
	if class := action.LockClass(); class != opspec.LockNone {
		set[class] = true
	}
	switch action {
	// A restart and a shutdown take the whole host: any other mutation would not
	// manage to finish anyway.
	case opspec.ActionSystemReboot, opspec.ActionSystemShutdown:
		set[HostClaim] = true

	// The kernel is a separate resource, but sysctl and modules also change the
	// network stack.
	case opspec.ActionSysctlEnsure, opspec.ActionKernelModuleLoad,
		opspec.ActionKernelModuleBlacklist:
		set[opspec.ClaimKernel] = true
		set[opspec.LockNetwork] = true

	// The security of the host: the MAC mode and the audit rules change the
	// policy every next change has to reckon with.
	case opspec.ActionSELinuxModeSet, opspec.ActionAuditRulesReload:
		set[opspec.ClaimSecurity] = true
	}

	claims := make([]opspec.ResourceClaim, 0, len(set))
	for class := range set {
		claims = append(claims, opspec.ResourceClaim{Class: class, Mode: opspec.ClaimExclusive, Weight: 1})
	}
	return claims
}

// claimNames lists the classes of the claims, for the report of a start and
// the log of the session: the panel shows what the task holds, not how.
func claimNames(claims []opspec.ResourceClaim) []string {
	names := make([]string, 0, len(claims))
	for _, claim := range claims {
		names = append(names, claim.Class)
	}
	return names
}

// filePath returns the path a file operation concerns.
func filePath(action opspec.ActionType, payload opspec.Payload) string {
	switch action {
	case opspec.ActionFileEnsure, opspec.ActionFileRemove, opspec.ActionFileRollback:
		if payload.File != nil {
			return strings.TrimSpace(payload.File.Path)
		}
	}
	return ""
}

// operationName names the task in the description of a collision.
func operationName(task *agentv1.TaskEnvelope) string {
	action, _, err := decodeAction(task)
	if err != nil {
		return ""
	}
	return string(action)
}

// acquireResources waits for the resources of a task with its own time limit.
func acquireResources(ctx context.Context, resources *locks, task *agentv1.TaskEnvelope,
	claims []opspec.ResourceClaim, waiting func(blocker string)) (func(), string) {
	if len(claims) == 0 {
		return func() {}, ""
	}
	bounded, cancel := context.WithTimeout(ctx, resourceWaitLimit)
	defer cancel()

	release, reason := resources.acquireReporting(bounded, task.GetTaskId(), operationName(task), claims, waiting)
	if release != nil {
		return release, ""
	}
	if ctx.Err() != nil {
		// The session ended: there is nobody to send the result to.
		return nil, ""
	}
	return nil, reason
}
