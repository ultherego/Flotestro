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

// HostClaim is a claim on the whole host. A restart and a shutdown collide with
// every other mutation: a change that started right before a restart has no way
// of finishing.
const HostClaim = "host"

// resourceWaitLimit ends the wait for a busy resource.
//
// Waiting without end would turn the queue of the host into silence: the panel
// would see the task accepted and nothing more, until the time limit of the
// operation. A refusal naming the blocking task is an answer the operator can
// do something with.
const resourceWaitLimit = 2 * time.Minute

// locks serialize the mutations on the resources of the host.
//
// The limit on the number of tasks (the budget) and a resource lock answer two
// different questions: whether the host has the capacity for another task and
// whether two operations do not exclude each other. Two network restarts can
// fit within the limit of two general tasks and still leave a configuration no
// rollback plan describes.
//
// All the claims of a task are taken at once, under one lock. That leaves no
// partial acquisition and no acquisition order, and therefore no cycle: a task
// either gets the whole set or waits.
type locks struct {
	mu   sync.Mutex
	held map[string]holder
	// change is closed at every release. A waiter wakes up and checks once
	// more instead of polling in a loop.
	change chan struct{}
}

// holder says who holds a resource. The name of the operation is part of the
// answer for the operator: "the network is busy" without saying by what is not
// an answer.
type holder struct {
	task      string
	operation string
}

func newLocks() *locks {
	return &locks{held: map[string]holder{}, change: make(chan struct{})}
}

// acquire takes all the claims of a task or waits until that becomes possible.
//
// It returns a release function and an empty reason. When the wait ends, it
// returns nil and a reason naming the resource and the operation holding it.
func (l *locks) acquire(ctx context.Context, task, operation string,
	claims []string) (func(), string) {
	if len(claims) == 0 {
		return func() {}, ""
	}
	for {
		l.mu.Lock()
		if resource, who, collides := l.collision(claims); !collides {
			for _, claim := range claims {
				l.held[claim] = holder{task: task, operation: operation}
			}
			l.mu.Unlock()
			return func() { l.release(claims) }, ""
		} else {
			wait := l.change
			l.mu.Unlock()
			select {
			case <-wait:
			case <-ctx.Done():
				return nil, describeCollision(resource, who)
			}
		}
	}
}

// collision says whether any claim is already held. The host claim collides
// with everything - and everything collides with it.
func (l *locks) collision(claims []string) (resource string, who holder, collides bool) {
	if who, taken := l.held[HostClaim]; taken {
		return HostClaim, who, true
	}
	for _, claim := range claims {
		if claim == HostClaim && len(l.held) > 0 {
			for resource, who := range l.held {
				return resource, who, true
			}
		}
		if who, taken := l.held[claim]; taken {
			return claim, who, true
		}
	}
	return "", holder{}, false
}

func (l *locks) release(claims []string) {
	l.mu.Lock()
	for _, claim := range claims {
		delete(l.held, claim)
	}
	// Every release wakes all the waiters: which of them goes on is decided by
	// the repeated check and not by the order in which they fell asleep.
	close(l.change)
	l.change = make(chan struct{})
	l.mu.Unlock()
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

// taskClaims lists the resources a task takes exclusively.
//
// Reads take nothing: two state reads can run side by side, and their cost is
// limited by the task budget, not by a lock. The exclusive ones are the
// mutations - and they are the ones that have a resource class in the operation
// registry.
func taskClaims(task *agentv1.TaskEnvelope) []string {
	action, payload, err := decodeAction(task)
	if err != nil || !action.Mutating() {
		return nil
	}

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
	// network stack. Without that second claim a sysctl change could run in
	// parallel with an address change and leave a state nobody planned.
	case opspec.ActionSysctlEnsure, opspec.ActionKernelModuleLoad,
		opspec.ActionKernelModuleBlacklist:
		set["kernel"] = true
		set[opspec.LockNetwork] = true

	// The security of the host: the MAC mode and the audit rules change the
	// policy every next change has to reckon with.
	case opspec.ActionSELinuxModeSet, opspec.ActionAuditRulesReload:
		set["security"] = true
	}

	// A file is a resource in itself: two changes of the same file have to go
	// one after the other, and changes of different files have no reason to wait
	// for each other.
	if path := filePath(action, payload); path != "" {
		set["file:"+path] = true
	}

	claims := make([]string, 0, len(set))
	for name := range set {
		claims = append(claims, name)
	}
	// The order is fixed so that the description of a collision and the tests
	// are repeatable.
	sort.Strings(claims)
	return claims
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

// operationName names the task in the description of a collision. An unknown
// operation has no name, but it has an identifier - and that is enough to point
// at the one blocking.
func operationName(task *agentv1.TaskEnvelope) string {
	action, _, err := decodeAction(task)
	if err != nil {
		return ""
	}
	return string(action)
}

// acquireResources waits for the resources of a task with its own time limit.
//
// The limit is shorter than the limit of the operation: a task that has not got
// its resource within two minutes is to come back with an answer instead of
// staying silent until the end of its time. An empty reason together with nil
// means the end of the session.
func acquireResources(ctx context.Context, resources *locks, task *agentv1.TaskEnvelope,
	claims []string) (func(), string) {
	if len(claims) == 0 {
		return func() {}, ""
	}
	waiting, cancel := context.WithTimeout(ctx, resourceWaitLimit)
	defer cancel()

	release, reason := resources.acquire(waiting, task.GetTaskId(), operationName(task), claims)
	if release != nil {
		return release, ""
	}
	if ctx.Err() != nil {
		// The session ended: there is nobody to send the result to.
		return nil, ""
	}
	return nil, reason
}
