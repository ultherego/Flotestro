package helper

import (
	"context"
	"strings"
	"sync"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// Guard classes name the host resources a mutation uses exclusively. Only one
// mutation of a class runs at a time; a read takes no guard. Where the agent
// queues its tasks on the same resource, the name is the one the agent uses,
// so a refusal travels to the panel without translation.
const (
	GuardUnits      = "units"
	GuardPackages   = "packages"
	GuardContainers = "containers"
	GuardIdentity   = "identity"
	GuardAccounts   = "accounts"
	// The network is one resource: NetworkManager profiles, the resolver and
	// the firewall table are rewritten as a whole, and two changes at once
	// leave a state neither rollback plan describes.
	GuardNetwork = "network"
	// Storage is one resource: two operations on the same filesystem can
	// damage it.
	GuardStorage = "storage"
	// A backup repository is one resource: the tools hold their own lock on
	// it, and a second operation would wait under that lock until its time
	// ran out - without the panel knowing why.
	GuardBackup = "backup"
	// The trust store and the registry of deployed certificates are one per
	// host and are rewritten as a whole.
	GuardCertificates = "certificates"
	// Managed files share one registry: two writes at once would lose one of
	// the entries.
	GuardFiles = "files"
	// The kernel settings and the module lists live in a few shared files, and
	// the loaded modules change what the next sysctl means.
	GuardKernel = "kernel"
	// The time daemon configuration is reloaded as a whole.
	GuardTime = "time"
	// The MAC mode and the audit rules change the policy every next change
	// has to reckon with.
	GuardSecurity = "security"
)

// guards serialize the mutations on the resources of the host.
//
// A guard is refused, not waited for. The agent already queues its tasks on
// the same classes, so a collision here means a second client or an operation
// the agent did not know was mutating - waiting would hide that until the time
// limit runs out, and a refusal names it right away.
type guards struct {
	mu sync.Mutex
	// held maps a class to the task holding it. The task is part of the
	// refusal: "the resource is busy" without saying with what is not an
	// answer the operator can act on.
	held map[string]string
}

// hold takes the guard of a class on behalf of a task.
//
// An empty class means the operation changes nothing and needs no guard; the
// release is then a no-op, so a handler that decides the class per operation
// does not need a second code path for reads. The release is meant for a
// defer: it gives the guard back exactly once.
func (g *guards) hold(class, task string) (release func(), refusal *helperv1.HelperResponse) {
	if class == "" {
		return func() {}, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.held == nil {
		g.held = map[string]string{}
	}
	if holder, taken := g.held[class]; taken {
		return nil, rejectBusy(class, holder)
	}
	g.held[class] = task
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			delete(g.held, class)
			g.mu.Unlock()
		})
	}, nil
}

// hold takes the guard of a class for the task named in the order.
func (s *Server) hold(class string, request *helperv1.HelperRequest) (func(), *helperv1.HelperResponse) {
	return s.guards.hold(class, request.GetTaskId())
}

// busyPrefix opens every refusal of a held guard. The class follows it up to
// the next space: the response has no field for the class, so the agent reads
// it from the message with BusyResource.
const busyPrefix = "the resource "

// rejectBusy builds the refusal of a held guard.
func rejectBusy(class, holder string) *helperv1.HelperResponse {
	message := busyPrefix + class + " is busy"
	if holder != "" {
		message += " with the task " + holder
	}
	return reject(ErrorLocked, message)
}

// BusyResource reads the guard class out of a locked refusal.
//
// It returns an empty string for a message of another shape - the lock of a
// package manager held by an administrator, for one, is also reported as
// locked, but names no class of the helper.
func BusyResource(message string) string {
	rest, found := strings.CutPrefix(message, busyPrefix)
	if !found {
		return ""
	}
	class, _, _ := strings.Cut(rest, " ")
	return class
}

// longestOperation is the most time any family gives an order. The socket
// deadline is derived from it, so every family cap stays within it.
const longestOperation = 12 * time.Hour

// timeLimit reads the time limit of an order and keeps it within the cap of
// the family.
//
// An order without a limit gets the fallback; one asking for more than the
// family allows gets the cap. The cap is what keeps a guard from being held
// forever: a hung tool ends with the context, not with the patience of the
// operator.
func timeLimit(request *helperv1.HelperRequest, fallback, ceiling time.Duration) time.Duration {
	limit := time.Duration(request.GetTimeoutSeconds()) * time.Second
	switch {
	case limit <= 0:
		return fallback
	case limit > ceiling:
		return ceiling
	}
	return limit
}

// deadline derives the context of one operation from the order. Every tool
// the operation runs is started under it, so the guard of the operation is
// released at the latest when the limit passes.
func deadline(ctx context.Context, request *helperv1.HelperRequest,
	fallback, ceiling time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeLimit(request, fallback, ceiling))
}
