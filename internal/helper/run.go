package helper

import (
	"context"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/ultherego/flotestro/internal/helper/runscope"
	"github.com/ultherego/flotestro/internal/opspec"
)

// A heavy operation - a package transaction, a backup, a filesystem check, a
// Compose deployment - runs its tools in a transient systemd scope with the
// resource controls of its family.

// scopeUnitPrefix names the transient units, so that they are found together
// in systemctl and told apart from the agent replacement unit.
const scopeUnitPrefix = "flotestro-op-"

// unitArgIndex is where the unit name sits in a wrapped argument array.
const unitArgIndex = 3

// scopeRunner turns an argument array into one that runs under a transient
// scope.
type scopeRunner struct {
	lookPath func(file string) (string, error)
	log      *slog.Logger
	// sequence numbers the scopes this helper started, so that two tools of one
	// operation never share a unit name.
	sequence *atomic.Uint64
}

// newScopeRunner builds the runner of the helper.
func newScopeRunner(log *slog.Logger) scopeRunner {
	return scopeRunner{lookPath: exec.LookPath, log: log, sequence: new(atomic.Uint64)}
}

// next hands out the number of the next scope.
func (r scopeRunner) next() uint64 {
	if r.sequence == nil {
		return 0
	}
	return r.sequence.Add(1)
}

// wrap returns the argument array of the tool under a scope with the given
// limits, and whether it was wrapped.
func (r scopeRunner) wrap(taskID string, family opspec.ResourceFamily,
	limits opspec.ResourceLimits, argv []string) ([]string, bool) {
	if len(argv) == 0 {
		return argv, false
	}
	prefix, ok := r.prefix(taskID, family, limits)
	if !ok {
		return argv, false
	}
	return runscope.Prefixed(prefix, argv), true
}

// prefix returns the systemd-run invocation that puts a tool under a scope
// with the given limits, and whether there is one.
func (r scopeRunner) prefix(taskID string, family opspec.ResourceFamily,
	limits opspec.ResourceLimits) ([]string, bool) {
	if limits.Empty() {
		return nil, false
	}
	systemdRun, err := r.lookPath("systemd-run")
	if err != nil {
		if r.log != nil {
			r.log.Warn("the operation runs without a resource scope: systemd-run is not available",
				"task_id", taskID, "family", string(family))
		}
		return nil, false
	}
	prefixed := []string{
		systemdRun, "--scope", "--quiet",
		// Every tool gets a unit of its own, numbered after the task.
		"--unit=" + scopeUnit(taskID, r.next()),
		"--description=Flotestro: " + string(family) + " operation",
		// A scope whose tool failed stays behind as a failed unit until somebody
		// resets it; collected on failure as well, it leaves nothing for the
		// operator to clean up.
		"--property=CollectMode=inactive-or-failed",
	}
	for _, property := range limits.Properties() {
		prefixed = append(prefixed, "--property="+property)
	}
	return append(prefixed, "--"), true
}

// scopeUnit names the scope of one tool of a task.
func scopeUnit(taskID string, sequence uint64) string {
	var name strings.Builder
	for _, char := range taskID {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
			name.WriteRune(char)
		case char == '-' || char == '_' || char == '.':
			name.WriteRune(char)
		}
		if name.Len() >= 64 {
			break
		}
	}
	if name.Len() == 0 {
		name.WriteString("unnamed")
	}
	return scopeUnitPrefix + name.String() + "-" + strconv.FormatUint(sequence, 10)
}

// scoped wraps the argument array of a heavy operation in the scope of its
// family, when the family has one.
func (s *Server) scoped(taskID string, family opspec.ResourceFamily, argv []string) []string {
	runner := s.scopes
	if runner.lookPath == nil {
		// A server built without the constructor - the tests do that - gets
		// the real lookup.
		runner = newScopeRunner(s.log)
	}
	wrapped, scoped := runner.wrap(taskID, family, opspec.FamilyLimits(family), argv)
	if scoped && s.log != nil {
		s.log.Info("the operation runs in a resource scope",
			"task_id", taskID, "family", string(family), "unit", wrapped[unitArgIndex])
	}
	return wrapped
}

// scopeContext records the scope of a family in the context, for the modules
// that build their commands far from the helper and read the prefix there.
func (s *Server) scopeContext(ctx context.Context, taskID string,
	family opspec.ResourceFamily) context.Context {
	runner := s.scopes
	if runner.lookPath == nil {
		runner = newScopeRunner(s.log)
	}
	if _, ok := runner.prefix(taskID, family, opspec.FamilyLimits(family)); !ok {
		return runscope.With(ctx, nil)
	}
	if s.log != nil {
		s.log.Info("the operation runs in a resource scope",
			"task_id", taskID, "family", string(family), "unit", scopeUnitPrefix+"*")
	}
	return runscope.With(ctx, func(argv []string) []string {
		// The prefix is computed anew for every tool, so each gets its own
		// unit number; only the presence of a scope was decided above.
		prefix, _ := runner.prefix(taskID, family, opspec.FamilyLimits(family))
		return runscope.Prefixed(prefix, argv)
	})
}

// runScoped runs a tool of a heavy operation under the scope of its family and
// returns the combined output, like runTool.
func (s *Server) runScoped(ctx context.Context, family opspec.ResourceFamily,
	argv []string) (string, error) {
	return runTool(ctx, s.scoped(taskOf(ctx), family, argv))
}

// taskKey carries the task identifier down to the handlers that run the tools:
// the storage handlers take the action alone, and the scope needs a name.
type taskKey struct{}

// withTask records the task identifier in the context.
func withTask(ctx context.Context, taskID string) context.Context {
	return context.WithValue(ctx, taskKey{}, taskID)
}

// taskOf reads the task identifier recorded by withTask; empty when none.
func taskOf(ctx context.Context) string {
	taskID, _ := ctx.Value(taskKey{}).(string)
	return taskID
}
