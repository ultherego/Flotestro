package helper

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/ultherego/flotestro/internal/opspec"
)

// A heavy operation - a package transaction, a backup, a filesystem check, a
// Compose deployment - runs its tools in a transient systemd scope with the
// resource controls of its family. The scope is a cgroup around the tools,
// nothing more: the same argument array reaches the same tool, only under a
// CPU and I/O weight and a memory ceiling, so that the operation slows itself
// down on a busy host rather than the host.
//
// A host without systemd-run runs the tools as before. That is said in the
// journal of the helper, not hidden: an operator asking why an update took
// the whole machine is to find the answer there.

// scopeUnitPrefix names the transient units, so that they are found together
// in systemctl and told apart from the agent replacement unit.
const scopeUnitPrefix = "flotestro-op-"

// scopeRunner turns an argument array into one that runs under a transient
// scope. The path lookup is injected, so a test can stand in for a host
// with and without systemd-run.
type scopeRunner struct {
	lookPath func(file string) (string, error)
	log      *slog.Logger
}

// newScopeRunner builds the runner of the helper.
func newScopeRunner(log *slog.Logger) scopeRunner {
	return scopeRunner{lookPath: exec.LookPath, log: log}
}

// wrap returns the argument array of the tool under a scope with the given
// limits, and whether it was wrapped. The array is prefixed and nothing in
// it is interpreted: no shell, no quoting, the same argv as without the
// scope.
//
// Empty limits mean the caller asked for no scope. A missing systemd-run
// means a plain run, with the reason logged once per operation.
func (r scopeRunner) wrap(taskID string, family opspec.ResourceFamily,
	limits opspec.ResourceLimits, argv []string) ([]string, bool) {
	if limits.Empty() || len(argv) == 0 {
		return argv, false
	}
	systemdRun, err := r.lookPath("systemd-run")
	if err != nil {
		if r.log != nil {
			r.log.Warn("the operation runs without a resource scope: systemd-run is not available",
				"task_id", taskID, "family", string(family), "tool", argv[0])
		}
		return argv, false
	}
	prefixed := []string{
		systemdRun, "--scope", "--quiet",
		"--unit=" + scopeUnit(taskID),
		"--description=Flotestro: " + string(family) + " operation",
	}
	for _, property := range limits.Properties() {
		prefixed = append(prefixed, "--property="+property)
	}
	prefixed = append(prefixed, "--")
	return append(prefixed, argv...), true
}

// scopeUnit names the scope of a task. A unit name takes letters, digits and
// a few punctuation marks; a task identifier is a UUID, but the name is
// filtered anyway, because the identifier arrives from the network.
func scopeUnit(taskID string) string {
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
	return scopeUnitPrefix + name.String()
}

// scoped wraps the argument array of a heavy operation in the scope of its
// family, when the family has one. The families without limits in the
// registry run plain; the table is the same one the scheduler writes into
// the task envelope, so the host and the panel agree on the numbers.
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
			"task_id", taskID, "family", string(family), "unit", scopeUnit(taskID))
	}
	return wrapped
}

// runScoped runs a tool of a heavy operation under the scope of its family
// and returns the combined output, like runTool. The task is the one the
// context carries.
func (s *Server) runScoped(ctx context.Context, family opspec.ResourceFamily,
	argv []string) (string, error) {
	return runTool(ctx, s.scoped(taskOf(ctx), family, argv))
}

// taskKey carries the task identifier down to the handlers that run the
// tools: the storage handlers take the action alone, and the scope needs a
// name.
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
