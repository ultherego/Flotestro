package helper

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/packages"
)

// AgentReplacementUnit is the name of the transient unit in which the agent
// replacement happens. The name is fixed: two replacements at once on one host
// make no sense, and systemd refuses the second one instead of letting both
// onto the same package database.
const AgentReplacementUnit = "flotestro-agent-replacement"

// ErrorSelfReplacement means the host cannot be replaced safely.
const ErrorSelfReplacement = "self_replacement_unavailable"

// agentReplacement recognizes an order in which the agent replaces itself.
//
// The recognition goes by the package name, not by a field in the request:
// this is a fact about the host, not a wish of the panel. The agent package in
// the company of others is not a replacement but an installation of a set -
// and that one is not performed, because the scripts of the agent package cut
// the transaction in half, leaving the rest of the set in a state nobody
// ordered.
func agentReplacement(packageSpecs []string) (string, bool) {
	if len(packageSpecs) != 1 {
		return "", false
	}
	spec := strings.TrimSpace(packageSpecs[0])
	if spec == packages.AgentPackage {
		return spec, true
	}
	rest, ok := strings.CutPrefix(spec, packages.AgentPackage)
	if !ok || len(rest) < 2 {
		return "", false
	}
	// apt separates the version with "=", dnf with a dash. The prefix alone is
	// not enough: "flotestro-agent-tools" starts with it too and is not this
	// package. A digit decides - a version starts with one, a name does not.
	if rest[0] != '=' && rest[0] != '-' {
		return "", false
	}
	if rest[1] < '0' || rest[1] > '9' {
		return "", false
	}
	return spec, true
}

// orderAgentReplacement starts the installation of the agent package outside
// the helper.
//
// The scripts of the agent package stop the helper - and with it its whole
// control group, that is the package manager in the middle of the transaction.
// An installation led by the helper would therefore end with a half-installed
// package and a host that did not come back. That is why this one transaction
// starts as a separate systemd unit: it outlives the death of the one who
// ordered it.
//
// The answer does not carry the result of the transaction and is not meant to:
// success is decided by the agent coming back in the expected version, which
// the panel sees.
func (s *Server) orderAgentReplacement(ctx context.Context, manager packages.Manager,
	spec string) *helperv1.HelperResponse {
	if _, ok := manager.(packages.Lifecycle); !ok {
		return reject(ErrorUnsupported,
			"the manager "+manager.Name()+" does not support installing packages")
	}
	if err := StartAgentReplacement(ctx, spec); err != nil {
		return reject(ErrorSelfReplacement, err.Error())
	}
	s.log.Info("the agent replacement was started outside the helper",
		"package", spec, "unit", AgentReplacementUnit, "manager", manager.Name())
	return &helperv1.HelperResponse{
		Accepted: true,
		Message: "the installation of " + spec + " is running in the unit " +
			AgentReplacementUnit + "; the result is decided by the return of the agent",
		PackageResult: &helperv1.PackageActionResult{Manager: manager.Name()},
	}
}

// StartAgentReplacement starts the transient unit that calls this same helper
// binary in replacement mode.
//
// The unit gets only the package name with the version - not a command. The
// content of the transaction is assembled by the manager adapter on the other
// side, exactly as with every other package operation.
func StartAgentReplacement(ctx context.Context, spec string) error {
	if _, ok := agentReplacement([]string{spec}); !ok {
		return fmt.Errorf("%q is not the agent package", spec)
	}
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		return fmt.Errorf("a host without systemd-run cannot replace the agent")
	}
	binary, err := helperPath()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, systemdRun,
		"--collect", "--quiet",
		// Without --no-block systemd-run waits for the end of a oneshot unit,
		// that is for the whole transaction - while standing in the helper's
		// control group, which that transaction is about to stop. The order is
		// to return after the unit starts, not after it finishes: the result is
		// decided by the return of the agent.
		"--no-block",
		"--unit="+AgentReplacementUnit,
		"--description=Flotestro: agent replacement",
		"--property=Type=oneshot",
		// The package transaction has its own time limit; this one is the last
		// net, so that a hung installation does not stay on the host forever.
		"--property=TimeoutStartSec=3600",
		"--", binary, "-agent-replacement", spec)
	cmd.Env = toolEnvironment()
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// RunAgentReplacement installs the given version of the agent package.
//
// The function works without the agent, without the socket and without the
// panel: at the moment when the package scripts stop the helper and restart
// the agent, it is the only process that still knows what was supposed to
// happen.
func RunAgentReplacement(ctx context.Context, spec string, log *slog.Logger) error {
	if _, ok := agentReplacement([]string{spec}); !ok {
		return fmt.Errorf("%q is not the agent package", spec)
	}
	if err := packages.SetRuntimeDir("/var/lib/flotestro-helper"); err != nil {
		return fmt.Errorf("the working directory of the helper: %w", err)
	}
	manager, err := packages.Detect()
	if err != nil {
		return err
	}
	lifecycle, ok := manager.(packages.Lifecycle)
	if !ok {
		return fmt.Errorf("the manager %s does not support installing packages", manager.Name())
	}
	// The version is given explicitly, so a downgrade is an operator decision
	// as well: that is how the return after a failed agent release works.
	apply, err := lifecycle.Install(ctx, packages.Options{
		Mode:           packages.ModeInstall,
		Packages:       []string{spec},
		AllowDowngrade: true,
	})
	if err != nil {
		// There is nobody for the result to return to - the agent is no longer
		// listening to this transaction. The host journal is the only place the
		// reason stays in; the panel will only see that the host did not come
		// back in the requested version.
		log.Error("the agent replacement failed",
			"package", spec, "manager", manager.Name(),
			"changed", len(apply.Applied), "err", err)
		return err
	}
	log.Info("the agent replacement was performed",
		"package", spec, "manager", manager.Name(), "changed", len(apply.Applied))
	return nil
}
