package packages

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	aptGetPath     = "/usr/bin/apt-get"
	dpkgPath       = "/usr/bin/dpkg"
	dpkgQueryPath  = "/usr/bin/dpkg-query"
	aptMarkPath    = "/usr/bin/apt-mark"
	dpkgStatusPath = "/var/lib/dpkg/status"
	// The debconf tools serve only to unblock a package that waits for a
	// decision of the operator.
	debconfShowPath = "/usr/bin/debconf-show"
	debconfSetPath  = "/usr/bin/debconf-set-selections"
)

// aptLockFiles are the files APT and dpkg lock for the duration of an
// operation.
var aptLockFiles = []string{
	"/var/lib/dpkg/lock-frontend",
	"/var/lib/dpkg/lock",
	"/var/cache/apt/archives/lock",
	"/var/lib/apt/lists/lock",
}

// APT is the adapter of Debian and Ubuntu.
type APT struct{}

func (a *APT) Name() string { return "apt" }

func (a *APT) Available() bool {
	info, err := os.Stat(aptGetPath)
	return err == nil && !info.IsDir()
}

// LockHeld checks the locks of dpkg and APT. We do not work around a lock: a
// concurrent transaction can damage the package database.
func (a *APT) LockHeld() (bool, string) {
	for _, path := range aptLockFiles {
		if held, checked := lockHeld(path); checked && held {
			return true, path
		}
	}
	return false, ""
}

// Plan computes the upgrade through a simulation. A simulation needs neither
// the lock nor root, so planning does not collide with the manual work of the
// administrator.
func (a *APT) Plan(ctx context.Context, options Options) (Plan, error) {
	plan := Plan{Manager: a.Name(), DiskAvailableBytes: diskAvailable("/"), Mode: options.Mode}
	// A package waiting for its configuration stops every transaction, so the
	// plan says so at once. Without that the operator learns about the block
	// only after a failed upgrade.
	plan.Blocked = a.BlockedPackages(ctx)

	switch options.Mode {
	case ModeRemove:
		return a.planRemove(ctx, plan, options)
	case ModeInstall:
		return a.planInstall(ctx, plan, options)
	}

	result := run(ctx, 3*time.Minute, aptGetPath,
		"--simulate", "--quiet", "-o", "Debug::NoLocking=true", "upgrade")
	if !result.Ran || result.ExitCode != 0 {
		return plan, fmt.Errorf("the apt simulation: %s", result.Reason())
	}

	for _, line := range strings.Split(result.Stdout, "\n") {
		change, ok := parseAptInstLine(line)
		if !ok || !matchesFilter(change, options) {
			continue
		}
		plan.Changes = append(plan.Changes, change)
	}

	plan.DownloadBytes = a.downloadSize(ctx, options)
	plan.RebootPredicted = a.rebootPredicted(plan.Changes)
	return plan, nil
}

// parseAptInstLine reads a line of the form:
//
//	Inst libfoo [1.0-1] (1.0-2 Debian:12/stable [amd64])
//
// The format is stable under LC_ALL=C and does not depend on the language of
// the interface.
func parseAptInstLine(line string) (Change, bool) {
	if !strings.HasPrefix(line, "Inst ") {
		return Change{}, false
	}
	rest := strings.TrimPrefix(line, "Inst ")
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return Change{}, false
	}

	change := Change{Name: fields[0]}
	if start := strings.Index(rest, "["); start >= 0 {
		if end := strings.Index(rest[start:], "]"); end > 0 {
			change.CurrentVersion = rest[start+1 : start+end]
		}
	}
	if start := strings.Index(rest, "("); start >= 0 {
		if end := strings.LastIndex(rest, ")"); end > start {
			inner := strings.Fields(rest[start+1 : end])
			if len(inner) > 0 {
				change.CandidateVersion = inner[0]
			}
			if len(inner) > 1 {
				change.Origin = strings.Join(inner[1:], " ")
			}
		}
	}
	// The security repositories of Debian and Ubuntu have a recognisable
	// origin.
	origin := change.Origin
	change.Security = strings.Contains(origin, "-security") ||
		strings.Contains(origin, "Debian-Security") ||
		strings.Contains(origin, "Ubuntu:") && strings.Contains(origin, "security")
	return change, true
}

// downloadSize sums up the sizes of the packages to fetch. The value is an
// estimate of the plan rather than a promise; on an error we return zero
// instead of guessing.
func (a *APT) downloadSize(ctx context.Context, options Options) uint64 {
	result := run(ctx, 2*time.Minute, aptGetPath,
		"--print-uris", "--quiet", "--yes", "-o", "Debug::NoLocking=true", "upgrade")
	if !result.Ran || result.ExitCode != 0 {
		return 0
	}
	var total uint64
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		// The format: 'uri' file_name size SHA256:...
		if len(fields) < 3 || !strings.HasPrefix(fields[0], "'") {
			continue
		}
		if size, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
			total += size
		}
	}
	return total
}

// rebootPredicted guesses the need for a restart from the packages being
// upgraded. It is a prediction of the plan rather than the state of the host.
func (a *APT) rebootPredicted(changes []Change) bool {
	for _, change := range changes {
		name := change.Name
		if strings.HasPrefix(name, "linux-image") || strings.HasPrefix(name, "linux-generic") ||
			name == "libc6" || strings.HasPrefix(name, "systemd") {
			return true
		}
	}
	return false
}

// Refresh refreshes the metadata of the repository. It requires root and the
// lock.
func (a *APT) Refresh(ctx context.Context) error {
	if held, path := a.LockHeld(); held {
		return fmt.Errorf("%w: %s", ErrLocked, path)
	}
	result := run(ctx, 5*time.Minute, aptGetPath, "update", "--quiet")
	if !result.Ran || result.ExitCode != 0 {
		return fmt.Errorf("apt-get update: %s", result.Reason())
	}
	return nil
}

// Upgrade carries the transaction out. The behaviour towards conffiles is
// defined explicitly: we keep the file of the administrator and never ask
// interactively. A prompt in this mode would mean a hang rather than a
// success.
func (a *APT) Upgrade(ctx context.Context, options Options) (Apply, error) {
	apply := Apply{Manager: a.Name()}

	if held, path := a.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}

	// A transaction can pull a rebuild of the initramfs. When the process does
	// not see the kernel modules, the image comes out without the disk driver
	// and the host does not come up after a restart - better not to start.
	if hidden, dir := modulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	// The versions from before the transaction are always recorded, also when
	// the transaction fails.
	before := a.installedVersions(ctx)

	// APT has no "security only" mode: apt-get upgrade raises everything that
	// can be raised. The narrowing is therefore computed from the plan and
	// passed as a list of names - otherwise the operator would approve three
	// security packages and the host would raise forty.
	if options.SecurityOnly && len(options.Packages) == 0 {
		plan, err := a.Plan(ctx, options)
		if err != nil {
			return apply, err
		}
		if len(plan.Changes) == 0 {
			// No security updates is not an error and must not turn into a
			// full upgrade of the host.
			return apply, nil
		}
		for _, change := range plan.Changes {
			// The agent package has an operation of its own for replacing it:
			// raised in this transaction it would stop the helper that runs
			// it. The remaining protected packages are raised normally - the
			// protection covers removing them rather than security updates.
			if change.Name == AgentPackage {
				continue
			}
			options.Packages = append(options.Packages, change.Name)
		}
		if len(options.Packages) == 0 {
			return apply, nil
		}
	}

	args := []string{
		"--yes", "--quiet",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "APT::Get::Assume-Yes=true",
		"upgrade",
	}
	// An ordinary upgrade does not touch the agent: replacing it in the middle
	// of a transaction it carries out itself ends with a host cut off halfway
	// through the work and a result nobody collects. APT has no exclusions, so
	// the package is held for the duration of the transaction and released
	// afterwards. Replacing the agent has an operation of its own that skips
	// this deliberately.
	if release, err := a.holdAgent(ctx); err == nil {
		defer release()
	}
	if len(options.Packages) > 0 {
		args = append([]string{"--yes", "--quiet",
			"-o", "Dpkg::Options::=--force-confold",
			"-o", "Dpkg::Options::=--force-confdef",
			"install", "--only-upgrade"}, options.Packages...)
	}

	// Apt reports progress over a machine channel of its own on descriptor 3.
	if options.Progress != nil {
		args = append([]string{"-o", "APT::Status-Fd=3"}, args...)
	}
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, options.Progress != nil,
		aptGetPath, args...)

	// A damaged archive in the cache repairs itself, because it has one
	// correct answer. A configuration question of a package has none and is
	// left to the operator - that is the boundary between repairing and
	// deciding for a person.
	if (!result.Ran || result.ExitCode != 0) && BrokenDownload(result.Stderr, result.Stdout) {
		cleaning := run(ctx, 5*time.Minute, aptGetPath, "--quiet", "clean")
		if cleaning.Ran && cleaning.ExitCode == 0 {
			apply.SelfRepair = append(apply.SelfRepair,
				"the damaged archives were removed from the cache and the transaction was retried")
			result = runWithProgress(ctx, 45*time.Minute, options.Progress,
				options.Progress != nil, aptGetPath, args...)
		}
	}

	after := a.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.PackagesNeedingAttention = a.PackagesNeedingAttention(ctx)
	apply.DatabaseBroken = len(apply.PackagesNeedingAttention) > 0
	apply.RebootRequired = fileExists("/var/run/reboot-required") || fileExists("/run/reboot-required")
	apply.ServicesNeedingRestart = a.servicesNeedingRestart(ctx)

	if !result.Ran || result.ExitCode != 0 {
		// The name of the package goes into the message, because without it the
		// operator knows only that the transaction failed and has to log into
		// the host to establish the cause.
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		if len(apply.PackagesNeedingAttention) > 0 {
			return apply, fmt.Errorf("apt-get upgrade: %s; needs attention: %s",
				result.Reason(), strings.Join(apply.PackagesNeedingAttention, ", "))
		}
		return apply, fmt.Errorf("apt-get upgrade: %s", result.Reason())
	}
	return apply, nil
}

// installedVersions returns a map of package -> version.
func (a *APT) installedVersions(ctx context.Context) map[string]string {
	result := run(ctx, 2*time.Minute, dpkgQueryPath, "-W", "-f", "${binary:Package} ${Version}\n")
	if !result.Ran || result.ExitCode != 0 {
		return nil
	}
	versions := map[string]string{}
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			versions[fields[0]] = fields[1]
		}
	}
	return versions
}

// DatabaseBroken checks whether dpkg was left in a state that needs
// repairing. After such a failure the following campaigns on the host have to
// be held back.
func (a *APT) DatabaseBroken(ctx context.Context) bool {
	return len(a.PackagesNeedingAttention(ctx)) > 0
}

// PackagesNeedingAttention lists the packages whose state blocks a
// transaction.
//
// The state is read straight from the dpkg database rather than through "dpkg
// --audit": the audit needs access to the lock of the database directory,
// which the agent without root does not have. The status file is readable by
// everyone, so the same information is available both to the agent and to the
// helper - and the plan of an operation can warn about the block before anyone
// orders an upgrade.
func (a *APT) PackagesNeedingAttention(ctx context.Context) []string {
	blocked := a.blockedFromStatus()
	names := make([]string, 0, len(blocked))
	for _, pkg := range blocked {
		names = append(names, pkg.Name)
	}
	return names
}

// blockedFromStatus parses /var/lib/dpkg/status and returns the packages in a
// state other than fully installed or entirely removed.
func (a *APT) blockedFromStatus() []Blocked {
	return blockedFromStatusFile(dpkgStatusPath)
}

// blockedFromStatusFile is separated out so that the parsing can be checked
// without changing the package database of a running system.
func blockedFromStatusFile(path string) []Blocked {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var blocked []Blocked
	for _, stanza := range strings.Split(string(data), "\n\n") {
		var name, status string
		for _, line := range strings.Split(stanza, "\n") {
			switch {
			case strings.HasPrefix(line, "Package: "):
				name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
			case strings.HasPrefix(line, "Status: "):
				status = strings.TrimSpace(strings.TrimPrefix(line, "Status: "))
			}
		}
		if name == "" || status == "" {
			continue
		}
		fields := strings.Fields(status)
		if len(fields) != 3 {
			continue
		}
		// The third field describes the actual state of the package. Installed
		// and configuration files alone block nothing; every other state means
		// dpkg did not finish its work and will do it during the next
		// transaction - and may fail on it then.
		switch fields[2] {
		case "installed", "config-files", "not-installed":
			continue
		}
		blocked = append(blocked, Blocked{Name: name, Status: status})
	}
	return blocked
}

// servicesNeedingRestart reads the list written by needrestart, if it is
// installed. A missing tool means an empty list rather than no need.
func (a *APT) servicesNeedingRestart(ctx context.Context) []string {
	const path = "/var/run/reboot-required.pkgs"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var packages []string
	for _, line := range strings.Split(string(data), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			packages = append(packages, trimmed)
		}
	}
	return packages
}

// diffVersions compares the state before and after the transaction.
func diffVersions(before, after map[string]string) []Change {
	var changes []Change
	for name, newVersion := range after {
		oldVersion := before[name]
		if oldVersion != newVersion {
			changes = append(changes, Change{
				Name:             name,
				CurrentVersion:   oldVersion,
				CandidateVersion: newVersion,
			})
		}
	}
	return changes
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// planRemove computes what will disappear along with the named packages.
//
// Removing one package can pull dozens of dependent ones. The operator is to
// see the full list before the approval rather than discover it after the
// fact, when the host can no longer be restored without a registry.
func (a *APT) planRemove(ctx context.Context, plan Plan, options Options) (Plan, error) {
	if len(options.Packages) == 0 {
		return plan, fmt.Errorf("a removal plan requires a list of packages")
	}
	args := append([]string{"--simulate", "--quiet", "-o", "Debug::NoLocking=true", "remove"},
		options.Packages...)
	result := run(ctx, 3*time.Minute, aptGetPath, args...)
	if !result.Ran || result.ExitCode != 0 {
		return plan, fmt.Errorf("the removal simulation: %s", result.Reason())
	}

	for _, line := range strings.Split(result.Stdout, "\n") {
		name, ok := parseAptRemvLine(line)
		if !ok {
			continue
		}
		plan.Removals = append(plan.Removals, name)
	}
	plan.Protected = ProtectedInSet(plan.Removals)
	return plan, nil
}

// planInstall computes what will arrive along with the named packages.
func (a *APT) planInstall(ctx context.Context, plan Plan, options Options) (Plan, error) {
	if len(options.Packages) == 0 {
		return plan, fmt.Errorf("an installation plan requires a list of packages")
	}
	args := append([]string{"--simulate", "--quiet", "-o", "Debug::NoLocking=true", "install"},
		options.Packages...)
	result := run(ctx, 3*time.Minute, aptGetPath, args...)
	if !result.Ran || result.ExitCode != 0 {
		return plan, fmt.Errorf("the installation simulation: %s", result.Reason())
	}

	for _, line := range strings.Split(result.Stdout, "\n") {
		if change, ok := parseAptInstLine(line); ok {
			plan.Changes = append(plan.Changes, change)
		}
		// An installation can remove as well: a conflict of packages ends with
		// a replacement rather than an addition.
		if name, ok := parseAptRemvLine(line); ok {
			plan.Removals = append(plan.Removals, name)
		}
	}
	plan.Protected = ProtectedInSet(plan.Removals)
	plan.DownloadBytes = a.downloadSize(ctx, options)
	return plan, nil
}

// parseAptRemvLine reads a line of the form:
//
//	Remv libfoo [1.0-1]
func parseAptRemvLine(line string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || fields[0] != "Remv" {
		return "", false
	}
	return fields[1], true
}

// holdAgent holds the agent package for the duration of one transaction.
//
// It returns the releasing function. When the package was held earlier by the
// administrator we do not release it: the decision of the operator of the host
// weighs more than the convenience of one transaction.
func (a *APT) holdAgent(ctx context.Context) (func(), error) {
	state := run(ctx, 30*time.Second, aptMarkPath, "showhold")
	if !state.Ran {
		return nil, fmt.Errorf("apt-mark showhold: %s", state.Reason())
	}
	if strings.Contains(state.Stdout, AgentPackage) {
		return func() {}, nil
	}
	if result := run(ctx, 30*time.Second, aptMarkPath, "hold", AgentPackage); !result.Ran ||
		result.ExitCode != 0 {
		return nil, fmt.Errorf("apt-mark hold: %s", result.Reason())
	}
	// The trace of our own hold. A transaction can die with its process - the
	// deferred release does not run then and the package stays held for good,
	// blocking every later replacement of the agent. This file is how we
	// recognise our own hold, and only such a hold is released: the decision
	// of the administrator of the host stays untouched.
	_ = os.WriteFile(holdTrace(), []byte(AgentPackage+"\n"), 0o600)

	return func() {
		// The context of the transaction may already be cancelled and the
		// release has to run anyway: a package left on hold would block a
		// later replacement of the agent.
		releasing, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		run(releasing, 30*time.Second, aptMarkPath, "unhold", AgentPackage)
		_ = os.Remove(holdTrace())
	}, nil
}

// holdTrace names the marker file of our own hold on the agent package.
func holdTrace() string {
	return filepath.Join(runtimeDir, "state", "agent-hold")
}

// legacyHoldTrace is the name earlier helpers gave the marker. A host
// upgraded with an abandoned hold from such a helper still has it under
// the old name, and it has to be released the same way.
func legacyHoldTrace() string {
	return filepath.Join(runtimeDir, "state", "wstrzymany-agent")
}

// ReleaseAbandonedHold lifts the hold on the agent package left behind by a
// transaction that did not reach its end.
//
// Called at the start of the helper. Without it a host whose transaction died
// with its process was left with the agent package held for good - and no
// later replacement of the agent could go through.
func ReleaseAbandonedHold(ctx context.Context) (bool, error) {
	trace := holdTrace()
	if _, err := os.Stat(trace); err != nil {
		trace = legacyHoldTrace()
		if _, err := os.Stat(trace); err != nil {
			return false, nil
		}
	}
	defer func() { _ = os.Remove(trace) }()

	// A host without apt has nothing to release. The trace was removed above,
	// so the attempt does not come back at every start of the helper.
	if _, err := os.Stat(aptMarkPath); err != nil {
		return false, nil
	}
	state := run(ctx, 30*time.Second, aptMarkPath, "showhold")
	if !state.Ran {
		return false, fmt.Errorf("apt-mark showhold: %s", state.Reason())
	}
	if !strings.Contains(state.Stdout, AgentPackage) {
		return false, nil
	}
	if result := run(ctx, 30*time.Second, aptMarkPath, "unhold", AgentPackage); !result.Ran ||
		result.ExitCode != 0 {
		return false, fmt.Errorf("apt-mark unhold: %s", result.Reason())
	}
	return true, nil
}

func (a *APT) Install(ctx context.Context, options Options) (Apply, error) {
	apply := Apply{Manager: a.Name()}
	if len(options.Packages) == 0 {
		return apply, fmt.Errorf("an installation requires a list of packages")
	}
	if held, path := a.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}
	if hidden, dir := modulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	before := a.installedVersions(ctx)
	args := []string{"--yes", "--quiet",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Options::=--force-confdef"}
	if options.AllowDowngrade {
		args = append(args, "--allow-downgrades")
	}
	// A hold on a package protects it from an ordinary upgrade rather than
	// from an operation that names the version outright.
	if options.AllowDowngrade {
		args = append(args, "--allow-change-held-packages")
	}
	args = append(append(args, "install"), options.Packages...)
	if options.Progress != nil {
		args = append([]string{"-o", "APT::Status-Fd=3"}, args...)
	}
	result := runWithProgress(ctx, 45*time.Minute, options.Progress,
		options.Progress != nil, aptGetPath, args...)

	after := a.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.PackagesNeedingAttention = a.PackagesNeedingAttention(ctx)
	apply.DatabaseBroken = len(apply.PackagesNeedingAttention) > 0
	apply.RebootRequired = fileExists("/var/run/reboot-required") || fileExists("/run/reboot-required")
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, fmt.Errorf("apt-get install: %s", result.Reason())
	}
	return apply, nil
}

// Remove removes the named packages along with their dependencies.
//
// The set to remove is computed again right before the operation and compared
// with what the operator approved. A difference means the host has changed
// since the plan and a different set would be removed - and a refusal is then
// the right reaction rather than carrying out something nobody saw.
func (a *APT) Remove(ctx context.Context, options Options, expected []string) (Apply, error) {
	apply := Apply{Manager: a.Name()}
	if len(options.Packages) == 0 {
		return apply, fmt.Errorf("a removal requires a list of packages")
	}
	if held, path := a.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}

	plan, err := a.Plan(ctx, Options{Mode: ModeRemove, Packages: options.Packages})
	if err != nil {
		return apply, err
	}
	if len(plan.Protected) > 0 {
		return apply, fmt.Errorf("%w: %s", ErrProtectedPackage, strings.Join(plan.Protected, ", "))
	}
	if difference := compareSets(expected, plan.Removals); difference != "" {
		return apply, fmt.Errorf("%w: %s", ErrPlanChanged, difference)
	}

	before := a.installedVersions(ctx)
	args := append([]string{"--yes", "--quiet", "remove"}, options.Packages...)
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, false, aptGetPath, args...)

	after := a.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.PackagesNeedingAttention = a.PackagesNeedingAttention(ctx)
	apply.DatabaseBroken = len(apply.PackagesNeedingAttention) > 0
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, fmt.Errorf("apt-get remove: %s", result.Reason())
	}
	return apply, nil
}

// SetHold holds or releases the upgrades of packages.
func (a *APT) SetHold(ctx context.Context, pkgs []string, hold bool) (Apply, error) {
	apply := Apply{Manager: a.Name()}
	if len(pkgs) == 0 {
		return apply, fmt.Errorf("a hold requires a list of packages")
	}
	operation := "unhold"
	if hold {
		operation = "hold"
	}
	args := append([]string{operation}, pkgs...)
	result := run(ctx, time.Minute, aptMarkPath, args...)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, fmt.Errorf("apt-mark %s: %s", operation, result.Reason())
	}
	return apply, nil
}

// Holds returns the packages held on the host.
func (a *APT) Holds(ctx context.Context) []string {
	result := run(ctx, 30*time.Second, aptMarkPath, "showhold")
	if !result.Ran || result.ExitCode != 0 {
		return nil
	}
	var held []string
	for _, line := range strings.Split(result.Stdout, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			held = append(held, name)
		}
	}
	return held
}
