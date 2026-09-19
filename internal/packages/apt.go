package packages

import (
	"bufio"
	"context"
	"errors"
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
	aptCachePath   = "/usr/bin/apt-cache"
	dpkgStatusPath = "/var/lib/dpkg/status"
	// aptListsDir holds the package lists and the release files that sign
	// them; the release files are the identity of the metadata a plan reads.
	aptListsDir = "/var/lib/apt/lists"
	// The archives land in the cache and the database lives under /var/lib;
	// both are on /var, which is often a file system of its own.
	aptCacheDir     = "/var/cache/apt/archives"
	dpkgDatabaseDir = "/var/lib/dpkg"
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

// Plan computes the upgrade through a simulation.
func (a *APT) Plan(ctx context.Context, options Options) (Plan, error) {
	plan, err := a.plan(ctx, options)
	if err != nil {
		return plan, err
	}
	return finishPlan(ctx, a, plan, options), nil
}

func (a *APT) plan(ctx context.Context, options Options) (Plan, error) {
	plan := Plan{Manager: a.Name(), DiskAvailableBytes: diskAvailable("/"), Mode: options.Mode}
	// A package waiting for its configuration stops every transaction, so the
	// plan says so at once.
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
		// An upgrade can drop a package as well - a conflict resolved by a
		// replacement - and that is a removal the operator approves or not.
		if name, ok := parseAptRemvLine(line); ok {
			plan.Removals = append(plan.Removals, name)
		}
	}

	// The archives of a narrowed upgrade are those of the named packages, not of
	// everything apt-get would raise; the transaction narrows the same way, with
	// "install --only-upgrade" and the names.
	sizing := []string{"upgrade"}
	if options.SecurityOnly || len(options.Packages) > 0 {
		sizing = append([]string{"install", "--only-upgrade"}, changeNames(plan.Changes)...)
	}
	plan.DownloadBytes, plan.Space = a.planSpace(ctx, plan.Changes, sizing)
	plan.RebootPredicted = a.rebootPredicted(plan.Changes)
	return plan, nil
}

// planSpace measures where the bytes of the plan go.
func (a *APT) planSpace(ctx context.Context, changes []Change, sizing []string) (uint64, []SpaceFact) {
	// Nothing to change needs nothing; the tools are not asked about an
	// empty set, which apt-get would read as "everything".
	needs := spaceNeeds{downloadKnown: true, installBasis: BasisInstalledSize}
	if len(changes) == 0 {
		return 0, spaceFacts(aptCacheDir, dpkgDatabaseDir, needs)
	}
	var digests map[string]string
	needs.download, digests, needs.downloadKnown = a.downloadManifest(ctx, sizing...)
	needs.kernel = anyKernel(a.Name(), changes)
	names := changeNames(changes)
	candidate, installed := a.candidateSizes(ctx, names), a.installedSizes(ctx, names)
	grown, measured := growth(names, candidate, installed)
	installNeeds(&needs, grown, measured)
	// The plan carries per package what the sums were made of: the digest of the
	// archive the index publishes and the growth of the installed files, each
	// only where it was measured.
	for i := range changes {
		change := &changes[i]
		if digest, ok := digests[change.Name]; ok {
			change.Digest = digest
		}
		if size, ok := candidate[change.Name]; ok {
			change.InstalledDeltaBytes = int64(size) - int64(installed[change.Name])
			change.InstalledDeltaKnown = true
		}
	}
	return needs.download, spaceFacts(aptCacheDir, dpkgDatabaseDir, needs)
}

// changeNames lists the names of the changes in their order.
func changeNames(changes []Change) []string {
	names := make([]string, 0, len(changes))
	for _, change := range changes {
		names = append(names, change.Name)
	}
	return names
}

// candidateSizes reads the installed size of the candidate version of every
// named package.
func (a *APT) candidateSizes(ctx context.Context, names []string) map[string]uint64 {
	result := run(ctx, 2*time.Minute, aptCachePath,
		append([]string{"--no-all-versions", "show"}, names...)...)
	if !result.Ran {
		return nil
	}
	// A name apt-cache does not know ends with the code 100 and the records
	// of the known ones on the standard output; what it printed is used.
	return ParseAPTCacheSizes(result.Stdout)
}

// installedSizes reads the installed size of the installed version of every
// named package.
func (a *APT) installedSizes(ctx context.Context, names []string) map[string]uint64 {
	result := run(ctx, 2*time.Minute, dpkgQueryPath,
		append([]string{"-W", "-f", "${binary:Package}\t${Installed-Size}\n"}, names...)...)
	if !result.Ran {
		return nil
	}
	return ParseInstalledSizeLines(result.Stdout)
}

// ParseAPTCacheSizes reads the records of "apt-cache show": the Package and
// the Installed-Size fields, the latter in KiB.
func ParseAPTCacheSizes(output string) map[string]uint64 {
	sizes := map[string]uint64{}
	name := ""
	for _, line := range strings.Split(output, "\n") {
		switch {
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		case strings.HasPrefix(line, "Installed-Size: ") && name != "":
			if kib, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "Installed-Size: ")), 10, 64); err == nil {
				sizes[name] = kib << 10
			}
		case strings.TrimSpace(line) == "":
			name = ""
		}
	}
	return sizes
}

// ParseInstalledSizeLines reads lines of "name<TAB>KiB", as dpkg-query prints
// them with the format above.
func ParseInstalledSizeLines(output string) map[string]uint64 {
	sizes := map[string]uint64{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) != 2 {
			continue
		}
		if kib, err := strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64); err == nil {
			sizes[fields[0]] = kib << 10
		}
	}
	return sizes
}

// parseAptInstLine reads a line of the form: Inst libfoo [1. 0-1] (1.
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
	// The current version stands in brackets before the parenthesis; the brackets
	// after it hold the architecture, and a fresh install has no current version
	// at all.
	head := rest
	if open := strings.Index(rest, "("); open >= 0 {
		head = rest[:open]
	}
	if start := strings.Index(head, "["); start >= 0 {
		if end := strings.Index(head[start:], "]"); end > 0 {
			change.CurrentVersion = head[start+1 : start+end]
		}
	}
	if start := strings.Index(rest, "("); start >= 0 {
		if end := strings.LastIndex(rest, ")"); end > start {
			inner := strings.Fields(rest[start+1 : end])
			if len(inner) > 0 {
				change.CandidateVersion = inner[0]
			}
			// The architecture closes the line in brackets; what stands between the
			// version and it is the origin, possibly more than one repository separated
			// by commas.
			if last := len(inner) - 1; last > 0 && strings.HasPrefix(inner[last], "[") && strings.HasSuffix(inner[last], "]") {
				change.Architecture = strings.Trim(inner[last], "[]")
				inner = inner[:last]
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

// downloadManifest reads what the operation fetches: the sum of the sizes of
// the archives and the digest of each, keyed by package name.
func (a *APT) downloadManifest(ctx context.Context, operation ...string) (uint64, map[string]string, bool) {
	args := append([]string{"--print-uris", "--quiet", "--yes", "-o", "Debug::NoLocking=true"},
		operation...)
	result := run(ctx, 2*time.Minute, aptGetPath, args...)
	if !result.Ran || result.ExitCode != 0 {
		return 0, nil, false
	}
	total, digests := ParseAPTPrintURIs(result.Stdout)
	return total, digests, true
}

// ParseAPTPrintURIs reads the lines of apt-get --print-uris: 'http://deb.
// debian.
func ParseAPTPrintURIs(output string) (uint64, map[string]string) {
	var total uint64
	digests := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasPrefix(fields[0], "'") {
			continue
		}
		if size, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
			total += size
		}
		// The file name is name_version_arch.deb; the name ends at the
		// first underscore, and a version never carries one.
		name, _, found := strings.Cut(fields[1], "_")
		if !found || len(fields) < 4 {
			continue
		}
		algorithm, sum, found := strings.Cut(fields[3], ":")
		if found && sum != "" {
			digests[name] = strings.ToLower(algorithm) + ":" + strings.ToLower(sum)
		}
	}
	return total, digests
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

// Upgrade carries the transaction out.
func (a *APT) Upgrade(ctx context.Context, options Options) (Apply, error) {
	apply := Apply{Manager: a.Name()}

	if held, path := a.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}

	// A transaction can pull a rebuild of the initramfs.
	if hidden, dir := modulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	// The versions from before the transaction are always recorded, also when
	// the transaction fails.
	before := a.installedVersions(ctx)

	// APT has no "security only" mode: apt-get upgrade raises everything that can
	// be raised.
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
			// The agent package has an operation of its own for replacing it: raised in
			// this transaction it would stop the helper that runs it.
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
	// An ordinary upgrade does not touch the agent: replacing it in the middle of
	// a transaction it carries out itself ends with a host cut off halfway
	// through the work and a result nobody collects.
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

	// A damaged archive in the cache repairs itself, because it has one correct
	// answer.
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
		// operator knows only that the transaction failed and has to log into the
		// host to establish the cause.
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
	// Both spellings of the name are recorded: a package that may be installed
	// for more than one architecture is printed by dpkg as name:arch, while apt
	// names it without the suffix in a plan.
	versions := map[string]string{}
	result := runLines(ctx, 2*time.Minute, func(line string) {
		addInstalledDebian(versions, line)
	}, dpkgQueryPath, "-W", "-f",
		"${Package} ${Architecture} ${Version} ${db:Status-Status}\n")
	if !result.Complete() {
		return nil
	}
	return versions
}

// parseInstalledDebian reads what dpkg-query printed.
func parseInstalledDebian(output string) map[string]string {
	versions := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		addInstalledDebian(versions, line)
	}
	return versions
}

// addInstalledDebian records one row of "dpkg-query -W".
func addInstalledDebian(versions map[string]string, line string) {
	fields := strings.Fields(line)
	if len(fields) != 4 || fields[3] != "installed" {
		return
	}
	name, architecture, version := fields[0], fields[1], fields[2]
	// A second architecture of the same package would otherwise overwrite the
	// first under the bare name; the qualified name stays exact either way.
	if _, taken := versions[name]; !taken {
		versions[name] = version
	}
	versions[name+":"+architecture] = version
}

// DatabaseBroken checks whether dpkg was left in a state that needs repairing.
func (a *APT) DatabaseBroken(ctx context.Context) bool {
	return len(a.PackagesNeedingAttention(ctx)) > 0
}

// PackagesNeedingAttention lists the packages whose state blocks a
// transaction.
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
// without changing the package database of a running system. The file carries
// the description of every package, so it is read stanza by stanza.
func blockedFromStatusFile(path string) []Blocked {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var blocked []Blocked
	var name, status string
	closeStanza := func() {
		defer func() { name, status = "", "" }()
		if name == "" || status == "" {
			return
		}
		fields := strings.Fields(status)
		if len(fields) != 3 {
			return
		}
		// The third field describes the actual state of the package.
		switch fields[2] {
		case "installed", "config-files", "not-installed":
			return
		}
		blocked = append(blocked, Blocked{Name: name, Status: status})
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			closeStanza()
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		case strings.HasPrefix(line, "Status: "):
			status = strings.TrimSpace(strings.TrimPrefix(line, "Status: "))
		}
	}
	if scanner.Err() != nil {
		// A file read only in part says nothing about the packages below the
		// hole, and a shorter list of blocked packages would read as fewer.
		return nil
	}
	closeStanza()
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
// Removing one package can pull dozens of dependent ones.
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
	plan.DownloadBytes, plan.Space = a.planSpace(ctx, plan.Changes,
		append([]string{"install"}, options.Packages...))
	return plan, nil
}

// parseAptRemvLine reads a line of the form: Remv libfoo [1.
func parseAptRemvLine(line string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || fields[0] != "Remv" {
		return "", false
	}
	return fields[1], true
}

// holdAgent holds the agent package for the duration of one transaction. It
// returns the releasing function.
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
	// The trace of our own hold.
	_ = os.WriteFile(holdTrace(), []byte(AgentPackage+"\n"), 0o600)

	return func() {
		// The context of the transaction may already be cancelled and the release
		// has to run anyway: a package left on hold would block a later replacement
		// of the agent.
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

// legacyHoldTrace is the name earlier helpers gave the marker.
func legacyHoldTrace() string {
	return filepath.Join(runtimeDir, "state", "wstrzymany-agent")
}

// ReleaseAbandonedHold lifts the hold on the agent package left behind by a
// transaction that did not reach its end.
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

// Holds returns the packages held on the host. The read needs no root:
// apt-mark reads the selections out of the dpkg database.
func (a *APT) Holds(ctx context.Context) ([]string, string) {
	result := run(ctx, 30*time.Second, aptMarkPath, "showhold")
	if !result.Ran || result.ExitCode != 0 {
		return nil, "apt-mark showhold: " + result.Reason()
	}
	held := []string{}
	for _, line := range strings.Split(result.Stdout, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			held = append(held, name)
		}
	}
	return held, ""
}

// --- What proves the origin of a package file on the apt family ---------
// A .deb carries no signature: the proof is the index, where InRelease covers
// Packages and Packages the checksum of every package file.

// The typed reasons an apt host cannot establish the origin of a package file.
const (
	// APTProofUnsigned means the repository publishes no signed index at all.
	APTProofUnsigned = "apt_repository_unsigned"
	// APTProofKeyUntrusted means the index is signed by a key apt does not hold.
	APTProofKeyUntrusted = "apt_index_key_untrusted"
	// APTProofIndexUnreadable means the index of that repository is not on the
	// host or could not be read.
	APTProofIndexUnreadable = "apt_index_unreadable"
	// APTProofOriginUnknown means apt did not say which repository publishes
	// the file.
	APTProofOriginUnknown = "apt_artefact_origin_unknown"
	// APTProofDigestMismatch means the index publishes another file under that
	// name than the one the host holds.
	APTProofDigestMismatch = "apt_index_digest_mismatch"
)

// The prefixes that mark a signer value as the signature of a repository
// index rather than of the file, so an unproven order is never an empty field.
const (
	APTProofPrefix        = "apt-index:"
	APTProofUnknownPrefix = "apt-index-unknown:"
)

// gpgvPath is the tool apt itself verifies its indexes with.
const gpgvPath = "/usr/bin/gpgv"

// errAPTIndexUnreadable says the host could not verify the index at all, as
// opposed to reading it and finding a key it does not trust.
var errAPTIndexUnreadable = errors.New("the repository index could not be verified")

// minKeyDigits is the shortest key identity worth comparing: a short key ID is
// cheap enough to collide with that it establishes nobody.
const minKeyDigits = 16

// The apt state the proof reads. They are variables so that a test can point
// them at fixture files rather than at the host's own apt.
var (
	aptIndexDir       = aptListsDir
	aptTrustedKeyring = "/etc/apt/trusted.gpg"
	aptTrustedDir     = "/etc/apt/trusted.gpg.d"
	aptSourcesDir     = APTSourcesDir
	aptSourcesFile    = APTSourcesFile
)

// APTIndexProof is what an apt host can establish about the origin of a package
// file: the repository that publishes it and the key that signed its index.
type APTIndexProof struct {
	Established bool `json:"established"`
	// Reason is the typed code when nothing could be established.
	Reason      string `json:"reason,omitempty"`
	ArtefactURI string `json:"artefact_uri,omitempty"`
	IndexPath   string `json:"index_path,omitempty"`
	// SignedBy is the key gpgv accepted the signature of the index on.
	SignedBy string `json:"signed_by,omitempty"`
	// Detail says in one sentence what stood in the way.
	Detail string `json:"detail,omitempty"`
}

// Token renders the proof into the one field a package result carries for the
// signature: the key on success, the typed reason otherwise.
func (p APTIndexProof) Token() string {
	if p.Established && p.SignedBy != "" {
		return APTProofPrefix + p.SignedBy
	}
	reason := p.Reason
	if reason == "" {
		reason = APTProofIndexUnreadable
	}
	return APTProofUnknownPrefix + reason
}

// DescribeArtefactSigner puts into the result of a job what proved the origin
// of the file that was installed, in the words of the family it came from.
func DescribeArtefactSigner(value string) string {
	switch {
	case value == "":
		return "the signer of the artefact was not established"
	case strings.HasPrefix(value, APTProofPrefix):
		return "the proof is the repository index signed by " +
			strings.TrimPrefix(value, APTProofPrefix)
	case strings.HasPrefix(value, APTProofUnknownPrefix):
		return "the repository index proved nothing about the artefact (" +
			strings.TrimPrefix(value, APTProofUnknownPrefix) + ")"
	}
	return "the artefact was signed by " + value
}

// EstablishAPTIndexProof reads what an apt host can prove about a package file:
// which repository publishes it and which key apt trusts signed that index.
func EstablishAPTIndexProof(ctx context.Context, spec, artefactSHA256 string) APTIndexProof {
	uri, published, err := aptArtefactOrigin(ctx, spec)
	if err != nil {
		return APTIndexProof{Reason: APTProofOriginUnknown, Detail: err.Error()}
	}
	proof := APTIndexProof{ArtefactURI: uri}
	index, signature, reason, detail := aptIndexOf(uri)
	if reason != "" {
		proof.Reason, proof.Detail = reason, detail
		return proof
	}
	proof.IndexPath = index

	signer, err := aptIndexSigner(ctx, index, signature)
	if err != nil {
		proof.Reason, proof.Detail = APTProofKeyUntrusted, err.Error()
		// A host without the tool or without a key store has not judged the key;
		// it has not looked at it.
		if errors.Is(err, errAPTIndexUnreadable) {
			proof.Reason = APTProofIndexUnreadable
		}
		return proof
	}
	proof.SignedBy = signer

	// A signed index proves nothing about this file unless it is the file the
	// index publishes.
	if published == "" {
		proof.Reason = APTProofIndexUnreadable
		proof.Detail = "the index of " + index + " names no checksum for " + filepath.Base(uri)
		return proof
	}
	if artefactSHA256 != "" && !strings.EqualFold(published, artefactSHA256) {
		proof.Reason = APTProofDigestMismatch
		proof.Detail = "the index publishes " + published + " under that name and the host holds " +
			artefactSHA256
		return proof
	}
	proof.Established = true
	return proof
}

// aptArtefactOrigin asks apt where the package file of one specification comes
// from and what checksum its index publishes for it. Nothing is downloaded.
var aptArtefactOrigin = func(ctx context.Context, spec string) (string, string, error) {
	result := run(ctx, time.Minute, aptGetPath, "--yes", "--quiet", "--print-uris",
		"--reinstall", "--allow-downgrades", "--allow-change-held-packages",
		"-o", "Debug::NoLocking=true", "install", spec)
	if !result.Ran || result.ExitCode != 0 {
		return "", "", fmt.Errorf("apt-get --print-uris: %s", result.Reason())
	}
	uri, ok := ParseAPTArtefactURI(result.Stdout, AgentPackage)
	if !ok {
		return "", "", fmt.Errorf("apt named no source for %s", spec)
	}
	// The manifest of the same output carries the checksum the index publishes;
	// only a SHA-256 answers the digest an order names.
	_, digests := ParseAPTPrintURIs(result.Stdout)
	published, isSHA256 := strings.CutPrefix(digests[AgentPackage], "sha256:")
	if !isSHA256 {
		published = ""
	}
	return uri, published, nil
}

// ParseAPTArtefactURI reads the address one package is fetched from out of
// what apt-get --print-uris wrote; the manifest parser reads the rest.
func ParseAPTArtefactURI(output, name string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "'") {
			continue
		}
		// The file name is name_version_arch.deb; the name ends at the first
		// underscore, and a version never carries one.
		if file, _, found := strings.Cut(fields[1], "_"); !found || file != name {
			continue
		}
		if uri := strings.Trim(fields[0], "'"); uri != "" {
			return uri, true
		}
	}
	return "", false
}

// aptIndexOf finds the release file of the repository that publishes an
// address, or the typed reason why the host has none to read.
func aptIndexOf(uri string) (index, signature, reason, detail string) {
	target := APTFileName(uri)
	entries, err := os.ReadDir(aptIndexDir)
	if err != nil {
		return "", "", APTProofIndexUnreadable, "reading " + aptIndexDir + ": " + err.Error()
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	name, detached, ok := MatchAPTIndex(target, names)
	if !ok {
		return "", "", APTProofIndexUnreadable,
			"the host holds no release file of the repository that publishes " + target
	}
	index = filepath.Join(aptIndexDir, name)
	if detached == "" {
		return index, "", "", ""
	}
	// A release file without any signature beside it is a repository nobody
	// vouches for - which apt accepts only when the source says trusted.
	signature = filepath.Join(aptIndexDir, detached)
	if !fileExists(signature) {
		return "", "", APTProofUnsigned,
			"the repository publishes " + name + " and no signature of it"
	}
	return index, signature, "", ""
}

// MatchAPTIndex picks, among the files apt keeps in its lists directory, the
// release file of the repository an address belongs to.
func MatchAPTIndex(fileName string, names []string) (index, signature string, ok bool) {
	best, bestBase := "", ""
	for _, name := range names {
		base, isIndex := aptIndexBase(name)
		if !isIndex || !strings.HasPrefix(fileName, base+"_") {
			continue
		}
		// The longest base wins: two sources on one host differ by their path
		// alone, and the shorter one would swallow the longer one's packages.
		if len(base) < len(bestBase) {
			continue
		}
		if len(base) > len(bestBase) || strings.HasSuffix(name, "_InRelease") {
			bestBase, best = base, name
		}
	}
	switch {
	case best == "":
		return "", "", false
	case strings.HasSuffix(best, "_InRelease"):
		return best, "", true
	}
	return best, best + ".gpg", true
}

// aptIndexBase reduces the name of a release file to the repository it belongs
// to: the lists directory encodes the whole address in the name.
func aptIndexBase(name string) (string, bool) {
	trimmed, ok := strings.CutSuffix(name, "_InRelease")
	if !ok {
		if trimmed, ok = strings.CutSuffix(name, "_Release"); !ok {
			return "", false
		}
	}
	// A distribution tree carries the suite under dists/; a flat repository
	// has its release file directly beside the packages.
	if index := strings.LastIndex(trimmed, "_dists_"); index > 0 {
		return trimmed[:index], true
	}
	base := strings.TrimSuffix(trimmed, "_.")
	return base, base != ""
}

// APTFileName is the name apt gives a fetched address in its lists directory:
// the scheme goes, the credentials go, every slash becomes an underscore.
func APTFileName(uri string) string {
	name := uri
	if _, rest, found := strings.Cut(name, "://"); found {
		name = rest
	}
	host, path, hasPath := strings.Cut(name, "/")
	if _, rest, found := strings.Cut(host, "@"); found {
		host = rest
	}
	name = host
	if hasPath {
		name += "/" + path
	}
	return strings.ReplaceAll(strings.Trim(name, "/"), "/", "_")
}

// aptIndexSigner verifies a release file with gpgv against the keys apt itself
// trusts and names the key that signed it.
var aptIndexSigner = func(ctx context.Context, index, signature string) (string, error) {
	keyrings := APTTrustedKeyrings()
	if len(keyrings) == 0 {
		return "", fmt.Errorf("%w: apt holds no repository keys", errAPTIndexUnreadable)
	}
	args := make([]string, 0, 2*len(keyrings)+4)
	args = append(args, "--status-fd", "1")
	for _, keyring := range keyrings {
		args = append(args, "--keyring", keyring)
	}
	if signature != "" {
		args = append(args, signature)
	}
	args = append(args, index)
	result := run(ctx, 30*time.Second, gpgvPath, args...)
	if !result.Ran {
		return "", fmt.Errorf("%w: %s", errAPTIndexUnreadable, result.Reason())
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("gpgv did not accept %s against the keys apt trusts: %s",
			filepath.Base(index), result.Reason())
	}
	signer, ok := PGPStatusSigner(result.Stdout)
	if !ok {
		return "", fmt.Errorf("gpgv accepted %s without naming the key", filepath.Base(index))
	}
	return signer, nil
}

// APTTrustedKeyrings lists the key stores apt reads: its own trusted set and
// every keyring a source names with Signed-By.
func APTTrustedKeyrings() []string {
	var keyrings []string
	if fileExists(aptTrustedKeyring) {
		keyrings = append(keyrings, aptTrustedKeyring)
	}
	entries, _ := os.ReadDir(aptTrustedDir)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !(strings.HasSuffix(name, ".gpg") || strings.HasSuffix(name, ".asc")) {
			continue
		}
		keyrings = append(keyrings, filepath.Join(aptTrustedDir, name))
	}
	for _, path := range aptSignedByKeyrings() {
		if fileExists(path) {
			keyrings = append(keyrings, path)
		}
	}
	return keyrings
}

// aptSignedByKeyrings lists the keyrings the sources themselves name: apt
// trusts such a key for that one source, so the store is short without them.
func aptSignedByKeyrings() []string {
	files := []string{aptSourcesFile}
	entries, _ := os.ReadDir(aptSourcesDir)
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, filepath.Join(aptSourcesDir, entry.Name()))
		}
	}
	var paths []string
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		paths = append(paths, ParseAPTSignedBy(string(data))...)
	}
	return paths
}

// ParseAPTSignedBy reads the keyring paths a source names, in both formats apt
// understands. Inline key material names no file and is passed over.
func ParseAPTSignedBy(content string) []string {
	var paths []string
	add := func(value string) {
		for _, field := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ','
		}) {
			if strings.HasPrefix(field, "/") {
				paths = append(paths, field)
			}
		}
	}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if key, value, found := strings.Cut(trimmed, ":"); found &&
			strings.EqualFold(strings.TrimSpace(key), "signed-by") {
			add(value)
			continue
		}
		for _, field := range strings.Fields(trimmed) {
			if value, ok := strings.CutPrefix(strings.Trim(field, "[]"), "signed-by="); ok {
				add(value)
			}
		}
	}
	return paths
}

// PGPStatusSigner reads the fingerprint out of the status output of gpg or
// gpgv; VALIDSIG is written only for a signature that checked out.
func PGPStatusSigner(output string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		_, rest, found := strings.Cut(strings.TrimSpace(line), "[GNUPG:] VALIDSIG ")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 || !HexKeyIdentity(fields[0]) {
			continue
		}
		return strings.ToUpper(fields[0]), true
	}
	return "", false
}

// HexKeyIdentity says whether a value is a key identity long enough to name
// one key rather than a family of them.
func HexKeyIdentity(value string) bool {
	if len(value) < minKeyDigits {
		return false
	}
	for _, char := range value {
		switch {
		case char >= '0' && char <= '9':
		case char >= 'a' && char <= 'f':
		case char >= 'A' && char <= 'F':
		default:
			return false
		}
	}
	return true
}
