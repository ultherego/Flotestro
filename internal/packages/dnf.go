package packages

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	dnfPath = "/usr/bin/dnf"
	rpmPath = "/usr/bin/rpm"
)

// dnfLockFiles are the files locked for the duration of an RPM transaction.
var dnfLockFiles = []string{
	"/var/lib/rpm/.rpm.lock",
	"/var/cache/dnf/metadata_lock.pid",
}

// DNF is the adapter of Fedora and of the systems of the RHEL family.
type DNF struct{}

func (d *DNF) Name() string { return "dnf" }

func (d *DNF) Available() bool {
	info, err := os.Stat(dnfPath)
	return err == nil && !info.IsDir()
}

func (d *DNF) LockHeld() (bool, string) {
	for _, path := range dnfLockFiles {
		if held, checked := lockHeld(path); checked && held {
			return true, path
		}
	}
	return false, ""
}

// Plan computes the upgrade from the local cache. check-update returns 100
// when there are updates and 0 when there are none; every other code is an
// error.
func (d *DNF) Plan(ctx context.Context, options Options) (Plan, error) {
	plan := Plan{Manager: d.Name(), DiskAvailableBytes: diskAvailable("/")}

	// A removal plan and an installation plan answer a question other than an
	// upgrade plan: not "what will change on its own" but "what will disappear
	// or arrive along with what I am asking for".
	switch options.Mode {
	case ModeRemove:
		return d.planRemove(ctx, plan, options)
	case ModeInstall:
		return d.planInstall(ctx, plan, options)
	}

	result := run(ctx, 5*time.Minute, dnfPath, "--quiet", "--cacheonly", "check-update")
	if !result.Ran || (result.ExitCode != 0 && result.ExitCode != 100) {
		return plan, fmt.Errorf("dnf check-update: %s", result.Reason())
	}

	for _, line := range strings.Split(result.Stdout, "\n") {
		change, ok := parseDNFUpdateLine(line)
		if !ok || !matchesFilter(change, options) {
			continue
		}
		plan.Changes = append(plan.Changes, change)
	}
	plan.RebootPredicted = d.rebootPredicted(plan.Changes)
	// Fedora does not publish consistent metadata about the download size in
	// this mode, so we do not guess the value.
	return plan, nil
}

// parseDNFUpdateLine czyta linie postaci:
//
//	NetworkManager.x86_64   1:1.52.2-1.fc42   updates
func parseDNFUpdateLine(line string) (Change, bool) {
	if strings.HasPrefix(line, " ") || strings.TrimSpace(line) == "" {
		return Change{}, false
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.Contains(fields[0], ".") {
		return Change{}, false
	}
	name := fields[0]
	if index := strings.LastIndex(name, "."); index > 0 {
		name = name[:index]
	}
	return Change{
		Name:             name,
		CandidateVersion: fields[1],
		Origin:           fields[2],
		// Fedora does not publish consistent security metadata for every
		// repository, so we do not mark changes as security on the basis of
		// the name of the repository alone.
		Security: false,
	}, true
}

func (d *DNF) rebootPredicted(changes []Change) bool {
	for _, change := range changes {
		name := change.Name
		if strings.HasPrefix(name, "kernel") || name == "glibc" || strings.HasPrefix(name, "systemd") {
			return true
		}
	}
	return false
}

func (d *DNF) Refresh(ctx context.Context) error {
	if held, path := d.LockHeld(); held {
		return fmt.Errorf("%w: %s", ErrLocked, path)
	}
	result := run(ctx, 10*time.Minute, dnfPath, "--quiet", "makecache")
	if !result.Ran || result.ExitCode != 0 {
		return fmt.Errorf("dnf makecache: %s", result.Reason())
	}
	return nil
}

// Upgrade carries the transaction out. The mode is non-interactive, and the
// versions before and after are always recorded, also when the transaction
// fails.
func (d *DNF) Upgrade(ctx context.Context, options Options) (Apply, error) {
	apply := Apply{Manager: d.Name()}

	if held, path := d.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}

	// Dracut builds the initramfs from the same module tree as initramfs-tools,
	// so hidden modules threaten the same thing here: a host that will not come
	// up.
	if hidden, dir := modulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	before := d.installedVersions(ctx)

	args := []string{"--assumeyes", "--quiet", "upgrade"}
	if options.SecurityOnly {
		args = append(args, "--security")
	}
	// An ordinary upgrade does not touch the agent. Replacing the agent in the
	// middle of a transaction it carries out itself ends with a host cut off
	// from management halfway through the work - and a result nobody collects.
	// There is a separate operation for that, which skips this protection
	// deliberately.
	if len(options.Packages) == 0 {
		args = append(args, "--exclude="+AgentPackage)
	}
	args = append(args, options.Packages...)

	// Dnf numbers the steps in its output; the progress is read out of them.
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, args...)

	// A damaged file in the cache has exactly one correct answer: fetch it
	// again. Waiting for a person with that adds no safety and costs an
	// interrupted campaign.
	if (!result.Ran || result.ExitCode != 0) && BrokenDownload(result.Stderr, result.Stdout) {
		cleaning := run(ctx, 5*time.Minute, dnfPath, "--assumeyes", "--quiet", "clean", "packages")
		if cleaning.Ran && cleaning.ExitCode == 0 {
			apply.SelfRepair = append(apply.SelfRepair,
				"the damaged packages were removed from the cache and the transaction was retried")
			result = runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, args...)
		}
	}

	after := d.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = d.DatabaseBroken(ctx)
	apply.RebootRequired = d.rebootRequired(ctx)

	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, fmt.Errorf("dnf upgrade: %s", result.Reason())
	}
	return apply, nil
}

func (d *DNF) installedVersions(ctx context.Context) map[string]string {
	result := run(ctx, 2*time.Minute, rpmPath, "-qa", "--qf", "%{NAME} %{EVR}\n")
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

// rebootRequired asks dnf about the need for a restart. We trust the code 1
// only when the tool printed something: an execution error ends with the same
// code.
func (d *DNF) rebootRequired(ctx context.Context) bool {
	result := run(ctx, time.Minute, dnfPath, "needs-restarting", "-r")
	return result.Ran && result.ExitCode == 1 && strings.TrimSpace(result.Stdout) != ""
}

// DatabaseBroken checks the consistency of the RPM database.
func (d *DNF) DatabaseBroken(ctx context.Context) bool {
	result := run(ctx, 2*time.Minute, rpmPath, "--verifydb")
	return result.Ran && result.ExitCode != 0
}

// The full life cycle of packages for dnf.
//
// Installing, removing and holding are separate decisions here just as in apt,
// but the tool answers differently: dnf has no simulation that would print the
// set of changes alone, so the plan is read from its own table of a
// transaction interrupted before execution. That is the answer of dnf rather
// than our reconstruction of its dependencies - and only such an answer may be
// shown to a person who is about to remove something.

// dnfVersionlock is the name of the command of the plugin that locks
// versions.
const dnfVersionlock = "versionlock"

// planRemove computes what will disappear along with the named packages.
func (d *DNF) planRemove(ctx context.Context, plan Plan, options Options) (Plan, error) {
	if len(options.Packages) == 0 {
		return plan, fmt.Errorf("a removal plan requires a list of packages")
	}
	// --assumeno ends with the code 1 and a message about the interruption:
	// that is how dnf shows a transaction it does not carry out.
	args := append([]string{"--assumeno", "remove"}, options.Packages...)
	result := run(ctx, 10*time.Minute, dnfPath, args...)
	if !result.Ran {
		return plan, fmt.Errorf("dnf remove: %s", result.Reason())
	}
	output := result.Stdout + "\n" + result.Stderr
	if DNFPackageMissing(output) {
		// A package that is not there is not an error of the plan: there is
		// nothing to remove.
		return plan, nil
	}
	// A transaction dnf cannot resolve is not an empty plan. An empty plan
	// would read as "nothing will disappear" - and that is the answer to a
	// question other than "this cannot be removed".
	if reason := DNFUnresolvable(output); reason != "" {
		return plan, fmt.Errorf("dnf cannot resolve this transaction: %s", reason)
	}
	removals, announced, err := ParseDNFRemovalPlan(output)
	if err != nil {
		return plan, err
	}
	if announced > 0 && len(removals) != announced {
		// Silence here would be the worst possible answer: the operator would
		// see a shorter list than what will really disappear.
		return plan, fmt.Errorf("the removal plan was not recognised: dnf announces %d packages "+
			"and %d were read", announced, len(removals))
	}
	if len(removals) == 0 {
		// Output we read nothing out of is not an empty plan either: it means
		// the format has changed and we do not know what would disappear.
		return plan, fmt.Errorf("the removal plan was not recognised in the answer of dnf")
	}
	plan.Removals = removals
	plan.Protected = ProtectedInSet(plan.Removals)
	return plan, nil
}

// planInstall computes what will arrive along with the named packages.
func (d *DNF) planInstall(ctx context.Context, plan Plan, options Options) (Plan, error) {
	if len(options.Packages) == 0 {
		return plan, fmt.Errorf("an installation plan requires a list of packages")
	}
	args := append([]string{"--assumeno", "install"}, options.Packages...)
	result := run(ctx, 10*time.Minute, dnfPath, args...)
	if !result.Ran {
		return plan, fmt.Errorf("dnf install: %s", result.Reason())
	}
	output := result.Stdout + "\n" + result.Stderr
	// A package that is in no source ends with an error code and a message -
	// and that is an answer rather than an empty plan.
	if DNFPackageMissing(output) {
		return plan, fmt.Errorf("dnf does not know a package from this order")
	}
	if reason := DNFUnresolvable(output); reason != "" {
		return plan, fmt.Errorf("dnf cannot resolve this transaction: %s", reason)
	}
	// Dnf ends a transaction interrupted before execution with a non-zero
	// code; a zero code means here that there was nothing to install or that
	// the tool answered other than we assume.
	changes := ParseDNFInstallPlan(output)
	if len(changes) == 0 {
		if result.ExitCode == 0 && WholeTransactionReady(output) {
			// Everything is already installed: an empty plan is true here.
			return plan, nil
		}
		return plan, fmt.Errorf("the installation plan was not recognised in the answer of dnf (code %d)",
			result.ExitCode)
	}
	plan.Changes = append(plan.Changes, changes...)
	plan.RebootPredicted = d.rebootPredicted(plan.Changes)
	return plan, nil
}

// removalHeadings list the sections of the transaction table that mean a
// removal. Each of them means something else to a person - a named package, a
// dependent package and a package left without a user - but all of them
// disappear.
var removalHeadings = []string{
	"removing:",
	"removing dependent packages:",
	"removing unused dependencies:",
	"removing dependencies:",
}

// The summary of a transaction. Dnf5 writes "Removing: 3 packages", dnf4 -
// "Remove  3 Packages"; that number is the only guard against an incomplete
// read of the table, so we read both spellings.
var (
	removalSummaries = []string{"removing:", "remove "}
	installSummaries = []string{"installing:", "install "}
)

var installHeadings = []string{
	"installing:",
	"installing dependencies:",
	"installing weak dependencies:",
	"upgrading:",
}

// ParseDNFRemovalPlan reads the table of a transaction interrupted before
// execution.
//
// It returns the names of the packages and the number dnf itself announced in
// the summary. A divergence between them is an error rather than a detail: it
// means the format of the output has changed and the list shown to a person
// would be incomplete.
func ParseDNFRemovalPlan(output string) ([]string, int, error) {
	names, announced := dnfTransactionSections(output, removalHeadings, removalSummaries)
	return names, announced, nil
}

// ParseDNFInstallPlan reads from the transaction table what will arrive.
func ParseDNFInstallPlan(output string) []Change {
	names, _ := dnfTransactionSections(output, installHeadings, installSummaries)
	changes := make([]Change, 0, len(names))
	for _, name := range names {
		changes = append(changes, Change{Name: name})
	}
	return changes
}

// dnfTransactionSections reads the names of the packages from the transaction
// table.
//
// The table has section headings at the left edge and indented entries; the
// columns are the name, the architecture, the version, the repository and the
// size. The summary at the end gives the numbers - and they serve to check
// whether the read is complete.
func dnfTransactionSections(output string, headings, summaries []string) ([]string, int) {
	var names []string
	seen := map[string]bool{}
	inSection := false
	inSummary := false
	announced := 0

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(lower, "transaction summary") {
			inSection, inSummary = false, true
			continue
		}
		if inSummary {
			// Dnf5 writes "Removing: 3 packages", dnf4 - "Remove  3 Packages".
			// We read both, because it is that number that guards whether the
			// read is complete.
			if matchesSummary(lower, summaries) {
				for _, field := range strings.Fields(lower) {
					if number, err := strconv.Atoi(field); err == nil {
						announced = number
						break
					}
				}
			}
			continue
		}
		if contains(headings, lower) {
			inSection = true
			continue
		}
		// The heading of another section ends the previous one.
		if strings.HasSuffix(lower, ":") && !strings.HasPrefix(line, " ") {
			inSection = false
			continue
		}
		if !inSection || !strings.HasPrefix(line, " ") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, announced
}

// matchesSummary recognises a summary line in both generations of dnf.
func matchesSummary(line string, summaries []string) bool {
	for _, prefix := range summaries {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func contains(list []string, value string) bool {
	for _, entry := range list {
		if entry == value {
			return true
		}
	}
	return false
}

// DNFPackageMissing recognises the answer "there is no such package".
func DNFPackageMissing(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "no packages to remove") ||
		strings.Contains(lower, "no match for argument") ||
		strings.Contains(lower, "unable to find a match")
}

// WholeTransactionReady recognises the answer "there is nothing to do".
//
// It is the only case where an empty installation plan is true: everything
// from the order is already installed in a version dnf does not change.
func WholeTransactionReady(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "nothing to do") ||
		strings.Contains(lower, "package is already installed") ||
		strings.Contains(lower, "already installed")
}

// Install adds packages along with their dependencies.
func (d *DNF) Install(ctx context.Context, options Options) (Apply, error) {
	apply := Apply{Manager: d.Name()}
	if len(options.Packages) == 0 {
		return apply, fmt.Errorf("an installation requires a list of packages")
	}
	if held, path := d.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}
	if hidden, dir := modulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	before := d.installedVersions(ctx)
	args := append([]string{"--assumeyes", "--quiet", "install"}, options.Packages...)
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, args...)
	// dnf does not go back a version with the "install" command and has no
	// switch for it: a separate command serves a version older than the
	// installed one. We try it only when the operation explicitly allows it.
	if options.AllowDowngrade && (!result.Ran || result.ExitCode != 0) {
		downgrade := append([]string{"--assumeyes", "--quiet", "downgrade"}, options.Packages...)
		result = runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, downgrade...)
	}

	after := d.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = d.DatabaseBroken(ctx)
	apply.RebootRequired = d.rebootRequired(ctx)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, fmt.Errorf("dnf install: %s", result.Reason())
	}
	return apply, nil
}

// Remove removes the named packages along with what disappears with them.
//
// The set is computed again right before the operation and compared with what
// the operator approved: a difference means the host has changed since the
// plan.
func (d *DNF) Remove(ctx context.Context, options Options, expected []string) (Apply, error) {
	apply := Apply{Manager: d.Name()}
	if len(options.Packages) == 0 {
		return apply, fmt.Errorf("a removal requires a list of packages")
	}
	if held, path := d.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}

	plan, err := d.planRemove(ctx, Plan{Manager: d.Name()}, options)
	if err != nil {
		return apply, err
	}
	if len(plan.Protected) > 0 {
		return apply, fmt.Errorf("%w: %s", ErrProtectedPackage, strings.Join(plan.Protected, ", "))
	}
	if difference := compareSets(expected, plan.Removals); difference != "" {
		return apply, fmt.Errorf("%w: %s", ErrPlanChanged, difference)
	}

	before := d.installedVersions(ctx)
	args := append([]string{"--assumeyes", "--quiet", "remove"}, options.Packages...)
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, args...)

	after := d.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = d.DatabaseBroken(ctx)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, fmt.Errorf("dnf remove: %s", result.Reason())
	}
	return apply, nil
}

// SetHold holds or releases the upgrades of packages.
//
// Dnf does that with the versionlock plugin. A host without it cannot hold a
// package - and that is an answer rather than a silent consent: a package
// considered held and upgraded in the next campaign is worse than an outright
// refusal.
func (d *DNF) SetHold(ctx context.Context, pkgs []string, hold bool) (Apply, error) {
	apply := Apply{Manager: d.Name()}
	if len(pkgs) == 0 {
		return apply, fmt.Errorf("a hold requires a list of packages")
	}
	if !d.HasVersionlock(ctx) {
		return apply, fmt.Errorf("%s: this host has no versionlock plugin, so dnf cannot "+
			"hold a package", ErrorUnsupported)
	}
	operation := "delete"
	if hold {
		operation = "add"
	}
	args := append([]string{dnfVersionlock, operation}, pkgs...)
	result := run(ctx, 5*time.Minute, dnfPath, args...)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, fmt.Errorf("dnf versionlock %s: %s", operation, result.Reason())
	}
	return apply, nil
}

// Holds returns the packages held on the host.
func (d *DNF) Holds(ctx context.Context) []string {
	// --quiet removes the lines about metadata from the output; without it the
	// first line was sometimes shown as the name of a held package.
	result := run(ctx, time.Minute, dnfPath, "--quiet", dnfVersionlock, "list")
	if !result.Ran || result.ExitCode != 0 {
		return nil
	}
	return ParseVersionlock(result.Stdout)
}

// HasVersionlock says whether the host can hold packages.
func (d *DNF) HasVersionlock(ctx context.Context) bool {
	result := run(ctx, 30*time.Second, dnfPath, dnfVersionlock, "list")
	return result.Ran && result.ExitCode == 0
}

// ParseVersionlock reads the list of locks in both formats dnf prints.
//
// Dnf5 writes "Package name: <name>", dnf4 - the pattern "name-0:version.*"
// alone. We read both, because the panel is to work with both generations of
// the tool.
func ParseVersionlock(output string) []string {
	var names []string
	seen := map[string]bool{}
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if name, ok := strings.CutPrefix(trimmed, "Package name:"); ok {
			add(name)
			continue
		}
		// A dnf4 entry is a NEVRA pattern: name-epoch:version-release.arch or
		// name-epoch:version-*. Anything else - a line about metadata, a
		// heading, a message - is not a lock and must not pretend to be the
		// name of a package on the list of held ones.
		if name := nameFromNEVRAPattern(trimmed); name != "" {
			add(name)
		}
	}
	return names
}

// nevraPattern recognises a lock entry in the dnf4 format.
//
// The pattern is deliberately strict: a line that is not a lock is to be
// skipped rather than land on the list of held packages. A list with the entry
// "Last metadata expiration check" would tell the operator that a package that
// does not exist has been held.
var nevraPattern = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9._+-]*?)-([0-9]+:)?[0-9][^\s-]*-[^\s-]+$`)

// nameFromNEVRAPattern extracts the name of a package out of a lock pattern,
// or returns nothing when the line is not a lock.
func nameFromNEVRAPattern(pattern string) string {
	match := nevraPattern.FindStringSubmatch(strings.TrimSpace(pattern))
	if match == nil {
		return ""
	}
	return match[1]
}

// DNFUnresolvable recognises a transaction dnf cannot resolve and returns the
// reason the tool gave.
//
// The most common case is a package without which the system cannot be left
// consistent - dnf then refuses the whole transaction. A refusal with a reason
// is the only correct answer here: an empty list would mean "nothing will
// disappear".
func DNFUnresolvable(output string) string {
	lower := strings.ToLower(output)
	markers := []string{
		"failed to resolve the transaction",
		"depsolve error",
		"error: depsolving problem",
		"protected packages",
		"the operation would result in removing",
	}
	found := false
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			found = true
			break
		}
	}
	if !found {
		return ""
	}
	// The reason is taken from the "Problem:" lines or from the end of the
	// output: that is where dnf explains what cannot be reconciled.
	var reasons []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "problem") || strings.Contains(lower, "protected") ||
			strings.HasPrefix(lower, "- ") {
			reasons = append(reasons, trimmed)
		}
	}
	if len(reasons) == 0 {
		return "dnf rejected the transaction without giving a reason"
	}
	if len(reasons) > 3 {
		reasons = reasons[:3]
	}
	return strings.Join(reasons, " / ")
}
