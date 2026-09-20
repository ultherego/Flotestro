package packages

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	dnfPath = "/usr/bin/dnf"
	rpmPath = "/usr/bin/rpm"
	// The database of rpm. The cache is not a constant: dnf4 and dnf5 keep
	// theirs in different directories, see dnfCacheDir.
	rpmDatabaseDir = "/var/lib/rpm"
)

// dnfCacheDir is where the archives land.
func dnfCacheDir() string {
	for _, dir := range []string{"/var/cache/libdnf5", "/var/cache/dnf"} {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}
	return "/var/cache/libdnf5"
}

// dnfReadArgs are the arguments every read of the metadata carries. The
// metadata is refreshed by the helper, which runs as root and writes the
// system cache; the agent plans unprivileged and would otherwise read a cache
// of its own that the refresh never touched - so a package added to a
// repository since that cache was filled is simply not there, and the plan
// says the package does not exist.
func dnfReadArgs() []string {
	return []string{"--cacheonly", "--setopt=cachedir=" + dnfCacheDir()}
}

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

// Plan computes the upgrade from the local cache.
func (d *DNF) Plan(ctx context.Context, options Options) (Plan, error) {
	plan, err := d.plan(ctx, options)
	if err != nil {
		return plan, err
	}
	return finishPlan(ctx, d, plan, options), nil
}

func (d *DNF) plan(ctx context.Context, options Options) (Plan, error) {
	plan := Plan{Manager: d.Name(), DiskAvailableBytes: diskAvailable("/"), Mode: options.Mode}

	// A removal plan and an installation plan answer a question other than an
	// upgrade plan: not "what will change on its own" but "what will disappear or
	// arrive along with what I am asking for".
	switch options.Mode {
	case ModeRemove:
		return d.planRemove(ctx, plan, options)
	case ModeInstall:
		return d.planInstall(ctx, plan, options)
	}

	result, pending, err := d.pendingUpdates(ctx, options)
	if err != nil {
		return plan, err
	}
	installed := d.installedVersions(ctx)
	for i := range pending {
		// check-update names the candidate and nothing about what is there now; the
		// rpm database does, and the direction of the change follows from the two.
		pending[i].CurrentVersion = installed[pending[i].Name]
		pending[i].Action = ActionUpgrade
	}
	// The advisories decide what a security-only plan may carry; what they do
	// not cover stays in the plan as blocked instead of disappearing from it.
	if options.SecurityOnly && len(pending) > 0 {
		if pending, plan.Blocked, err = d.classifySecurity(ctx, pending, result.Truncated); err != nil {
			return plan, err
		}
	}
	plan.Changes = pending
	plan.RebootPredicted = d.rebootPredicted(plan.Changes)
	// check-update lists the versions and nothing about their size.
	plan.DownloadBytes, plan.Space = d.planSpace(ctx, plan.Changes, func() string {
		args := append([]string{"--assumeno"}, append(dnfReadArgs(), "upgrade")...)
		if options.SecurityOnly {
			args = append(args, "--security")
		}
		if len(options.Packages) == 0 {
			args = append(args, "--exclude="+AgentPackage)
		}
		result := run(ctx, 10*time.Minute, dnfPath, append(args, options.Packages...)...)
		return result.Stdout + "\n" + result.Stderr
	})
	return plan, nil
}

// planSpace measures where the bytes of the plan go: the archives and the
// installed size from the summary of the transaction, the growth of /boot from
// the kernel of the plan.
func (d *DNF) planSpace(ctx context.Context, changes []Change, summary func() string) (uint64, []SpaceFact) {
	needs := spaceNeeds{downloadKnown: true, installBasis: BasisInstalledSize}
	if len(changes) == 0 {
		return 0, spaceFacts(dnfCacheDir(), rpmDatabaseDir, needs)
	}
	needs.kernel = anyKernel(d.Name(), changes)
	sizes := ParseDNFTransactionSizes(summary())
	needs.download, needs.downloadKnown = sizes.Download, sizes.DownloadKnown
	installNeeds(&needs, sizes.Install, sizes.InstallKnown)
	return needs.download, spaceFacts(dnfCacheDir(), rpmDatabaseDir, needs)
}

// DNFTransactionSizes is what the summary of a transaction says about its
// size.
type DNFTransactionSizes struct {
	Download      uint64
	DownloadKnown bool
	Install       uint64
	InstallKnown  bool
}

// ParseDNFTransactionSizes reads the size lines of a transaction summary in
// both spellings.
func ParseDNFTransactionSizes(output string) DNFTransactionSizes {
	var sizes DNFTransactionSizes
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Total download size:"):
			sizes.Download, sizes.DownloadKnown = ParseHumanSize(strings.TrimPrefix(line, "Total download size:"))
		case strings.HasPrefix(line, "Total size:"):
			sizes.Download, sizes.DownloadKnown = 0, true
		case strings.HasPrefix(line, "Installed size:"):
			sizes.Install, sizes.InstallKnown = ParseHumanSize(strings.TrimPrefix(line, "Installed size:"))
		case strings.Contains(line, "Need to download "):
			rest := line[strings.Index(line, "Need to download ")+len("Need to download "):]
			sizes.Download, sizes.DownloadKnown = ParseHumanSize(strings.TrimSuffix(rest, "."))
		case strings.Contains(line, "(install "):
			rest := line[strings.Index(line, "(install ")+len("(install "):]
			if end := strings.IndexAny(rest, ",)"); end > 0 {
				sizes.Install, sizes.InstallKnown = ParseHumanSize(rest[:end])
			}
		}
	}
	return sizes
}

// parseDNFUpdateLine reads a line of the form: NetworkManager. x86_64 1:1. 52.
// 2-1.
func parseDNFUpdateLine(line string) (Change, bool) {
	if strings.HasPrefix(line, " ") || strings.TrimSpace(line) == "" {
		return Change{}, false
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.Contains(fields[0], ".") {
		return Change{}, false
	}
	name, arch := fields[0], ""
	if index := strings.LastIndex(name, "."); index > 0 {
		name, arch = name[:index], name[index+1:]
	}
	return Change{
		Name:             name,
		Architecture:     arch,
		CandidateVersion: fields[1],
		Origin:           fields[2],
		// The name of a repository classifies nothing; only an advisory does, and a
		// security-only plan reads them through securityFilter.
		Security: false,
	}, true
}

// checkUpdate reads the pending updates from the cache; code 100 is what dnf
// answers when there are any.
func (d *DNF) checkUpdate(ctx context.Context) (commandResult, error) {
	result := run(ctx, 5*time.Minute, dnfPath,
		append([]string{"--quiet"}, append(dnfReadArgs(), "check-update")...)...)
	if !result.Ran || (result.ExitCode != 0 && result.ExitCode != 100) {
		return result, fmt.Errorf("dnf check-update: %s", result.Reason())
	}
	return result, nil
}

// dnfSecurityUnknown is the refusal of a security-only operation this host
// cannot classify: the code of pacman, the sentence of this family.
type dnfSecurityUnknown struct{ reason string }

func (e dnfSecurityUnknown) Error() string { return e.reason }

// Is answers the shared sentinel, so the refusal carries ErrorSecurityUnknown
// and counts as a refusal of the host rather than a failed transaction.
func (e dnfSecurityUnknown) Is(target error) bool { return target == ErrSecurityUnknown }

// DNFAdvisoryTypes says, per package, whether an advisory of this host marks
// its pending update as a security fix. A package that is not in it is unknown.
type DNFAdvisoryTypes map[string]bool

// Security answers for one package: the exact architecture first, the bare
// name after it, because a vendor names the same fix in both spellings.
func (t DNFAdvisoryTypes) Security(name, architecture string) (security, known bool) {
	if value, ok := t[name+"."+architecture]; ok {
		return value, true
	}
	value, ok := t[name]
	return value, ok
}

// ParseDNFUpdateinfoList reads "dnf updateinfo list": the advisory, its type
// and severity, and the package the advisory closes.
func ParseDNFUpdateinfoList(output string) DNFAdvisoryTypes {
	types := DNFAdvisoryTypes{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		pkg, ok := ParseNEVRA(fields[len(fields)-1])
		if !ok {
			continue
		}
		// dnf4 writes the type and the severity in one column ("Moderate/Sec."),
		// dnf5 in two; in both the word stands between the advisory and the package.
		security := strings.Contains(strings.ToLower(strings.Join(fields[1:len(fields)-1], " ")), "sec")
		key := pkg.Name + "." + pkg.Architecture
		types[key] = types[key] || security
		types[pkg.Name] = types[pkg.Name] || security
	}
	return types
}

// pendingUpdates reads the updates dnf has for this host, narrowed by the
// names of the order; the security filter needs the advisories and comes after.
func (d *DNF) pendingUpdates(ctx context.Context, options Options) (commandResult, []Change, error) {
	result, err := d.checkUpdate(ctx)
	if err != nil {
		return result, nil, err
	}
	byName := options
	byName.SecurityOnly = false
	var pending []Change
	for _, line := range strings.Split(result.Stdout, "\n") {
		if change, ok := parseDNFUpdateLine(line); ok && matchesFilter(change, byName) {
			pending = append(pending, change)
		}
	}
	return result, pending, nil
}

// unclassifiedStatus is what the operator reads next to an update the
// advisories of this host say nothing about.
const unclassifiedStatus = "no advisory of this host says whether this update closes a " +
	"vulnerability, so a security-only plan leaves it out rather than calling it harmless"

// classifySecurity divides the pending updates by the advisories of the host:
// security stays, a known bug fix goes, what nothing covers leaves as blocked.
func (d *DNF) classifySecurity(ctx context.Context, pending []Change,
	truncated bool) ([]Change, []Blocked, error) {
	if truncated {
		return nil, nil, dnfSecurityUnknown{"dnf listed more pending updates than the agent reads, " +
			"so this host cannot say which of them are security updates"}
	}
	args := append([]string{"--quiet"}, append(dnfReadArgs(), "updateinfo", "list", "--updates")...)
	result := run(ctx, 5*time.Minute, dnfPath, args...)
	if !result.Complete() {
		return nil, nil, dnfSecurityUnknown{"the advisories of this host could not be read (" +
			result.unreadable("dnf updateinfo list") +
			"), so a security-only plan cannot be computed"}
	}
	return classifyPending(pending, ParseDNFUpdateinfoList(result.Stdout))
}

// classifyPending divides the pending updates by what the advisories say.
func classifyPending(pending []Change, types DNFAdvisoryTypes) ([]Change, []Blocked, error) {
	var changes []Change
	var blocked []Blocked
	for _, change := range pending {
		security, known := types.Security(change.Name, change.Architecture)
		switch {
		case !known:
			// Unknown is not "not a security update": the update leaves the plan
			// named and with its reason, never in silence.
			blocked = append(blocked, Blocked{Name: change.Name, Status: unclassifiedStatus,
				Kind: BlockedAdvisory})
		case security:
			change.Security = true
			changes = append(changes, change)
		}
	}
	// A plan with nothing to carry out and updates it cannot classify would read
	// as a clean host at every later step; that is what this code is for.
	if len(changes) == 0 && len(blocked) > 0 {
		return nil, nil, dnfSecurityUnknown{"no advisory of this host classifies " +
			strings.Join(blockedNames(blocked), ", ") +
			", so nothing here can be planned as a security update"}
	}
	return changes, blocked, nil
}

// maxUnclassifiedNamed bounds the refusal: a host behind on everything would
// otherwise carry its whole pending list into one message.
const maxUnclassifiedNamed = 10

// blockedNames lists the blocked packages for a message, bounded.
func blockedNames(blocked []Blocked) []string {
	names := make([]string, 0, len(blocked))
	for _, entry := range blocked {
		names = append(names, entry.Name)
	}
	names = unique(names)
	if len(names) > maxUnclassifiedNamed {
		rest := fmt.Sprintf("and %d more", len(names)-maxUnclassifiedNamed)
		names = append(names[:maxUnclassifiedNamed:maxUnclassifiedNamed], rest)
	}
	return names
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

// Upgrade carries the transaction out.
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

	// "dnf --security" upgrades nothing and succeeds where nothing is
	// classified, so this path asks the plan's question and answers it alike.
	if options.SecurityOnly {
		result, pending, err := d.pendingUpdates(ctx, options)
		if err != nil {
			return apply, err
		}
		if len(pending) > 0 {
			if _, _, err := d.classifySecurity(ctx, pending, result.Truncated); err != nil {
				return apply, err
			}
		}
	}

	before := d.installedVersions(ctx)

	args := []string{"--assumeyes", "--quiet", "upgrade"}
	if options.SecurityOnly {
		args = append(args, "--security")
	}
	// An ordinary upgrade does not touch the agent.
	if len(options.Packages) == 0 {
		args = append(args, "--exclude="+AgentPackage)
	}
	args = append(args, options.Packages...)

	// Dnf numbers the steps in its output; the progress is read out of them.
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, args...)

	// A damaged file in the cache has exactly one correct answer: fetch it again.
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
	apply.ScriptletErrors = scriptletFailures(result.Stdout + "\n" + result.Stderr)
	apply.RebootRequired = d.rebootRequired(ctx)

	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, fmt.Errorf("dnf upgrade: %s", result.Reason())
	}
	return apply, nil
}

// installedVersions returns a map of package -> version.
func (d *DNF) installedVersions(ctx context.Context) map[string]string {
	// The architecture is recorded next to the bare name: a plan that names
	// kernel-core.
	versions := map[string]string{}
	result := runLines(ctx, 2*time.Minute, func(line string) {
		addInstalledRPM(versions, line)
	}, rpmPath, "-qa", "--qf", "%{NAME} %{ARCH} %{EVR}\n")
	if !result.Complete() {
		return nil
	}
	return versions
}

// parseInstalledRPM reads what rpm printed. Several versions of the same
// name - the kernels - are answered by the newest under the bare name.
func parseInstalledRPM(output string) map[string]string {
	versions := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		addInstalledRPM(versions, line)
	}
	return versions
}

// addInstalledRPM records one row of "rpm -qa".
func addInstalledRPM(versions map[string]string, line string) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return
	}
	name, architecture, version := fields[0], fields[1], fields[2]
	if previous, seen := versions[name]; !seen || CompareRPMVersions(previous, version) < 0 {
		versions[name] = version
	}
	versions[name+"."+architecture] = version
}

// rebootRequired asks dnf about the need for a restart.
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

// dnfVersionlock is the name of the command of the plugin that locks
// versions.
const dnfVersionlock = "versionlock"

// ErrorVersionlockMissing means the host cannot hold a package version,
// because the plugin that does it is not installed.
const ErrorVersionlockMissing = "versionlock_missing"

// versionlockPackage names what restores the feature.
const versionlockPackage = "python3-dnf-plugin-versionlock on dnf4, dnf5-plugin-versionlock on dnf5"

// ErrVersionlockMissing means the hold was refused before anything was
// attempted.
var ErrVersionlockMissing = errors.New("this host has no dnf versionlock plugin, so a package " +
	"version cannot be held; install " + versionlockPackage)

// versionlockPaths are the files a distribution installs the plugin as: dnf4
// loads it as a Python module next to the other commands of dnf-plugins-core,
// dnf5 as a shared library of libdnf5, and both keep the configuration of the.
var versionlockPaths = []string{
	"/usr/lib/python3*/site-packages/dnf-plugins/versionlock.py",
	"/usr/lib64/python3*/site-packages/dnf-plugins/versionlock.py",
	"/usr/lib64/dnf5/plugins/versionlock.so",
	"/usr/lib/dnf5/plugins/versionlock.so",
	"/usr/lib64/libdnf5/plugins/versionlock.so",
	"/usr/lib/libdnf5/plugins/versionlock.so",
	"/etc/dnf/plugins/versionlock.conf",
}

// VersionlockInstalled says whether the host has the plugin that holds a
// package version.
func VersionlockInstalled() bool {
	for _, pattern := range versionlockPaths {
		matches, err := filepath.Glob(pattern)
		if err == nil && len(matches) > 0 {
			return true
		}
	}
	return false
}

// DNFFeatures are the parts of the dnf adapter the host has.
func DNFFeatures(dnf, versionlock bool) map[string]bool {
	return map[string]bool{
		// An rpm database lock looks different from a debconf question, and the
		// repair would look different too, so the adapter does not have it.
		"repair": false,
		"hold":   dnf && versionlock,
	}
}

// DNFReason explains the limits of the adapter on this host: a missing dnf
// and a dnf that cannot hold a package are two different answers.
func DNFReason(dnf, versionlock bool) string {
	if !dnf {
		return "dnf is not installed on this host"
	}
	if !versionlock {
		// The same sentence the refusal of the operation carries, so the panel shows
		// one explanation whether it hides the hold or refuses an order for it.
		return ErrVersionlockMissing.Error()
	}
	return ""
}

// planRemove computes what will disappear along with the named packages.
func (d *DNF) planRemove(ctx context.Context, plan Plan, options Options) (Plan, error) {
	if len(options.Packages) == 0 {
		return plan, fmt.Errorf("a removal plan requires a list of packages")
	}
	// --assumeno ends with the code 1 and a message about the interruption: that
	// is how dnf shows a transaction it does not carry out.
	args := append(append([]string{"--assumeno"}, append(dnfReadArgs(), "remove")...), options.Packages...)
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
	// A transaction dnf cannot resolve is not an empty plan.
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
	args := append(append([]string{"--assumeno"}, append(dnfReadArgs(), "install")...), options.Packages...)
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
	// Dnf ends a transaction interrupted before execution with a non-zero code; a
	// zero code means here that there was nothing to install or that the tool
	// answered other than we assume.
	changes := ParseDNFInstallPlan(output)
	if len(changes) == 0 {
		if result.ExitCode == 0 && WholeTransactionReady(output) {
			// Everything is already installed: an empty plan is true here.
			return plan, nil
		}
		return plan, fmt.Errorf("the installation plan was not recognised in the answer of dnf (code %d)",
			result.ExitCode)
	}
	installed := d.installedVersions(ctx)
	for i := range changes {
		if changes[i].Action != ActionRemove {
			changes[i].CurrentVersion = installed[changes[i].Name]
		}
	}
	plan.Changes = append(plan.Changes, changes...)
	// An installation can drop packages too - a conflict resolved by a
	// replacement, or a dependency nothing needs any more - and they go into the
	// plan as removals the operator sees before the consent.
	removals, _, _ := ParseDNFRemovalPlan(output)
	plan.Removals = append(plan.Removals, removals...)
	plan.Protected = ProtectedInSet(plan.Removals)
	plan.RebootPredicted = d.rebootPredicted(plan.Changes)
	plan.DownloadBytes, plan.Space = d.planSpace(ctx, plan.Changes, func() string { return output })
	return plan, nil
}

// removalHeadings list the sections of the transaction table that mean a
// removal.
var removalHeadings = []string{
	"removing:",
	"removing dependent packages:",
	"removing unused dependencies:",
	"removing dependencies:",
}

// The summary of a transaction.
var (
	removalSummaries = []string{"removing:", "remove "}
	installSummaries = []string{"installing:", "install "}
)

var installHeadings = []string{
	"installing:",
	"installing dependencies:",
	"installing weak dependencies:",
	"upgrading:",
	"downgrading:",
	"reinstalling:",
}

// dnfSectionAction says which direction a section of the transaction
// table means, and dnfSectionReason why its packages are in the plan.
func dnfSectionAction(heading string) string {
	switch {
	case strings.HasPrefix(heading, "upgrading"):
		return ActionUpgrade
	case strings.HasPrefix(heading, "downgrading"):
		return ActionDowngrade
	case strings.HasPrefix(heading, "removing"):
		return ActionRemove
	}
	return ActionInstall
}

func dnfSectionReason(heading string) string {
	switch {
	case strings.Contains(heading, "unused"):
		return ReasonOrphan
	case strings.Contains(heading, "dependen"):
		return ReasonDependency
	}
	return ReasonRequested
}

// ParseDNFRemovalPlan reads the table of a transaction interrupted before
// execution.
func ParseDNFRemovalPlan(output string) ([]string, int, error) {
	entries, announced := dnfTransactionSections(output, removalHeadings, removalSummaries)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names, announced, nil
}

// ParseDNFInstallPlan reads from the transaction table what will arrive: every
// entry with its architecture, its version and the repository it comes from,
// and the direction its section means.
func ParseDNFInstallPlan(output string) []Change {
	entries, _ := dnfTransactionSections(output, installHeadings, installSummaries)
	changes := make([]Change, 0, len(entries))
	for _, entry := range entries {
		changes = append(changes, Change{
			Name: entry.Name, Architecture: entry.Architecture, CandidateVersion: entry.Version,
			Origin: entry.Repository, Action: dnfSectionAction(entry.Section),
			Reason: dnfSectionReason(entry.Section),
		})
	}
	return changes
}

// dnfEntry is one row of the transaction table with the section it was
// read under.
type dnfEntry struct {
	Name, Architecture, Version, Repository, Section string
}

// dnfTransactionSections reads the packages from the transaction table.
func dnfTransactionSections(output string, headings, summaries []string) ([]dnfEntry, int) {
	var entries []dnfEntry
	seen := map[string]bool{}
	inSection := false
	inSummary := false
	announced := 0
	section := ""

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
			// Dnf5 writes "Removing: 3 packages", dnf4 - "Remove 3 Packages". We read
			// both, because it is that number that guards whether the read is complete.
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
			section = lower
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
		entry := dnfEntry{Name: name, Section: section}
		// The columns after the name: architecture, version, repository, size.
		if len(fields) > 3 {
			entry.Architecture, entry.Version, entry.Repository = fields[1], fields[2], fields[3]
		}
		entries = append(entries, entry)
	}
	return entries, announced
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
	// dnf does not go back a version with the "install" command and has no switch
	// for it: a separate command serves a version older than the installed one.
	if options.AllowDowngrade && (!result.Ran || result.ExitCode != 0) {
		downgrade := append([]string{"--assumeyes", "--quiet", "downgrade"}, options.Packages...)
		result = runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, downgrade...)
	}

	after := d.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = d.DatabaseBroken(ctx)
	apply.ScriptletErrors = scriptletFailures(result.Stdout + "\n" + result.Stderr)
	apply.RebootRequired = d.rebootRequired(ctx)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, fmt.Errorf("dnf install: %s", result.Reason())
	}
	return apply, nil
}

// Remove removes the named packages along with what disappears with them.
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
	apply.ScriptletErrors = scriptletFailures(result.Stdout + "\n" + result.Stderr)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, fmt.Errorf("dnf remove: %s", result.Reason())
	}
	return apply, nil
}

// SetHold holds or releases the upgrades of packages. Dnf does that with the
// versionlock plugin.
func (d *DNF) SetHold(ctx context.Context, pkgs []string, hold bool) (Apply, error) {
	apply := Apply{Manager: d.Name()}
	if len(pkgs) == 0 {
		return apply, fmt.Errorf("a hold requires a list of packages")
	}
	// The preflight of the hold: the plugin is looked for on the file system
	// first, so a host without it is refused without starting dnf at all, with
	// the same answer the capability registry gave the panel before the order.
	if !VersionlockInstalled() || !d.HasVersionlock(ctx) {
		return apply, ErrVersionlockMissing
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

// Holds returns the packages held on the host. A host without the
// versionlock plugin cannot hold, and says so instead of reporting no holds.
func (d *DNF) Holds(ctx context.Context) ([]string, string) {
	// A host without the plugin has an unknown list of holds rather than an empty
	// one, and the answer names what is missing instead of a failed command line.
	if !VersionlockInstalled() {
		return nil, "this host has no dnf versionlock plugin, so the held packages are unknown; " +
			"install " + versionlockPackage
	}
	// --quiet removes the lines about metadata from the output; without it the
	// first line was sometimes shown as the name of a held package.
	result := run(ctx, time.Minute, dnfPath, "--quiet", dnfVersionlock, "list")
	if !result.Ran || result.ExitCode != 0 {
		return nil, "dnf versionlock list: " + result.Reason()
	}
	held := ParseVersionlock(result.Stdout)
	if held == nil {
		held = []string{}
	}
	return held, ""
}

// HasVersionlock says whether the host can hold packages.
func (d *DNF) HasVersionlock(ctx context.Context) bool {
	result := run(ctx, 30*time.Second, dnfPath, dnfVersionlock, "list")
	return result.Ran && result.ExitCode == 0
}

// ParseVersionlock reads the list of locks in both formats dnf prints. Dnf5
// writes "Package name: <name>", dnf4 - the pattern "name-0:version.
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
		// A dnf4 entry is a NEVRA pattern: name-epoch:version-release. arch or
		// name-epoch:version-*.
		if name := nameFromNEVRAPattern(trimmed); name != "" {
			add(name)
		}
	}
	return names
}

// nevraPattern recognises a lock entry in the dnf4 format.
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

// scriptletFailures reads the packages whose scriptlet failed out of the
// output of a transaction dnf finished.
func scriptletFailures(output string) []string {
	var names []string
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), ">>>"))
		var nevra string
		switch {
		case strings.Contains(line, "error in %") && strings.Contains(line, "scriptlet:"):
			_, nevra, _ = strings.Cut(line, "scriptlet:")
		case strings.Contains(line, "scriptlet in rpm package"):
			_, nevra, _ = strings.Cut(line, "scriptlet in rpm package")
		default:
			continue
		}
		name := packageNameOfNEVRA(strings.TrimSpace(nevra))
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// packageNameOfNEVRA cuts the name out of "name-[epoch:]version-release.
func packageNameOfNEVRA(nevra string) string {
	nevra = strings.TrimSpace(strings.Fields(nevra + " ")[0])
	parts := strings.Split(nevra, "-")
	if len(parts) < 3 {
		return nevra
	}
	// The release carries the architecture ("1.noarch"); the version may
	// carry an epoch ("0:1.0"). Both are behind the name.
	return strings.Join(parts[:len(parts)-2], "-")
}
