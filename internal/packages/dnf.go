package packages

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	// The advisories decide what a security-only plan may carry; what they do
	// not cover stays in the plan as blocked instead of disappearing from it.
	if options.SecurityOnly && len(pending) > 0 {
		if pending, plan.Blocked, err = d.classifySecurity(ctx, pending, result.Truncated); err != nil {
			return plan, err
		}
	}
	// A host with nothing pending is not asked for a transaction it would not
	// make; what the file systems hold is worth saying all the same.
	if len(pending) == 0 {
		plan.DownloadBytes, plan.Space = d.planSpace(ctx, nil, nil)
		return plan, nil
	}
	// check-update names the direct updates and nothing else. What the operator
	// approves is the transaction dnf would carry out, so the plan is read from
	// its table: the dependencies it adds, what it replaces and what it drops.
	output, err := d.upgradePreview(ctx, options)
	if err != nil {
		return plan, err
	}
	changes, err := ParseDNFUpgradePlan(output)
	if err != nil {
		return plan, err
	}
	completeDNFChanges(changes, d.installedVersions(ctx), pending)
	// The protected removals are marked on the elements, not on the plan's list
	// that refuses the transaction whole: dropping the old kernel as the new one
	// arrives is the ordinary shape of an upgrade here.
	plan.Changes = changes
	plan.RebootPredicted = d.rebootPredicted(plan.Changes)
	// The sizes come from the summary of the same preview the table was read
	// from, so the plan and its bytes describe one transaction.
	plan.DownloadBytes, plan.Space = d.planSpace(ctx, plan.Changes, func() string { return output })
	return plan, nil
}

// upgradePreview asks dnf for the transaction it would carry out without
// carrying it out: --assumeno stops before execution and prints the whole
// table, which is the only place the dependencies and the removals stand.
func (d *DNF) upgradePreview(ctx context.Context, options Options) (string, error) {
	args := append([]string{"--assumeno"}, append(dnfReadArgs(), "upgrade")...)
	if options.SecurityOnly {
		args = append(args, "--security")
	}
	// An ordinary upgrade does not touch the agent, so the preview does not
	// promise a change the transaction will not make.
	if len(options.Packages) == 0 {
		args = append(args, "--exclude="+AgentPackage)
	}
	result := run(ctx, 10*time.Minute, dnfPath, append(args, options.Packages...)...)
	if !result.Ran {
		return "", fmt.Errorf("dnf upgrade: %s", result.Reason())
	}
	if result.Truncated {
		// A table read out of a cut output would name fewer packages than the
		// transaction touches.
		return "", dnfPlanUnreadable{"dnf wrote more about this transaction than the agent reads, " +
			"so the plan cannot describe what it would do"}
	}
	output := result.Stdout + "\n" + result.Stderr
	// A transaction dnf cannot resolve is not an empty plan.
	if reason := DNFUnresolvable(output); reason != "" {
		return "", fmt.Errorf("dnf cannot resolve this transaction: %s", reason)
	}
	return output, nil
}

// completeDNFChanges finishes the elements of an upgrade plan with what the
// transaction table does not say: the version installed now, and the security
// flag of the updates the advisories of the host classified.
func completeDNFChanges(changes []Change, installed map[string]string, classified []Change) {
	security := map[string]bool{}
	for _, change := range classified {
		if change.Security {
			security[change.Name] = true
			security[change.Name+"."+change.Architecture] = true
		}
	}
	for i := range changes {
		change := &changes[i]
		if change.Action == ActionRemove {
			continue
		}
		// The architecture first: a host carries two builds of one name, and the
		// change is about one of them.
		if version, ok := installed[change.Name+"."+change.Architecture]; ok {
			change.CurrentVersion = version
		} else {
			change.CurrentVersion = installed[change.Name]
		}
		change.Security = security[change.Name] || security[change.Name+"."+change.Architecture]
	}
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

// dnfPlanUnreadable is the refusal of a transaction whose table the agent does
// not recognise. It answers ErrPlanMetadataMissing: nothing was planned, and a
// plan shorter than the transaction would be approved for something else.
type dnfPlanUnreadable struct{ reason string }

func (e dnfPlanUnreadable) Error() string { return e.reason }

func (e dnfPlanUnreadable) Is(target error) bool { return target == ErrPlanMetadataMissing }

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
	// The same cache directory the unprivileged read will ask for, named rather
	// than left to dnf's own default: this runs as root and the read does not, and
	// the two default to different places.
	result := run(ctx, 10*time.Minute, dnfPath,
		"--quiet", "--setopt=cachedir="+dnfCacheDir(), "makecache")
	if !result.Ran || result.ExitCode != 0 {
		return fmt.Errorf("dnf makecache: %s", result.Reason())
	}
	warmDNFCacheForTheUnprivilegedRead(ctx)
	return nil
}

// warmDNFCacheForTheUnprivilegedRead compiles the metadata cache the way the
// agent's read will want it, while this still runs as root.
//
// makecache is not enough. libdnf5 recompiles the solv file when the options of
// the read differ from the options it was written with, and writing it means
// creating a temporary file in a directory that belongs to root. The agent plans
// unprivileged, so the recompilation fails - "cannot create temporary file ...
// Read-only file system" under the agent's own sandbox, "Permission denied"
// without it - and the plan of a host whose repository has just been republished
// fails with a filesystem error no operator can act on. Measured on agent-fedora
// on 02.10: after makecache the agent's read still failed; after the same read as
// root it succeeded.
//
// The exit code is not checked. check-update answers 100 when there are updates
// and 0 when there are none, this is a warm-up and not a question, and a refresh
// that fetched the metadata has done its job either way.
func warmDNFCacheForTheUnprivilegedRead(ctx context.Context) {
	args := append([]string{"--quiet"}, append(dnfReadArgs(), "check-update")...)
	_ = run(ctx, 5*time.Minute, dnfPath, args...)
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
	changes, err := dnfInstallChanges(output)
	if err != nil {
		return plan, err
	}
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

// obsoleteHeadings head the sections about a package that takes the place of
// another. Only dnf4 gives it one: dnf5 prints no such section at all, it
// writes the replaced package indented under the package that takes its place
// and counts it in the summary alone.
var obsoleteHeadings = []string{
	"obsoleting:",
}

// upgradeHeadings are every section an upgrade touches. A plan read from the
// direct updates alone would name neither the dependencies the transaction
// pulls in nor what it replaces or drops.
var upgradeHeadings = slices.Concat(installHeadings, removalHeadings, obsoleteHeadings)

// upgradeSummaries are the counts of an upgrade summary, in both spellings of
// dnf. The trailing space matters: "Installed size" is not a count of
// packages. A section this does not read - the packages dnf says it skips - is
// not counted either, so its absence from the table is not read as a short.
var upgradeSummaries = []string{
	"installing:", "install ",
	"upgrading:", "upgrade ",
	"downgrading:", "downgrade ",
	"removing:", "remove ",
	"reinstalling:", "reinstall ",
	"replacing:", "replacing ",
	"obsoleting:", "obsoleting ",
}

// dnfSectionAction says which direction a section of the transaction
// table means, and dnfSectionReason why its packages are in the plan.
func dnfSectionAction(heading string) string {
	switch {
	case strings.HasPrefix(heading, "upgrading"):
		return ActionUpgrade
	case strings.HasPrefix(heading, "downgrading"):
		return ActionDowngrade
	// The section dnfReplacedEntry puts a replaced package in: it is the one
	// that goes away, the one arriving in its place stands in the table itself.
	case strings.HasPrefix(heading, "removing"), strings.HasPrefix(heading, dnfReplacingSection):
		return ActionRemove
	}
	return ActionInstall
}

func dnfSectionReason(heading string) string {
	switch {
	// An obsoleting package is not named by the order: a repository says it takes
	// the place of something installed, and the package it replaces is dropped
	// along the way.
	case strings.Contains(heading, "unused"), strings.HasPrefix(heading, dnfReplacingSection):
		return ReasonOrphan
	case strings.Contains(heading, "dependen"), strings.HasPrefix(heading, "obsoleting"):
		return ReasonDependency
	}
	return ReasonRequested
}

// ParseDNFRemovalPlan reads the table of a transaction interrupted before
// execution.
func ParseDNFRemovalPlan(output string) ([]string, int, error) {
	// A removal reads only the sections of what goes away, and no replaced
	// package stands in them.
	entries, announced, _ := dnfTransactionSections(output, removalHeadings, removalSummaries)
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
	changes, _ := dnfInstallChanges(output)
	return changes
}

// dnfInstallChanges is what planInstall reads: the same table, and the refusal
// of a replaced package it cannot name - an installation drops it too.
func dnfInstallChanges(output string) ([]Change, error) {
	entries, _, unreadable := dnfTransactionSections(output, installHeadings, installSummaries)
	if len(unreadable) > 0 {
		return nil, dnfReplacedUnreadable(unreadable)
	}
	entries = withoutSupersededVersions(entries)
	changes := make([]Change, 0, len(entries))
	for _, entry := range entries {
		changes = append(changes, dnfChangeOf(entry))
	}
	return changes, nil
}

// ParseDNFUpgradePlan reads the whole table of an upgrade: what arrives on its
// own account and what arrives as a dependency, what is raised and what is
// lowered, what takes the place of something else and what goes away. A table
// this does not recognise is a refusal rather than a shorter plan: consent to
// four changes is not consent to the fourteen the transaction would make.
func ParseDNFUpgradePlan(output string) ([]Change, error) {
	entries, announced, unreadable := dnfTransactionSections(output, upgradeHeadings, upgradeSummaries)
	if len(unreadable) > 0 {
		return nil, dnfReplacedUnreadable(unreadable)
	}
	if len(entries) == 0 {
		// Every pending update is held or left out of this transaction: an empty
		// plan is the truth here, not a table that went unread.
		if WholeTransactionReady(output) {
			return nil, nil
		}
		return nil, dnfPlanUnreadable{"the transaction table was not recognised in the answer of dnf, " +
			"so the plan cannot say what this upgrade would install, replace or remove"}
	}
	if announced > len(entries) {
		return nil, dnfPlanUnreadable{fmt.Sprintf("dnf announces %d packages in this transaction and %d "+
			"were read from its table, so the plan would name fewer changes than it makes",
			announced, len(entries))}
	}
	// The fold comes after the count: dnf counts the superseded version in its
	// summary, so folding first would read a complete table as a short one.
	entries = withoutSupersededVersions(entries)
	changes := make([]Change, 0, len(entries))
	for _, entry := range entries {
		change := dnfChangeOf(entry)
		// A package that arrives without a version or without a repository comes
		// from a table in another format than this reads: the plan would say
		// neither what it installs nor where it comes from.
		if change.Action != ActionRemove && (change.CandidateVersion == "" ||
			change.Origin == "" || change.Origin == dnfRepositoryUnknown) {
			return nil, dnfPlanUnreadable{"the transaction table of dnf names no version or no " +
				"repository for " + entry.Name + ", so the plan cannot carry its identity"}
		}
		changes = append(changes, change)
	}
	return changes, nil
}

// dnfRepositoryUnknown is how dnf prints a package it cannot name a repository
// for. A plan cannot be carried out from a repository nobody can name, so a
// row with it is refused rather than guessed at.
const dnfRepositoryUnknown = "<unknown>"

// DNFDigestUnknown stands in the plan where the checksum of an archive would:
// the transaction table of dnf publishes none, and an empty field would read as
// a package whose artefact needs no proof.
const DNFDigestUnknown = "dnf-table-unknown:no_checksum_published"

// dnfChangeOf turns one row of the transaction table into an element of a plan:
// the full identity of the package - name, epoch, version, release and
// architecture - the repository it comes from, and what its section means.
func dnfChangeOf(entry dnfEntry) Change {
	change := Change{
		Name: entry.Name, Architecture: entry.Architecture, Origin: entry.Repository,
		Action: dnfSectionAction(entry.Section), Reason: dnfSectionReason(entry.Section),
	}
	if change.Action == ActionRemove {
		// A package that goes away has a version on the host and no candidate; its
		// repository column names where it came from.
		change.CurrentVersion = entry.Version
		return change
	}
	change.CandidateVersion = entry.Version
	change.Digest = DNFDigestUnknown
	return change
}

// dnfEntry is one row of the transaction table with the section it was
// read under.
type dnfEntry struct {
	Name, Architecture, Version, Repository, Section string
}

// dnfTransactionSections reads the packages from the transaction table. The
// third result holds the lines that name a replaced package in neither shape:
// they are not entries, and they are not nothing either.
func dnfTransactionSections(output string, headings, summaries []string) ([]dnfEntry, int, []string) {
	var entries []dnfEntry
	var unreadable []string
	seen := map[string]bool{}
	inSection := false
	inSummary := false
	announced := 0
	section := ""

	// One name can stand twice in one transaction - an old kernel removed while a
	// new one arrives - so what tells the rows apart is the whole identity.
	add := func(entry dnfEntry) {
		key := entry.Name + "." + entry.Architecture + "-" + entry.Version
		if seen[key] {
			return
		}
		seen[key] = true
		entries = append(entries, entry)
	}

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
			// An upgrade announces every direction on a line of its own, so the counts
			// are added up rather than overwritten.
			if matchesSummary(lower, summaries) {
				for _, field := range strings.Fields(lower) {
					if number, err := strconv.Atoi(field); err == nil {
						announced += number
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
		// Neither dnf gives the replaced package a section of its own: it stands
		// indented under the package that takes its place.
		if entry, replaced, readable := dnfReplacedEntry(trimmed); replaced {
			if !readable {
				unreadable = append(unreadable, trimmed)
				continue
			}
			add(entry)
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		entry := dnfEntry{Name: fields[0], Section: section}
		// The columns after the name: architecture, version, repository, size.
		if len(fields) > 3 {
			entry.Architecture, entry.Version, entry.Repository = fields[1], fields[2], fields[3]
		}
		add(entry)
	}
	return entries, announced, unreadable
}

// dnfReplacedUnreadable refuses a table whose replaced package cannot be named.
// Skipping the line would hide a removal the transaction makes.
func dnfReplacedUnreadable(lines []string) error {
	return dnfPlanUnreadable{"dnf names a package this transaction replaces in a line the agent " +
		"does not read (" + strings.Join(lines, "; ") + "), so the plan cannot say which package " +
		"would be removed"}
}

// dnfReplacingSection is the section a replaced package is filed under. Neither
// generation of dnf prints it as a heading; it is what the indented line means.
const dnfReplacingSection = "replacing:"

// dnfReplacedEntry reads the line dnf writes under the package that takes
// another's place. The two generations write it differently, measured on
// Fedora 42:
//
//	dnf4: "     replacing  words.noarch 3.0-61.fc42"
//	dnf5: "   replacing words           noarch 3.0-61.fc42      anaconda   4.7 MiB"
//
// Read as an ordinary row the line would enter the plan as a package named
// "replacing", and since a replaced package becomes a removal, the plan would
// promise to remove something nobody named. A line in neither shape is refused
// rather than guessed at, for the same reason.
func dnfReplacedEntry(line string) (entry dnfEntry, replaced, readable bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "replacing") {
		return dnfEntry{}, false, false
	}
	entry = dnfEntry{Section: dnfReplacingSection}
	switch {
	case len(fields) >= 5:
		// dnf5 puts the replaced package in the columns of the table itself: name,
		// architecture, version, the repository it came from, then its size.
		entry.Name, entry.Architecture, entry.Version, entry.Repository =
			fields[1], fields[2], fields[3], fields[4]
	case len(fields) == 3:
		// dnf4 writes the name and the architecture as one token, the version after
		// it. Without an architecture the token is not that shape either.
		index := strings.LastIndex(fields[1], ".")
		if index <= 0 || index == len(fields[1])-1 {
			return dnfEntry{}, true, false
		}
		entry.Name, entry.Architecture = fields[1][:index], fields[1][index+1:]
		entry.Version = fields[2]
	default:
		return dnfEntry{}, true, false
	}
	return entry, true, entry.Name != "" && entry.Architecture != "" && entry.Version != ""
}

// withoutSupersededVersions drops the "replacing" rows naming the version a
// transaction raises away from: a row of the same name and architecture as an
// arriving row is that package's previous version, not a package the host
// loses. dnf5 writes one under every ordinary upgrade. Kept as a removal it
// makes the plan promise to take away a name that stays installed, and the
// transaction is then told to remove it as well. A same-name row under
// "Removing:" is left alone - that is how an installonly package really drops
// its old build.
func withoutSupersededVersions(entries []dnfEntry) []dnfEntry {
	arriving := map[string]bool{}
	for _, entry := range entries {
		if dnfSectionAction(entry.Section) != ActionRemove {
			arriving[entry.Name+"."+entry.Architecture] = true
		}
	}
	kept := make([]dnfEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Section == dnfReplacingSection && arriving[entry.Name+"."+entry.Architecture] {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
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
