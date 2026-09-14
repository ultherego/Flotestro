package packages

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	pacmanPath       = "/usr/bin/pacman"
	pacmanKeyPath    = "/usr/bin/pacman-key"
	vercmpPath       = "/usr/bin/vercmp"
	checkupdatesPath = "/usr/bin/checkupdates"
	// PacmanConfPath is the one configuration file of pacman. There is no
	// conf.d: the sources, the held packages and the options all live here,
	// so the panel edits it in place and marks every line it owns.
	PacmanConfPath = "/etc/pacman.conf"
	// PacmanConfDir holds the mirror lists and the files the panel writes
	// next to them: the keys of the sources it manages.
	PacmanConfDir = "/etc/pacman.d"
	// pacmanLockPath is the lock of the package database. It is not a flock:
	// the file itself is the lock, created exclusively and removed at the end
	// of a transaction. A crash leaves it behind.
	pacmanLockPath    = "/var/lib/pacman/db.lck"
	pacmanCacheDir    = "/var/cache/pacman/pkg"
	pacmanDatabaseDir = "/var/lib/pacman"
	pacmanModulesRoot = "/usr/lib/modules"
	pacmanProcRoot    = "/proc"
)

// PacmanName is the name the adapter reports and the panel enumerates.
const PacmanName = "pacman"

// The error codes of the pacman adapter. They join the shared codes of the
// package module: an operation refused by the policy of the distribution is
// to be recognisable by the panel rather than read out of a sentence.
const (
	// ErrorCheckupdatesMissing means the host cannot plan an upgrade without
	// touching the sync database: checkupdates from pacman-contrib is the
	// tool that syncs a copy of its own.
	ErrorCheckupdatesMissing = "checkupdates_missing"
	// ErrorPartialUpgrade means an upgrade of named packages was ordered on
	// a distribution that does not support partial upgrades.
	ErrorPartialUpgrade = "partial_upgrade_unsupported"
	// ErrorSecurityUnknown means the host cannot tell a security update from
	// any other, because its repositories carry no such metadata.
	ErrorSecurityUnknown = "security_metadata_unavailable"
)

// ErrCheckupdatesMissing means an upgrade cannot be planned on this host.
// Planning must not modify the system, and on Arch the only way to see the
// pending updates without syncing the system database is checkupdates.
var ErrCheckupdatesMissing = errors.New("checkupdates is not installed, so an upgrade cannot " +
	"be planned without touching the sync database")

// ErrPartialUpgrade means an upgrade narrowed to named packages was ordered.
// Arch supports no partial upgrades: a package raised alone links against
// libraries the rest of the system does not have yet, and the host stops
// working in ways nobody planned. The whole system upgrades at once.
var ErrPartialUpgrade = errors.New("partial upgrades are unsupported on Arch: the whole " +
	"system upgrades at once")

// ErrSecurityUnknown means the classification cannot be made. It is an
// answer rather than zero: a host with no security metadata has an unknown
// number of security updates, not none.
var ErrSecurityUnknown = errors.New("the Arch repositories carry no security metadata")

// ErrDatabaseBroken means the package database needs repairing before any
// transaction can go through.
var ErrDatabaseBroken = errors.New("the package database needs repairing")

// Pacman is the adapter of Arch Linux and its derivatives.
type Pacman struct{}

func (p *Pacman) Name() string { return PacmanName }

func (p *Pacman) Available() bool {
	info, err := os.Stat(pacmanPath)
	return err == nil && !info.IsDir()
}

// LockHeld reports the database lock. The file is the lock, so its presence
// is the answer; whether the process that created it still runs is settled
// by the repair rather than by a transaction, which must not remove the lock
// of somebody else's running pacman.
func (p *Pacman) LockHeld() (bool, string) {
	if fileExists(pacmanLockPath) {
		return true, pacmanLockPath
	}
	return false, ""
}

// checkupdatesDB is the directory of the temporary sync database. It is
// named explicitly, so the plan and its enrichment read the same copy and
// the copy lands in the working directory of the process rather than in
// /tmp.
func checkupdatesDB() string {
	return filepath.Join(runtimeDir, "cache", "checkupdates")
}

// Plan computes the changes without touching the system database.
//
// An upgrade plan comes from checkupdates, which syncs a copy of the
// database in a directory of its own. "pacman -Sy --print" would answer the
// same question and is deliberately not used: it refreshes the system sync
// database, and a refresh without an upgrade is exactly the state Arch warns
// against.
func (p *Pacman) Plan(ctx context.Context, options Options) (Plan, error) {
	plan := Plan{Manager: p.Name(), DiskAvailableBytes: diskAvailable("/"), Mode: options.Mode}
	// A lock left by a crashed pacman stops every transaction; the plan says
	// so before anyone orders one.
	if held, path := p.LockHeld(); held {
		plan.Blocked = []Blocked{{Name: "pacman", Status: "the database lock " + path +
			" exists; a transaction will need the repair unless a pacman process holds it"}}
	}

	switch options.Mode {
	case ModeRemove:
		return p.planRemove(ctx, plan, options)
	case ModeInstall:
		return p.planInstall(ctx, plan, options)
	}

	if options.SecurityOnly {
		return plan, fmt.Errorf("%w, so a security-only plan cannot be computed", ErrSecurityUnknown)
	}
	if len(options.Packages) > 0 {
		return plan, fmt.Errorf("%w; plan the upgrade without naming packages", ErrPartialUpgrade)
	}
	if !fileExists(checkupdatesPath) {
		return plan, ErrCheckupdatesMissing
	}

	result := run(ctx, 10*time.Minute, checkupdatesPath, "--nocolor")
	switch {
	case !result.Ran:
		return plan, fmt.Errorf("checkupdates: %s", result.Reason())
	case result.ExitCode == checkupdatesNoUpdates:
		return plan, nil
	case result.ExitCode != 0:
		return plan, fmt.Errorf("checkupdates: %s", result.Reason())
	}

	for _, change := range ParseCheckupdates(result.Stdout) {
		// An ordinary upgrade skips the agent package, so the plan does not
		// promise a change the transaction will not make.
		if change.Name == AgentPackage {
			continue
		}
		plan.Changes = append(plan.Changes, change)
	}
	p.enrichFromSyncCopy(ctx, &plan)
	plan.RebootPredicted = p.rebootPredicted(plan.Changes)
	// The sizes of the candidates come from the same copy of the database
	// the plan came from, so the plan and its sizes agree.
	plan.Space = p.planSpace(ctx, plan, "--dbpath", checkupdatesDB())
	return plan, nil
}

// planSpace measures where the bytes of the plan go. The download size is
// already summed up from the printed targets; the growth of /usr comes from
// the installed size pacman prints for the candidate and for what is there
// now. The database arguments pick the sync database the candidates are
// read from.
func (p *Pacman) planSpace(ctx context.Context, plan Plan, database ...string) []SpaceFact {
	needs := spaceNeeds{downloadKnown: true, installBasis: BasisInstalledSize}
	if len(plan.Changes) == 0 {
		return spaceFacts(pacmanCacheDir, pacmanDatabaseDir, needs)
	}
	needs.download = plan.DownloadBytes
	needs.kernel = anyKernel(p.Name(), plan.Changes)
	names := changeNames(plan.Changes)
	candidate := p.packageInfoSizes(ctx, append(append([]string{"-Si"}, database...), names...)...)
	current := p.packageInfoSizes(ctx, append([]string{"-Qi"}, names...)...)
	grown, measured := growth(names, candidate, current)
	installNeeds(&needs, grown, measured)
	return spaceFacts(pacmanCacheDir, pacmanDatabaseDir, needs)
}

// packageInfoSizes runs a query of pacman and reads the installed sizes out
// of its answer. A name pacman does not know ends the query with an error
// and the records of the known ones on the standard output; what it printed
// is used.
func (p *Pacman) packageInfoSizes(ctx context.Context, args ...string) map[string]uint64 {
	result := run(ctx, 2*time.Minute, pacmanPath, args...)
	if !result.Ran {
		return nil
	}
	return ParsePacmanInfoSizes(result.Stdout)
}

// ParsePacmanInfoSizes reads the "Name" and "Installed Size" lines of
// "pacman -Si" and "pacman -Qi":
//
//	Name            : linux
//	Installed Size  : 143.39 MiB
func ParsePacmanInfoSizes(output string) map[string]uint64 {
	sizes := map[string]uint64{}
	name := ""
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Name":
			name = strings.TrimSpace(value)
		case "Installed Size":
			if size, ok := ParseHumanSize(value); ok && name != "" {
				sizes[name] = size
			}
		}
	}
	return sizes
}

// checkupdatesNoUpdates is the exit code checkupdates ends with when there is
// nothing to upgrade. A failure to fetch ends with 1 - and that is not "no
// updates".
const checkupdatesNoUpdates = 2

// ParseCheckupdates reads lines of the form:
//
//	linux 6.16.5.arch1-1 -> 6.16.6.arch1-1
//
// Security stays false on every change: the Arch repositories carry no such
// metadata, and the plan says so through the adapter rather than by
// marking every update as harmless.
func ParseCheckupdates(output string) []Change {
	var changes []Change
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[2] != "->" {
			continue
		}
		changes = append(changes, Change{
			Name: fields[0], CurrentVersion: fields[1], CandidateVersion: fields[3],
		})
	}
	return changes
}

// enrichFromSyncCopy fills the origin and the download size in from the copy
// of the database checkupdates has just synced. A failure leaves the plan as
// it was: the size is an estimate and the origin a convenience, neither is
// worth a failed plan.
func (p *Pacman) enrichFromSyncCopy(ctx context.Context, plan *Plan) {
	if len(plan.Changes) == 0 {
		return
	}
	result := run(ctx, 2*time.Minute, pacmanPath, "-Sup", "--noconfirm",
		"--dbpath", checkupdatesDB(), "--ignore", AgentPackage,
		"--print-format", pacmanPrintFormat)
	if !result.Ran || result.ExitCode != 0 {
		return
	}
	targets := ParsePacmanTargets(result.Stdout)
	for i := range plan.Changes {
		if target, ok := targets[plan.Changes[i].Name]; ok {
			plan.Changes[i].Origin = target.Origin
			plan.DownloadBytes += target.Size
		}
	}
}

// pacmanPrintFormat asks --print for the name, the version, the repository
// and the size of every target, separated by tabs.
const pacmanPrintFormat = "%n\t%v\t%r\t%s"

// PacmanTarget is one line of a printed transaction.
type PacmanTarget struct {
	Name, Version, Origin string
	Size                  uint64
}

// ParsePacmanTargets reads the output of --print in pacmanPrintFormat.
func ParsePacmanTargets(output string) map[string]PacmanTarget {
	targets := map[string]PacmanTarget{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) < 4 || strings.TrimSpace(fields[0]) == "" {
			continue
		}
		size, _ := strconv.ParseUint(strings.TrimSpace(fields[3]), 10, 64)
		targets[fields[0]] = PacmanTarget{
			Name: fields[0], Version: fields[1], Origin: fields[2], Size: size,
		}
	}
	return targets
}

// rebootPredicted guesses the need for a restart from the packages being
// upgraded. The kernel packages of Arch are named "linux" and its variants;
// the headers, the firmware and the documentation are not kernels.
func (p *Pacman) rebootPredicted(changes []Change) bool {
	for _, change := range changes {
		name := change.Name
		if pacmanKernelPackage(name) || name == "glibc" || name == "systemd" {
			return true
		}
	}
	return false
}

// pacmanKernelPackage recognises a kernel by its name.
func pacmanKernelPackage(name string) bool {
	if name == "linux" {
		return true
	}
	if !strings.HasPrefix(name, "linux-") {
		return false
	}
	for _, notAKernel := range []string{"headers", "firmware", "docs", "api", "tools", "atm"} {
		if strings.Contains(name, notAKernel) {
			return false
		}
	}
	return true
}

// Refresh syncs the system database. It requires root and the lock.
//
// This is the one place the system sync database is touched outside a full
// upgrade: the panel orders it deliberately, as the refresh step of a plan
// or before an installation.
func (p *Pacman) Refresh(ctx context.Context) error {
	if held, path := p.LockHeld(); held {
		return fmt.Errorf("%w: %s", ErrLocked, path)
	}
	result := run(ctx, 10*time.Minute, pacmanPath, "-Sy", "--noconfirm", "--noprogressbar")
	if !result.Ran || result.ExitCode != 0 {
		return p.failure("pacman -Sy", result)
	}
	return nil
}

// Upgrade carries the full system upgrade out.
//
// There is no narrowing here: Arch supports no partial upgrades, so a
// transaction on named packages is refused with a code rather than carried
// out with a warning. The agent package is the one exception - it is skipped,
// because raised in the middle of a transaction it runs itself it would cut
// the host off halfway through. Replacing the agent has an operation of its
// own.
func (p *Pacman) Upgrade(ctx context.Context, options Options) (Apply, error) {
	apply := Apply{Manager: p.Name()}
	if options.SecurityOnly {
		return apply, fmt.Errorf("%w, so a security-only upgrade cannot be told apart from a full one",
			ErrSecurityUnknown)
	}
	if len(options.Packages) > 0 {
		return apply, fmt.Errorf("%w: %s", ErrPartialUpgrade, strings.Join(options.Packages, ", "))
	}
	if held, path := p.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}
	// mkinitcpio builds the initramfs from the module tree like the other
	// families' tools: hidden modules threaten a host that will not come up.
	if hidden, dir := pacmanModulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	before := p.installedVersions(ctx)
	args := []string{"-Syu", "--noconfirm", "--noprogressbar", "--ignore", AgentPackage}
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, false, pacmanPath, args...)

	// A damaged file in the cache has exactly one correct answer: fetch it
	// again. The retry covers that alone; a signature nobody trusts is a
	// decision of the operator.
	if (!result.Ran || result.ExitCode != 0) && BrokenDownload(result.Stderr, result.Stdout) {
		if removed := p.dropDamagedArchives(result.Stderr + "\n" + result.Stdout); len(removed) > 0 {
			apply.SelfRepair = append(apply.SelfRepair,
				"the damaged archives were removed from the cache ("+strings.Join(removed, ", ")+
					") and the transaction was retried")
			result = runWithProgress(ctx, 45*time.Minute, options.Progress, false, pacmanPath, args...)
		}
	}

	after := p.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = p.DatabaseBroken(ctx)
	apply.RebootRequired = pacmanRebootRequired()
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, p.failure("pacman -Syu", result)
	}
	return apply, nil
}

// damagedArchive finds the name of a package file pacman complained about.
var damagedArchive = regexp.MustCompile(`([A-Za-z0-9@._+-]+\.pkg\.tar(?:\.[a-z0-9]+)?)`)

// dropDamagedArchives removes the named package files from the cache along
// with their signatures. It returns what it removed: a silent repair would be
// worse than none.
func (p *Pacman) dropDamagedArchives(output string) []string {
	var removed []string
	seen := map[string]bool{}
	for _, match := range damagedArchive.FindAllStringSubmatch(output, -1) {
		name := filepath.Base(match[1])
		if seen[name] {
			continue
		}
		seen[name] = true
		path := filepath.Join(pacmanCacheDir, name)
		if err := os.Remove(path); err != nil {
			continue
		}
		_ = os.Remove(path + ".sig")
		removed = append(removed, name)
	}
	return removed
}

// installedVersions returns a map of package -> version.
func (p *Pacman) installedVersions(ctx context.Context) map[string]string {
	result := run(ctx, 2*time.Minute, pacmanPath, "-Q")
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

// DatabaseBroken checks the consistency of the local database. The check
// needs neither root nor the lock.
func (p *Pacman) DatabaseBroken(ctx context.Context) bool {
	result := run(ctx, 2*time.Minute, pacmanPath, "-Dk")
	return result.Ran && result.ExitCode != 0
}

// planRemove computes what will disappear along with the named packages.
//
// "--print" answers without root and without the lock, and it is pacman's
// own resolution of the dependencies rather than our reconstruction: only
// such an answer may be shown to a person about to remove something.
func (p *Pacman) planRemove(ctx context.Context, plan Plan, options Options) (Plan, error) {
	if len(options.Packages) == 0 {
		return plan, fmt.Errorf("a removal plan requires a list of packages")
	}
	targets := append([]string{}, options.Packages...)
	for attempt := 0; attempt < 2 && len(targets) > 0; attempt++ {
		args := append([]string{"-Rsp", "--noconfirm", "--print-format", "%n"}, targets...)
		result := run(ctx, 5*time.Minute, pacmanPath, args...)
		if !result.Ran {
			return plan, fmt.Errorf("pacman -Rsp: %s", result.Reason())
		}
		output := result.Stdout + "\n" + result.Stderr
		if result.ExitCode == 0 {
			plan.Removals = pacmanPrintedNames(result.Stdout)
			plan.Protected = ProtectedInSet(plan.Removals)
			return plan, nil
		}
		// A package that is not there is not an error of the plan: there is
		// nothing to remove. The rest of the order is asked about again.
		if missing := PacmanTargetsNotFound(output); len(missing) > 0 {
			targets = without(targets, missing)
			continue
		}
		if reason := PacmanUnresolvable(output); reason != "" {
			// An empty plan would read as "nothing will disappear" - the
			// answer to a question other than "this cannot be removed".
			return plan, fmt.Errorf("pacman cannot resolve this removal: %s", reason)
		}
		return plan, fmt.Errorf("pacman -Rsp: %s", result.Reason())
	}
	return plan, nil
}

// planInstall computes what will arrive along with the named packages.
//
// The plan reads the sync database as it is. Installing does not refresh it
// on its own, so a plan made against an old database is a plan of an old
// version: the refresh step of the plan is where the operator brings it up
// to date, and MetadataRefreshed says whether that happened.
func (p *Pacman) planInstall(ctx context.Context, plan Plan, options Options) (Plan, error) {
	if len(options.Packages) == 0 {
		return plan, fmt.Errorf("an installation plan requires a list of packages")
	}
	args := append([]string{"-Sp", "--needed", "--noconfirm", "--print-format", pacmanPrintFormat},
		options.Packages...)
	result := run(ctx, 5*time.Minute, pacmanPath, args...)
	if !result.Ran {
		return plan, fmt.Errorf("pacman -Sp: %s", result.Reason())
	}
	output := result.Stdout + "\n" + result.Stderr
	if missing := PacmanTargetsNotFound(output); len(missing) > 0 {
		return plan, fmt.Errorf("pacman does not know a package from this order: %s",
			strings.Join(missing, ", "))
	}
	if reason := PacmanUnresolvable(output); reason != "" {
		return plan, fmt.Errorf("pacman cannot resolve this installation: %s", reason)
	}
	if result.ExitCode != 0 {
		return plan, fmt.Errorf("pacman -Sp: %s", result.Reason())
	}
	targets := ParsePacmanTargets(result.Stdout)
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	installed := p.installedVersions(ctx)
	for _, name := range names {
		target := targets[name]
		plan.Changes = append(plan.Changes, Change{
			Name: name, CurrentVersion: installed[name],
			CandidateVersion: target.Version, Origin: target.Origin,
		})
		plan.DownloadBytes += target.Size
	}
	plan.RebootPredicted = p.rebootPredicted(plan.Changes)
	plan.Space = p.planSpace(ctx, plan)
	return plan, nil
}

// pacmanPrintedNames reads the names printed by "--print-format %n".
func pacmanPrintedNames(output string) []string {
	var names []string
	for _, line := range strings.Split(output, "\n") {
		name := strings.TrimSpace(line)
		if name == "" || strings.ContainsAny(name, " :") {
			continue
		}
		names = append(names, name)
	}
	return names
}

// targetNotFound recognises the answer "there is no such package".
var targetNotFound = regexp.MustCompile(`(?m)^error: target not found: (\S+)`)

// PacmanTargetsNotFound lists the packages pacman does not know from the
// output of a failed command.
func PacmanTargetsNotFound(output string) []string {
	var names []string
	for _, match := range targetNotFound.FindAllStringSubmatch(output, -1) {
		names = append(names, match[1])
	}
	return names
}

// PacmanUnresolvable recognises a transaction pacman cannot resolve and
// returns the reason it gave.
func PacmanUnresolvable(output string) string {
	lower := strings.ToLower(output)
	markers := []string{
		"could not satisfy dependencies",
		"unresolvable package conflicts",
		"conflicting dependencies",
		"conflicting files",
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
	// The reason follows the error: pacman lists what breaks what in lines
	// starting with "::".
	var reasons []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "::") || strings.HasPrefix(trimmed, "error:") {
			reasons = append(reasons, strings.TrimSpace(strings.TrimPrefix(trimmed, "::")))
		}
	}
	if len(reasons) == 0 {
		return "pacman rejected the transaction without giving a reason"
	}
	if len(reasons) > 3 {
		reasons = reasons[:3]
	}
	return strings.Join(reasons, " / ")
}

func without(list, drop []string) []string {
	set := map[string]bool{}
	for _, name := range drop {
		set[name] = true
	}
	var kept []string
	for _, name := range list {
		if !set[name] {
			kept = append(kept, name)
		}
	}
	return kept
}

// Install adds packages along with their dependencies.
//
// Without a sync: "-Sy" followed by "-S" is the partial upgrade Arch warns
// against, so the installation takes the database as it is. A database
// nobody refreshed installs the versions it knows about - and a mirror that
// no longer has them answers with a fetch error rather than with a silent
// substitute.
func (p *Pacman) Install(ctx context.Context, options Options) (Apply, error) {
	apply := Apply{Manager: p.Name()}
	if len(options.Packages) == 0 {
		return apply, fmt.Errorf("an installation requires a list of packages")
	}
	if held, path := p.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}
	if hidden, dir := pacmanModulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	before := p.installedVersions(ctx)
	// pacman installs the version the sync database has, also when it is
	// older than the installed one, and has no switch that would refuse it.
	// The refusal is ours: going back a version is sometimes irreversible for
	// the data format and needs a deliberate consent.
	if !options.AllowDowngrade {
		if downgrade, err := p.wouldDowngrade(ctx, options.Packages, before); err != nil {
			return apply, err
		} else if downgrade != "" {
			return apply, fmt.Errorf("the installation would downgrade %s; the operation "+
				"did not allow a downgrade", downgrade)
		}
	}

	args := append([]string{"-S", "--needed", "--noconfirm", "--noprogressbar"}, options.Packages...)
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, false, pacmanPath, args...)

	after := p.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = p.DatabaseBroken(ctx)
	apply.RebootRequired = pacmanRebootRequired()
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, p.failure("pacman -S", result)
	}
	return apply, nil
}

// wouldDowngrade names the first package the installation would take back a
// version, or nothing.
func (p *Pacman) wouldDowngrade(ctx context.Context, pkgs []string,
	installed map[string]string) (string, error) {
	args := append([]string{"-Sp", "--needed", "--noconfirm", "--print-format", pacmanPrintFormat}, pkgs...)
	result := run(ctx, 5*time.Minute, pacmanPath, args...)
	if !result.Ran || result.ExitCode != 0 {
		// The installation itself will explain the failure; the check is
		// only about the direction of a change that can be computed.
		return "", nil
	}
	for name, target := range ParsePacmanTargets(result.Stdout) {
		current, present := installed[name]
		if !present || current == target.Version {
			continue
		}
		comparison := run(ctx, 30*time.Second, vercmpPath, target.Version, current)
		if comparison.Ran && comparison.ExitCode == 0 && strings.TrimSpace(comparison.Stdout) == "-1" {
			return fmt.Sprintf("%s from %s to %s", name, current, target.Version), nil
		}
	}
	return "", nil
}

// Remove removes the named packages along with what disappears with them.
//
// The set is computed again right before the operation and compared with what
// the operator approved: a difference means the host has changed since the
// plan.
func (p *Pacman) Remove(ctx context.Context, options Options, expected []string) (Apply, error) {
	apply := Apply{Manager: p.Name()}
	if len(options.Packages) == 0 {
		return apply, fmt.Errorf("a removal requires a list of packages")
	}
	if held, path := p.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}

	plan, err := p.planRemove(ctx, Plan{Manager: p.Name()}, options)
	if err != nil {
		return apply, err
	}
	if len(plan.Protected) > 0 {
		return apply, fmt.Errorf("%w: %s", ErrProtectedPackage, strings.Join(plan.Protected, ", "))
	}
	if difference := compareSets(expected, plan.Removals); difference != "" {
		return apply, fmt.Errorf("%w: %s", ErrPlanChanged, difference)
	}

	before := p.installedVersions(ctx)
	args := append([]string{"-Rs", "--noconfirm", "--noprogressbar"}, options.Packages...)
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, false, pacmanPath, args...)

	after := p.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = p.DatabaseBroken(ctx)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, p.failure("pacman -Rs", result)
	}
	return apply, nil
}

// failure classifies a failed pacman command into the errors of the module.
//
// pacman writes in English regardless of the locale under LC_ALL=C, so the
// messages are stable: a lock that could not be taken is the lock error, a
// damaged database is the database error, and the rest - a signature nobody
// trusts, a target that does not exist, a conflict - stays a transaction
// error with the reason in the message.
func (p *Pacman) failure(prefix string, result commandResult) error {
	text := strings.ToLower(result.Stderr + "\n" + result.Stdout)
	switch {
	case strings.Contains(text, "could not lock database") ||
		strings.Contains(text, "unable to lock database"):
		return fmt.Errorf("%w: %s", ErrLocked, pacmanLockPath)
	case strings.Contains(text, "invalid or corrupted database") ||
		strings.Contains(text, "could not open database") ||
		strings.Contains(text, "database is not valid") ||
		(strings.Contains(text, "could not register") && strings.Contains(text, "database")):
		return fmt.Errorf("%w: %s: %s", ErrDatabaseBroken, prefix, result.Reason())
	}
	if reason := PacmanTrustProblem(result.Stderr + "\n" + result.Stdout); reason != "" {
		return fmt.Errorf("%s: a signature the host does not trust: %s", prefix, reason)
	}
	if missing := PacmanTargetsNotFound(result.Stderr + "\n" + result.Stdout); len(missing) > 0 {
		return fmt.Errorf("%s: target not found: %s", prefix, strings.Join(missing, ", "))
	}
	if reason := PacmanUnresolvable(result.Stderr + "\n" + result.Stdout); reason != "" {
		return fmt.Errorf("%s: %s", prefix, reason)
	}
	return fmt.Errorf("%s: %s", prefix, result.Reason())
}

// PacmanTrustProblem recognises a failure of the signature check and returns
// the line that names the key.
func PacmanTrustProblem(output string) string {
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "signature from") &&
			(strings.Contains(lower, "unknown trust") || strings.Contains(lower, "is marginal trust") ||
				strings.Contains(lower, "is invalid") || strings.Contains(lower, "is unknown")) {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "error:"))
		}
		if strings.Contains(lower, "invalid or corrupted package (pgp signature)") ||
			strings.Contains(lower, "key could not be looked up remotely") ||
			strings.Contains(lower, "required key missing from keyring") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "error:"))
		}
	}
	return ""
}

// pacmanModulesHidden checks whether the process sees any module tree at
// all.
//
// The shared check looks for the tree of the running kernel, and on a
// rolling distribution that tree is legitimately gone after a kernel upgrade
// nobody has rebooted after: mkinitcpio builds the image for the installed
// kernel rather than the running one. What must not be missing is the whole
// directory - that is the sign of a namespace hiding the modules.
func pacmanModulesHidden() (bool, string) {
	if !kernelIsModular("/proc/modules") {
		return false, ""
	}
	entries, err := os.ReadDir(pacmanModulesRoot)
	if err != nil {
		return false, ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return false, ""
		}
	}
	return true, pacmanModulesRoot
}

// pacmanRebootRequired says whether the running kernel has been replaced on
// disk. Arch keeps no restart marker; the idiom of the distribution is the
// module tree of the running kernel, which the upgrade of the kernel package
// removes.
func pacmanRebootRequired() bool {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false
	}
	release := strings.TrimRight(string(uts.Release[:]), "\x00")
	if release == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(pacmanModulesRoot, release))
	return os.IsNotExist(err)
}

// PendingUpdates counts the updates for the inventory without touching the
// system database. The count is undetermined when it cannot be computed - a
// host without checkupdates has an unknown number of updates rather than
// none.
func (p *Pacman) PendingUpdates(ctx context.Context) (int, string) {
	if !fileExists(checkupdatesPath) {
		return 0, ErrCheckupdatesMissing.Error()
	}
	result := run(ctx, 10*time.Minute, checkupdatesPath, "--nocolor")
	switch {
	case !result.Ran:
		return 0, "checkupdates: " + result.Reason()
	case result.ExitCode == checkupdatesNoUpdates:
		return 0, ""
	case result.ExitCode != 0:
		return 0, "checkupdates: " + result.Reason()
	}
	return len(ParseCheckupdates(result.Stdout)), ""
}

// The hold of packages. pacman keeps it in IgnorePkg of /etc/pacman.conf
// rather than in a state of its own, and there is no conf.d to put a file of
// ours in. The panel therefore owns one line of the file, marked with a
// comment, and never rewrites the lines of the administrator: a package held
// by hand in another IgnorePkg line stays held, and the panel says so
// instead of quietly leaving it in place.

// holdMarker stands right before the IgnorePkg line the panel owns.
const holdMarker = "# flotestro: packages held by the panel"

// SetHold holds or releases the upgrades of packages.
func (p *Pacman) SetHold(ctx context.Context, pkgs []string, hold bool) (Apply, error) {
	apply := Apply{Manager: p.Name()}
	if len(pkgs) == 0 {
		return apply, fmt.Errorf("a hold requires a list of packages")
	}
	for _, name := range pkgs {
		if name == "" || strings.ContainsAny(name, " \t\n#=[]") {
			return apply, fmt.Errorf("an invalid package name %q", name)
		}
	}
	data, err := os.ReadFile(PacmanConfPath)
	if err != nil {
		return apply, fmt.Errorf("%s: %w", PacmanConfPath, err)
	}
	content, err := SetPacmanHolds(string(data), pkgs, hold)
	if err != nil {
		return apply, err
	}
	if content == string(data) {
		return apply, nil
	}
	if err := replaceFile(PacmanConfPath, []byte(content)); err != nil {
		return apply, fmt.Errorf("%s: %w", PacmanConfPath, err)
	}
	return apply, nil
}

// Holds returns the packages held on the host: the ones of the panel and the
// ones of the administrator alike. A held package will not get updates
// whoever held it, and the operator is to see that.
func (p *Pacman) Holds(ctx context.Context) []string {
	data, err := os.ReadFile(PacmanConfPath)
	if err != nil {
		return nil
	}
	_, all := PacmanHolds(string(data))
	return all
}

// PacmanHolds reads the IgnorePkg entries of the options section. It returns
// the ones the panel owns and all of them.
func PacmanHolds(content string) (managed, all []string) {
	lines := strings.Split(content, "\n")
	section := ""
	seen := map[string]bool{}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if header, ok := pacmanSectionHeader(trimmed); ok {
			section = header
			continue
		}
		if section != "options" {
			continue
		}
		key, value, ok := pacmanEntry(trimmed)
		if !ok || key != "IgnorePkg" {
			continue
		}
		ours := i > 0 && strings.TrimSpace(lines[i-1]) == holdMarker
		for _, name := range strings.Fields(value) {
			if ours {
				managed = append(managed, name)
			}
			if !seen[name] {
				seen[name] = true
				all = append(all, name)
			}
		}
	}
	return managed, all
}

// SetPacmanHolds rewrites the line of the panel in the content of
// pacman.conf. The result is the same whatever the number of calls: the
// marker and the line are replaced rather than added.
func SetPacmanHolds(content string, pkgs []string, hold bool) (string, error) {
	managed, all := PacmanHolds(content)
	ours := map[string]bool{}
	for _, name := range managed {
		ours[name] = true
	}
	set := map[string]bool{}
	for name := range ours {
		set[name] = true
	}
	if hold {
		for _, name := range pkgs {
			set[name] = true
		}
	} else {
		for _, name := range pkgs {
			if ours[name] {
				delete(set, name)
				continue
			}
			for _, held := range all {
				if held == name {
					return "", fmt.Errorf("%s is held by the administrator's own IgnorePkg line in %s, "+
						"which the panel does not rewrite", name, PacmanConfPath)
				}
			}
		}
	}
	held := make([]string, 0, len(set))
	for name := range set {
		held = append(held, name)
	}
	sort.Strings(held)

	lines := strings.Split(content, "\n")
	// The old line goes first, wherever it was.
	kept := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == holdMarker {
			if i+1 < len(lines) {
				if key, _, ok := pacmanEntry(strings.TrimSpace(lines[i+1])); ok && key == "IgnorePkg" {
					i++
				}
			}
			continue
		}
		kept = append(kept, lines[i])
	}
	if len(held) == 0 {
		return strings.Join(kept, "\n"), nil
	}
	block := []string{holdMarker, "IgnorePkg = " + strings.Join(held, " ")}
	return strings.Join(insertIntoOptions(kept, block), "\n"), nil
}

// insertIntoOptions puts the lines at the end of the options section, or
// creates the section when the file has none.
func insertIntoOptions(lines, block []string) []string {
	start := -1
	for i, line := range lines {
		if header, ok := pacmanSectionHeader(strings.TrimSpace(line)); ok && header == "options" {
			start = i
			break
		}
	}
	if start < 0 {
		return append(append([]string{"[options]"}, block...), lines...)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if _, ok := pacmanSectionHeader(strings.TrimSpace(lines[i])); ok {
			end = i
			break
		}
	}
	// The blank lines before the next section stay after our block.
	insertAt := end
	for insertAt > start+1 && strings.TrimSpace(lines[insertAt-1]) == "" {
		insertAt--
	}
	result := make([]string, 0, len(lines)+len(block))
	result = append(result, lines[:insertAt]...)
	result = append(result, block...)
	result = append(result, lines[insertAt:]...)
	return result
}

// pacmanSectionHeader recognises "[name]".
func pacmanSectionHeader(trimmed string) (string, bool) {
	if len(trimmed) < 3 || trimmed[0] != '[' || trimmed[len(trimmed)-1] != ']' {
		return "", false
	}
	return strings.TrimSpace(trimmed[1 : len(trimmed)-1]), true
}

// pacmanEntry splits "Key = value". A comment is not an entry.
func pacmanEntry(trimmed string) (key, value string, ok bool) {
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	key, value, found := strings.Cut(trimmed, "=")
	if !found {
		// A bare option such as "Color" or "VerbosePkgLists".
		return strings.TrimSpace(trimmed), "", true
	}
	return strings.TrimSpace(key), strings.TrimSpace(value), true
}

// replaceFile writes the content next to the file and moves it into place,
// keeping the permissions. A half-written pacman.conf would leave the host
// without a working package manager.
func replaceFile(path string, content []byte) error {
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	temp := path + ".flotestro-tmp"
	if err := os.WriteFile(temp, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(temp, mode); err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

// Repair unblocks package operations on the host.
//
// "pacman -Sy" is not a repair. The repair on Arch removes the lock a crashed
// pacman left behind - only when no pacman runs - and checks the local
// database. It reports what it changed: the operator is to know the host was
// touched in a way they did not order.
func (p *Pacman) Repair(ctx context.Context) ([]string, []Blocked, error) {
	var steps []string
	removed, running, err := removeStaleLock(pacmanLockPath, pacmanProcRoot)
	switch {
	case err != nil:
		return steps, nil, fmt.Errorf("the database lock: %w", err)
	case running != "":
		return steps, nil, fmt.Errorf("%w: %s is running (%s)", ErrLocked, PacmanName, running)
	case removed:
		steps = append(steps, "the stale lock "+pacmanLockPath+" was removed; no pacman process was running")
	}

	// The check changes nothing, so it is not a step: a host that needed no
	// repair is to read as one, not as a host that was unblocked.
	result := run(ctx, 5*time.Minute, pacmanPath, "-Dk")
	if !result.Ran {
		return steps, nil, fmt.Errorf("pacman -Dk: %s", result.Reason())
	}
	if result.ExitCode != 0 {
		remaining := ParsePacmanDatabaseCheck(result.Stderr + "\n" + result.Stdout)
		return steps, remaining, fmt.Errorf("%w: pacman -Dk: %s", ErrDatabaseBroken, result.Reason())
	}
	return steps, nil, nil
}

// removeStaleLock removes the lock file when no pacman process runs. It
// returns whether it removed anything and the description of a running
// pacman, if there is one.
func removeStaleLock(lockPath, procRoot string) (bool, string, error) {
	if !fileExists(lockPath) {
		return false, "", nil
	}
	if pid := pacmanProcess(procRoot); pid != "" {
		return false, "pid " + pid, nil
	}
	if err := os.Remove(lockPath); err != nil && !os.IsNotExist(err) {
		return false, "", err
	}
	return true, "", nil
}

// pacmanProcess returns the pid of a running pacman, or nothing. The name of
// the command is read from /proc: starting a process to look for a process
// would be one more thing that can hang on a busy host.
func pacmanProcess(procRoot string) string {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() || !onlyDigits(entry.Name()) {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == PacmanName {
			return entry.Name()
		}
	}
	return ""
}

// databaseCheckLine reads "error: missing 'dep' dependency for 'pkg'" and the
// other complaints of "pacman -Dk".
var databaseCheckLine = regexp.MustCompile(`for '([^']+)'`)

// ParsePacmanDatabaseCheck turns the complaints of the database check into
// the packages that need attention.
func ParsePacmanDatabaseCheck(output string) []Blocked {
	var blocked []Blocked
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(trimmed), "error:") {
			continue
		}
		status := strings.TrimSpace(strings.TrimPrefix(trimmed, "error:"))
		name := "database"
		if match := databaseCheckLine.FindStringSubmatch(trimmed); match != nil {
			name = match[1]
		}
		if seen[name+"\x1f"+status] {
			continue
		}
		seen[name+"\x1f"+status] = true
		blocked = append(blocked, Blocked{Name: name, Status: status})
	}
	return blocked
}

// The keys of the sources. pacman-key is the keyring of the host: a key
// added and locally signed there is what makes a signed source usable, and a
// key nobody signed makes every package of the source "unknown trust".

// ImportPacmanKey adds the key from the file to the keyring and signs it
// locally. It requires root.
func ImportPacmanKey(ctx context.Context, keyPath, fingerprint string) error {
	if fingerprint == "" {
		return fmt.Errorf("a key without a fingerprint cannot be signed")
	}
	if result := run(ctx, 2*time.Minute, pacmanKeyPath, "--add", keyPath); !result.Ran ||
		result.ExitCode != 0 {
		return fmt.Errorf("pacman-key --add: %s", result.Reason())
	}
	if result := run(ctx, 2*time.Minute, pacmanKeyPath, "--lsign-key", fingerprint); !result.Ran ||
		result.ExitCode != 0 {
		return fmt.Errorf("pacman-key --lsign-key: %s", result.Reason())
	}
	return nil
}

// ForgetPacmanKey removes the key from the keyring. A key that is not there
// is not an error: the source is being removed, and the goal is a keyring
// without it.
func ForgetPacmanKey(ctx context.Context, fingerprint string) error {
	if fingerprint == "" {
		return nil
	}
	result := run(ctx, 2*time.Minute, pacmanKeyPath, "--delete", fingerprint)
	if !result.Ran {
		return fmt.Errorf("pacman-key --delete: %s", result.Reason())
	}
	if result.ExitCode != 0 && !strings.Contains(strings.ToLower(result.Stderr), "not found") {
		return fmt.Errorf("pacman-key --delete: %s", result.Reason())
	}
	return nil
}

// The installed list of pacman. "pacman -Q" gives the name and the version
// of every package, "-Qm" the ones no sync database knows - built from the
// AUR or by hand - and "-Sl" which repository carries each native one. That
// is three processes for the whole list and everything the correlator can
// use: Arch has no source packages the way Debian has, and the architecture
// is one for the whole host.

// archOfficialRepositories are the repositories of the distribution itself.
// A package from any other sync repository is a third-party package.
var archOfficialRepositories = map[string]bool{
	"core": true, "extra": true, "multilib": true,
	"core-testing": true, "extra-testing": true, "multilib-testing": true,
	"testing": true, "community": true, "community-testing": true,
	"kde-unstable": true, "gnome-unstable": true,
}

// OriginForeign marks a package no sync database knows.
const OriginForeign = "foreign"

// installedPacman reads the local database.
func installedPacman(ctx context.Context) ([]InstalledPackage, string) {
	result := run(ctx, 2*time.Minute, pacmanPath, "-Q")
	if !result.Ran || result.ExitCode != 0 {
		return nil, "pacman -Q: " + result.Reason()
	}
	pkgs := ParsePacmanQuery(result.Stdout)
	if len(pkgs) == 0 {
		return nil, "pacman -Q returned an empty list"
	}

	// -Qm ends with the code 1 and no output when nothing is foreign; that is
	// an answer rather than an error.
	foreign := map[string]bool{}
	foreignResult := run(ctx, 2*time.Minute, pacmanPath, "-Qm")
	foreignKnown := foreignResult.Ran && (foreignResult.ExitCode == 0 ||
		(foreignResult.ExitCode == 1 && strings.TrimSpace(foreignResult.Stderr) == ""))
	if foreignKnown {
		for _, pkg := range ParsePacmanQuery(foreignResult.Stdout) {
			foreign[pkg.Name] = true
		}
	}

	// -Sl reads the sync databases the host has; without them nothing is
	// known about the repositories, and the origin stays unknown.
	repositories := map[string]string{}
	syncResult := run(ctx, 2*time.Minute, pacmanPath, "-Sl")
	if syncResult.Ran && syncResult.ExitCode == 0 {
		repositories = ParsePacmanSyncList(syncResult.Stdout)
	}
	FillPacmanOrigin(pkgs, foreign, foreignKnown, repositories)
	return pkgs, ""
}

// ParsePacmanQuery reads lines of "name version" and splits the version into
// the epoch, the version and the release.
func ParsePacmanQuery(output string) []InstalledPackage {
	var pkgs []InstalledPackage
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		pkg := InstalledPackage{Name: fields[0]}
		pkg.Epoch, pkg.Version, pkg.Release = SplitPacmanVersion(fields[1])
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		// Arch builds one package from one recipe; a split package keeps
		// the name of its base only in the local database, which the list
		// does not read. The package itself is the closest source there is.
		pkg.SourceName = pkg.Name
		pkg.SourceVersion = fields[1]
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

// SplitPacmanVersion breaks "epoch:version-release" into its parts. The
// version may not contain a dash, so the release is what follows the last
// one.
func SplitPacmanVersion(full string) (epoch, version, release string) {
	rest := full
	if colon := strings.Index(rest, ":"); colon > 0 {
		epoch, rest = rest[:colon], rest[colon+1:]
	}
	if dash := strings.LastIndex(rest, "-"); dash > 0 {
		return epoch, rest[:dash], rest[dash+1:]
	}
	return epoch, rest, ""
}

// ParsePacmanSyncList reads "repository name version [installed]" lines and
// returns the first repository each name is seen in - the order of the
// repositories in pacman.conf is the order pacman chooses in.
func ParsePacmanSyncList(output string) map[string]string {
	repositories := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if _, seen := repositories[fields[1]]; !seen {
			repositories[fields[1]] = fields[0]
		}
	}
	return repositories
}

// FillPacmanOrigin classifies the packages by where they come from.
func FillPacmanOrigin(pkgs []InstalledPackage, foreign map[string]bool, foreignKnown bool,
	repositories map[string]string) {
	for i := range pkgs {
		switch repo, inSync := repositories[pkgs[i].Name]; {
		case foreignKnown && foreign[pkgs[i].Name]:
			pkgs[i].Origin = OriginForeign
			pkgs[i].OriginClass = OriginLocal
		case inSync && archOfficialRepositories[repo]:
			pkgs[i].Origin = repo
			pkgs[i].RepositoryID = repo
			pkgs[i].OriginClass = OriginDistribution
		case inSync:
			pkgs[i].Origin = repo
			pkgs[i].RepositoryID = repo
			pkgs[i].OriginClass = OriginThirdParty
		default:
			pkgs[i].OriginClass = OriginUnknown
		}
	}
}
