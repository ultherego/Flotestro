// Package packages is the adapter of package managers. Planning works without
// root; refreshing the metadata and a transaction require the helper.
package packages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The stable error codes of the adapter. They are part of the contract of
// the result of a job.
const (
	ErrorLocked         = "package_manager_locked"
	ErrorPlanMismatch   = "plan_changed"
	ErrorTransaction    = "transaction_failed"
	ErrorUnsupported    = "unsupported_manager"
	ErrorDatabaseBroken = "package_database_broken"
	ErrorModulesHidden  = "kernel_modules_hidden"
)

// ErrLocked means the lock of the package manager is held. We do not work
// around the lock: a second transaction on the same package database can
// damage it.
var ErrLocked = errors.New("the package manager is busy")

// ErrModulesHidden means the process of the transaction does not see the
// module tree of the running kernel. A transaction in such an environment is
// dangerous: the scripts of the packages rebuild the initramfs without the
// drivers and the host does not come up after a restart.
var ErrModulesHidden = errors.New("the module tree of the kernel is not visible")

// ErrProtectedPackage means an attempt to remove a package without which the
// host stops being manageable or bootable.
var ErrProtectedPackage = errors.New("a protected package")

// ErrPlanChanged means the set of packages to remove has changed since the
// plan was approved.
var ErrPlanChanged = errors.New("the removal plan has changed since it was approved")

// compareSets returns a description of the difference, or nothing when the
// sets are equal. An empty expected set means there is no approved plan and is
// a difference as well: an irreversible operation must not go without a
// basis.
func compareSets(expected, current []string) string {
	if len(expected) == 0 {
		return "there is no approved removal plan"
	}
	set := map[string]bool{}
	for _, name := range expected {
		set[name] = true
	}
	var extra []string
	for _, name := range current {
		if !set[name] {
			extra = append(extra, name)
		}
		delete(set, name)
	}
	var missing []string
	for name := range set {
		missing = append(missing, name)
	}
	sort.Strings(extra)
	sort.Strings(missing)

	switch {
	case len(extra) > 0 && len(missing) > 0:
		return "added: " + strings.Join(extra, ", ") +
			"; dropped: " + strings.Join(missing, ", ")
	case len(extra) > 0:
		return "the removal would also cover: " + strings.Join(extra, ", ")
	case len(missing) > 0:
		return "no longer subject to removal: " + strings.Join(missing, ", ")
	}
	return ""
}

// Change describes one change of the version of a package.
type Change struct {
	Name             string `json:"name"`
	CurrentVersion   string `json:"current_version,omitempty"`
	CandidateVersion string `json:"candidate_version,omitempty"`
	Origin           string `json:"origin,omitempty"`
	Security         bool   `json:"security"`
}

// Plan describes what would be changed.
type Plan struct {
	Manager            string   `json:"manager"`
	Changes            []Change `json:"changes"`
	DownloadBytes      uint64   `json:"download_bytes"`
	DiskAvailableBytes uint64   `json:"disk_available_bytes"`
	MetadataRefreshed  bool     `json:"metadata_refreshed"`
	RebootPredicted    bool     `json:"reboot_predicted"`
	// Blocked describes the packages that make carrying the plan out
	// impossible. The plan itself goes through, because it changes nothing,
	// but a transaction on such a host will fail - the operator is to know
	// that before ordering it.
	Blocked []Blocked `json:"blocked,omitempty"`
	// Mode says what kind of plan this is.
	Mode string `json:"mode,omitempty"`
	// Removals lists the packages that would disappear along with the named
	// ones. Removing one package can pull dozens of dependent ones - the
	// operator is to see that before the approval rather than after.
	Removals []string `json:"removals,omitempty"`
	// Protected lists the protected packages that ended up in the plan. Their
	// presence means the operation will not be carried out.
	Protected []string `json:"protected,omitempty"`
}

// Apply describes the result of a transaction that was carried out.
type Apply struct {
	Manager                string   `json:"manager"`
	Applied                []Change `json:"applied"`
	RebootRequired         bool     `json:"reboot_required"`
	ServicesNeedingRestart []string `json:"services_needing_restart,omitempty"`
	DatabaseBroken         bool     `json:"package_database_broken"`
	// PackagesNeedingAttention names the packages that block the transaction.
	// Without them the message about repairing the database does not say what
	// to repair.
	PackagesNeedingAttention []string `json:"packages_needing_attention,omitempty"`
	// SelfRepair describes what the adapter repaired on its own before the
	// retry. A silent repair would be worse than none: the operator has to
	// know the host was touched in a way they did not order.
	SelfRepair []string `json:"self_repair,omitempty"`
	// Output is the tail of the output of the tool on a failure. One sentence
	// describing the error is enough to know something failed; to know why one
	// sometimes has to see the context - and logging into the host after every
	// failed transaction is exactly what the panel is to spare.
	Output []string `json:"output,omitempty"`
}

// tailLines returns the last useful lines of the output of the tool. The
// cause is usually near the end, so it is the beginning that can be given up.
func tailLines(stderr, stdout string, count int) []string {
	lines := usefulLines(stderr)
	if len(lines) == 0 {
		lines = usefulLines(stdout)
	}
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	return lines
}

// maxResultLines limits the context of an error in the result of an
// operation.
const maxResultLines = 40

// The modes of planning. An upgrade plan and a removal plan compute different
// things but answer the same question: what will this operation change on the
// host.
const (
	ModeUpgrade = "upgrade"
	ModeRemove  = "remove"
	ModeInstall = "install"
)

// Options narrow the scope of a plan or a transaction.
type Options struct {
	Packages     []string
	SecurityOnly bool
	// Mode chooses the kind of plan. Empty means an upgrade plan.
	Mode string
	// Progress receives the progress of a long transaction. Nil means there is
	// no receiver and the tool then works as before.
	Progress ProgressFunc
	// AllowDowngrade agrees to a version older than the installed one. It is
	// off by default: package managers refuse it for a good reason, because
	// going back a version is sometimes irreversible for the data format.
	AllowDowngrade bool
}

// Manager is the adapter of a specific package manager.
type Manager interface {
	// Name returns the name of the manager, e.g. apt or dnf.
	Name() string
	// Available says whether the manager is present on the host.
	Available() bool
	// LockHeld checks whether another package operation is running. It
	// requires root.
	LockHeld() (bool, string)
	// Plan computes the changes without modifying the system.
	Plan(ctx context.Context, options Options) (Plan, error)
	// Refresh refreshes the metadata of the repository. It requires root.
	Refresh(ctx context.Context) error
	// Upgrade carries the transaction out. It requires root.
	Upgrade(ctx context.Context, options Options) (Apply, error)
	// DatabaseBroken checks whether the package database needs repairing.
	DatabaseBroken(ctx context.Context) bool
}

// Lifecycle describes an adapter that can do the whole life cycle of
// packages rather than upgrading alone. An interface rather than a concrete
// type: the helper is to ask "can this manager do it" rather than "is this
// apt".
type Lifecycle interface {
	Install(ctx context.Context, options Options) (Apply, error)
	Remove(ctx context.Context, options Options, expected []string) (Apply, error)
	SetHold(ctx context.Context, pkgs []string, hold bool) (Apply, error)
	Holds(ctx context.Context) []string
}

// Detect returns the adapter proper for the host.
func Detect() (Manager, error) {
	for _, manager := range []Manager{&APT{}, &DNF{}} {
		if manager.Available() {
			return manager, nil
		}
	}
	return nil, fmt.Errorf("%s: the package manager was not recognised", ErrorUnsupported)
}

// commandResult separates the fact that a process ran from its result.
type commandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Ran      bool
	Err      error
}

// Reason describes the cause of a failure in a form readable in the result
// of a job.
func (r commandResult) Reason() string {
	if r.Err != nil && !r.Ran {
		return r.Err.Error()
	}
	if description := errorDescription(r.Stderr, r.Stdout); description != "" {
		return fmt.Sprintf("code %d: %s", r.ExitCode, description)
	}
	return fmt.Sprintf("code %d", r.ExitCode)
}

// runtimeDir is a directory writable by the user of the process. The package
// tools create files in HOME and in the XDG directories; the agent has no home
// directory, so without this dnf ends with a permission error that is easy to
// mistake for a lack of updates.
var runtimeDir = os.TempDir()

// SetRuntimeDir names the working directory for the tools that are run.
// The agent gives its state directory, the helper the directory of root.
func SetRuntimeDir(dir string) error {
	if dir == "" {
		return nil
	}
	for _, sub := range []string{"", "state", "cache", "config"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return err
		}
	}
	runtimeDir = dir
	return nil
}

// run starts a tool with a fixed path and an array of arguments. We never use
// sh -c, so the name of a package cannot become a command. LC_ALL=C stabilises
// the output we have to parse.
// ErrInvalidAnswer rejects an answer with a newline character: every line of
// the input of debconf is a separate setting, so such a value would allow
// adding settings nobody asked for.
var ErrInvalidAnswer = errors.New("the answer contains a newline character")

func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

// runWithInput starts a command, handing it content on the standard input.
func runWithInput(ctx context.Context, timeout time.Duration, input string,
	path string, args ...string) commandResult {
	return runCommand(ctx, timeout, input, path, args...)
}

func run(ctx context.Context, timeout time.Duration, path string, args ...string) commandResult {
	return runCommand(ctx, timeout, "", path, args...)
}

func runCommand(ctx context.Context, timeout time.Duration, input string,
	path string, args ...string) commandResult {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return commandResult{ExitCode: -1, Err: fmt.Errorf("%s: the tool is missing", path)}
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(cmdCtx, path, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	cmd.Env = environment()

	runErr := cmd.Run()
	result := commandResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1, Err: runErr}

	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		result.Ran, result.ExitCode = true, 0
	case errors.As(runErr, &exitErr):
		result.Ran, result.ExitCode = true, exitErr.ExitCode()
	}
	if cmdCtx.Err() != nil {
		result.Ran = false
	}
	return result
}

// environment is the same for every call of the package tools.
func environment() []string {
	return []string{
		"LC_ALL=C",
		"LANG=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		// The non-interactive mode is forced: a prompt in a transaction would
		// mean a hung job rather than a success.
		"DEBIAN_FRONTEND=noninteractive",
		// needrestart on Debian and Ubuntu restarts the services whose
		// libraries have changed on its own. In a transaction run by the
		// helper that hits the helper itself: it disappears halfway through
		// its own work and the job ends with "the answer of the helper: EOF".
		// A restart is a decision of the panel - the restart policy of a
		// campaign or a separate operation - so the tool is only to note it.
		"NEEDRESTART_MODE=l",
		"NEEDRESTART_SUSPEND=flotestro",
		// Dnf cuts its own messages to the width of the terminal, and without
		// a terminal it assumes eighty columns - the cause of an error was
		// then lost in the middle of a sentence ("scriptlet failed, exit
		// stat").
		"COLUMNS=200",
		"HOME=" + runtimeDir,
		"XDG_STATE_HOME=" + filepath.Join(runtimeDir, "state"),
		"XDG_CACHE_HOME=" + filepath.Join(runtimeDir, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(runtimeDir, "config"),
	}
}

// lockHeld checks the lock of a file without starting a process. It returns
// false when the file cannot be opened: no access is not proof that there is
// no lock, but it must not block the operation for good either.
func lockHeld(path string) (bool, bool) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false, false
	}
	defer file.Close()

	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err != nil {
		// EWOULDBLOCK means somebody else holds the lock.
		return true, true
	}
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	return false, true
}

// modulesHidden checks whether the module tree of the running kernel is
// visible to the process of the transaction. A namespace with
// ProtectKernelModules=yes puts an empty directory in its place;
// update-initramfs then builds an image without the disk driver and the host
// stops booting.
func modulesHidden() (bool, string) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false, ""
	}
	release := strings.TrimRight(string(uts.Release[:]), "\x00")
	return modulesHiddenAt("/proc/modules", "/lib/modules", release)
}

// modulesHiddenAt is the check separated from the system paths. A monolithic
// kernel - without a single loaded module - is not a suspicious case and does
// not block a transaction. A directory that cannot be read is not treated as
// hidden either: ignorance must not stop the upgrade of a whole fleet.
func modulesHiddenAt(procModules, modulesRoot, release string) (bool, string) {
	if release == "" || !kernelIsModular(procModules) {
		return false, ""
	}
	dir := filepath.Join(modulesRoot, release)
	entries, err := os.ReadDir(dir)
	switch {
	case os.IsNotExist(err):
		return true, dir
	case err != nil:
		return false, ""
	case len(entries) == 0:
		return true, dir
	}
	return false, ""
}

// kernelIsModular says whether the kernel uses modules at all.
func kernelIsModular(procModules string) bool {
	data, err := os.ReadFile(procModules)
	if err != nil {
		return false
	}
	return len(bytes.TrimSpace(data)) > 0
}

// diskAvailable returns the free space in the given file system.
func diskAvailable(path string) uint64 {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0
	}
	return stat.Bavail * uint64(stat.Bsize)
}

func firstLine(text string) string {
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return strings.TrimSpace(text[:index])
	}
	return strings.TrimSpace(text)
}

// matchesFilter says whether a package fits in the narrowing of an operation.
func matchesFilter(change Change, options Options) bool {
	if options.SecurityOnly && !change.Security {
		return false
	}
	if len(options.Packages) == 0 {
		return true
	}
	for _, name := range options.Packages {
		if name == change.Name {
			return true
		}
	}
	return false
}

// Hash computes the digest of the content of a plan. The execution compares
// it with its own plan, so a change of the repository metadata between the
// plan and the transaction is detectable. The order of the changes must not
// influence the result.
func (p Plan) Hash() []byte {
	names := make([]string, 0, len(p.Changes))
	index := map[string]Change{}
	for _, change := range p.Changes {
		names = append(names, change.Name)
		index[change.Name] = change
	}
	sort.Strings(names)

	hasher := sha256.New()
	fmt.Fprintf(hasher, "%s\n", p.Manager)
	for _, name := range names {
		change := index[name]
		fmt.Fprintf(hasher, "%s\t%s\t%s\n", change.Name, change.CurrentVersion, change.CandidateVersion)
	}
	return hasher.Sum(nil)
}
