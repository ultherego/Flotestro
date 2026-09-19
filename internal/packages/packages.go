// Package packages is the adapter of package managers. Planning works without
// root; refreshing the metadata and a transaction require the helper.
package packages

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ultherego/flotestro/internal/helper/runscope"
	"github.com/ultherego/flotestro/internal/plan"
)

// The stable error codes of the adapter. They are part of the contract of
// the result of a job.
const (
	ErrorLocked = "package_manager_locked"
	// ErrorPlanMismatch is the code of a plan the host no longer computes: the
	// shared code of the plan envelope, so a package transaction and every other
	// planned change refuse a moved plan with one word.
	ErrorPlanMismatch   = plan.ErrorStalePlan
	ErrorTransaction    = "transaction_failed"
	ErrorUnsupported    = "unsupported_manager"
	ErrorDatabaseBroken = "package_database_broken"
	ErrorModulesHidden  = "kernel_modules_hidden"
	ErrorNoSpace        = "insufficient_space"
)

// ErrLocked means the lock of the package manager is held.
var ErrLocked = errors.New("the package manager is busy")

// ErrModulesHidden means the process of the transaction does not see the
// module tree of the running kernel.
var ErrModulesHidden = errors.New("the module tree of the kernel is not visible")

// ErrProtectedPackage means an attempt to remove a package without which the
// host stops being manageable or bootable.
var ErrProtectedPackage = errors.New("a protected package")

// ErrPlanChanged means the set of packages to remove has changed since the
// plan was approved.
var ErrPlanChanged = errors.New("the removal plan has changed since it was approved")

// ErrorCodeOf maps the errors of the adapters to their stable codes.
func ErrorCodeOf(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrLocked):
		return ErrorLocked, true
	case errors.Is(err, ErrModulesHidden):
		return ErrorModulesHidden, true
	case errors.Is(err, ErrDatabaseBroken):
		return ErrorDatabaseBroken, true
	case errors.Is(err, ErrPlanMetadataMissing):
		return ErrorPlanMetadataMissing, true
	case errors.Is(err, ErrVersionlockMissing):
		return ErrorVersionlockMissing, true
	case errors.Is(err, ErrPartialUpgrade):
		return ErrorPartialUpgrade, true
	case errors.Is(err, ErrSecurityUnknown):
		return ErrorSecurityUnknown, true
	case errors.Is(err, ErrNoSpace):
		return ErrorNoSpace, true
	}
	// The refusals of the plan envelope - a stale plan, another planner,
	// an expired plan, a partial result - carry their own codes.
	if code, ok := plan.CodeOf(err); ok {
		return code, true
	}
	return "", false
}

// Refused says whether the error is a refusal of the host rather than a
// failure of a transaction: the operation asked for something this host cannot
// do or its distribution does not allow, and nothing was attempted.
func Refused(err error) bool {
	return errors.Is(err, ErrLocked) || errors.Is(err, ErrPlanMetadataMissing) ||
		errors.Is(err, ErrVersionlockMissing) ||
		errors.Is(err, ErrPartialUpgrade) || errors.Is(err, ErrSecurityUnknown) ||
		errors.Is(err, ErrNoSpace) || errors.Is(err, plan.ErrStalePlan) ||
		errors.Is(err, plan.ErrReplanRequired) || errors.Is(err, plan.ErrPlanExpired)
}

// compareSets returns a description of the difference, or nothing when the
// sets are equal.
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

// Change describes one element of a plan: what happens to one package. The
// name and the versions alone are not what the operator approves.
type Change struct {
	Name             string `json:"name"`
	CurrentVersion   string `json:"current_version,omitempty"`
	CandidateVersion string `json:"candidate_version,omitempty"`
	// Origin is the repository the candidate comes from, as the manager
	// names it: "Debian-Security:12/stable-security", "updates", "extra".
	Origin   string `json:"origin,omitempty"`
	Security bool   `json:"security"`
	// Architecture is the architecture of the candidate. Empty means the
	// manager did not say, never "any".
	Architecture string `json:"architecture,omitempty"`
	// Action is the direction: install, upgrade, downgrade or remove.
	Action string `json:"action,omitempty"`
	// Reason says why the element is in the plan: requested by the order, pulled
	// in as a dependency, or an orphan the manager drops along the way.
	Reason string `json:"reason,omitempty"`
	// Blocked marks a package that stops every transaction on the host;
	// Protected marks one the policy does not let go away.
	Blocked   bool `json:"blocked,omitempty"`
	Protected bool `json:"protected,omitempty"`
	// InstalledDeltaBytes is how the installed files of this package grow
	// or shrink; it is meaningful only when InstalledDeltaKnown says so.
	InstalledDeltaBytes int64 `json:"installed_delta_bytes,omitempty"`
	InstalledDeltaKnown bool  `json:"installed_delta_known,omitempty"`
	// Digest is the checksum of the archive as the index publishes it,
	// hexadecimal with the algorithm in front ("sha256:.
	Digest string `json:"digest,omitempty"`
}

// The reasons an element is in a plan.
const (
	ReasonRequested  = "requested"
	ReasonDependency = "dependency"
	ReasonOrphan     = "orphan"
)

// Plan describes what would be changed.
type Plan struct {
	Manager       string   `json:"manager"`
	Changes       []Change `json:"changes"`
	DownloadBytes uint64   `json:"download_bytes"`
	// DiskAvailableBytes is the free space of "/". It stays for the callers
	// that read one number; the per-file-system facts are in Space.
	DiskAvailableBytes uint64 `json:"disk_available_bytes"`
	// Space says, file system by file system, what the change needs and what is
	// there: the cache the archives land in, /usr where the files go, /boot when
	// a kernel is among the changes.
	Space             []SpaceFact `json:"space,omitempty"`
	MetadataRefreshed bool        `json:"metadata_refreshed"`
	RebootPredicted   bool        `json:"reboot_predicted"`
	// Blocked describes the packages that make carrying the plan out impossible.
	Blocked []Blocked `json:"blocked,omitempty"`
	// Mode says what kind of plan this is.
	Mode string `json:"mode,omitempty"`
	// Removals lists the packages that would disappear along with the named ones.
	Removals []string `json:"removals,omitempty"`
	// Protected lists the protected packages that ended up in the plan. Their
	// presence means the operation will not be carried out.
	Protected []string `json:"protected,omitempty"`

	// The header of the plan envelope (package plan): who made the plan, for
	// which host and picture of it, against which repository metadata, and until
	// when it holds.
	SchemaVersion     uint32    `json:"schema_version,omitempty"`
	PlannerVersion    string    `json:"planner_version,omitempty"`
	HostID            string    `json:"host_id,omitempty"`
	InventoryRevision string    `json:"inventory_revision,omitempty"`
	ResourceRevision  string    `json:"resource_revision,omitempty"`
	ExpiresAt         time.Time `json:"expires_at"`
	// Rollback says how the change could be taken back, or why it cannot.
	Rollback Rollback `json:"rollback"`
}

// Rollback is the plan's answer about undoing the change: the mechanism
// with its identifier, or unavailable with the reason.
type Rollback struct {
	Mechanism string `json:"mechanism"`
	ID        string `json:"id,omitempty"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// Apply describes the result of a transaction that was carried out.
type Apply struct {
	Manager                string   `json:"manager"`
	Applied                []Change `json:"applied"`
	RebootRequired         bool     `json:"reboot_required"`
	ServicesNeedingRestart []string `json:"services_needing_restart,omitempty"`
	DatabaseBroken         bool     `json:"package_database_broken"`
	// EffectsAchieved and EffectsMissed settle the expected effects of the
	// approved plan against the state read after the transaction.
	EffectsAchieved []plan.Outcome `json:"effects_achieved,omitempty"`
	EffectsMissed   []plan.Outcome `json:"effects_missed,omitempty"`
	// PackagesNeedingAttention names the packages that block the transaction.
	PackagesNeedingAttention []string `json:"packages_needing_attention,omitempty"`
	// SelfRepair describes what the adapter repaired on its own before the retry.
	SelfRepair []string `json:"self_repair,omitempty"`
	// ScriptletErrors names the packages whose maintainer scriptlet failed in a
	// transaction the manager still finished.
	ScriptletErrors []string `json:"scriptlet_errors,omitempty"`
	// Output is the tail of the output of the tool on a failure.
	Output []string `json:"output,omitempty"`
}

// tailLines returns the last useful lines of the output of the tool. The
// cause is usually near the end, so it is the beginning that can be given up.
func tailLines(stderr, stdout string, count int) []string {
	lines := lastUsefulLines(stderr, count)
	if len(lines) == 0 {
		lines = lastUsefulLines(stdout, count)
	}
	return lines
}

// maxResultLines limits the context of an error in the result of an
// operation.
const maxResultLines = 40

// The modes of planning.
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
	// AllowDowngrade agrees to a version older than the installed one.
	AllowDowngrade bool
	// Header is the part of the plan envelope the planner does not compute from
	// the host: the host identity, the inventory picture and the expiry.
	Header PlanHeader
}

// PlanHeader is the identity of a plan: for which host, against which
// inventory picture, and until when.
type PlanHeader struct {
	HostID            string
	InventoryRevision string
	ExpiresAt         time.Time
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

// Lifecycle describes an adapter that can do the whole life cycle of packages
// rather than upgrading alone.
type Lifecycle interface {
	Install(ctx context.Context, options Options) (Apply, error)
	Remove(ctx context.Context, options Options, expected []string) (Apply, error)
	SetHold(ctx context.Context, pkgs []string, hold bool) (Apply, error)
	// Holds returns the packages held on the host and, when the list could not be
	// read, the reason.
	Holds(ctx context.Context) ([]string, string)
}

// Detect returns the adapter proper for the host.
func Detect() (Manager, error) {
	for _, manager := range []Manager{&APT{}, &DNF{}, &Pacman{}} {
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
	// Truncated says the tool wrote more than the bound and the text above is
	// not all of it. A caller that reads a listing out of it has to refuse.
	Truncated bool
}

// Reason describes the cause of a failure in a form readable in the result
// of a job.
func (r commandResult) Reason() string {
	if r.Err != nil && !r.Ran {
		return r.Err.Error()
	}
	reason := fmt.Sprintf("code %d", r.ExitCode)
	if description := errorDescription(r.Stderr, r.Stdout); description != "" {
		reason += ": " + description
	}
	if r.Truncated {
		reason += " (" + truncatedNote + ")"
	}
	return reason
}

// Complete says the tool ran, succeeded and wrote all of what it had to say.
// Anything parsed out of a cut listing would be a shorter answer, and a
// shorter answer is not a smaller truth.
func (r commandResult) Complete() bool {
	return r.Ran && r.ExitCode == 0 && !r.Truncated
}

// ErrorOutputTooLarge is the stable code a listing carries when the tool wrote
// more than the agent reads in one go.
const ErrorOutputTooLarge = "tool_output_too_large"

// unreadable is the reason a listing that could not be read whole records. The
// cut case gets its own code, because it is not the tool failing.
func (r commandResult) unreadable(tool string) string {
	if r.Truncated {
		return ErrorOutputTooLarge + ": " + tool + ": " + r.Reason()
	}
	return tool + ": " + r.Reason()
}

// truncatedNote is the one sentence a cut output carries into a reason.
const truncatedNote = "the tool wrote more than the agent reads and the rest was not read"

// The bounds on what one run of a package tool may cost this process. A
// listing of every package of a distribution is well under a megabyte; past
// these a tool is running away and the agent must not grow with it.
const (
	maxCommandOutput = 8 << 20
	maxCommandError  = 256 << 10
	// maxLineBytes bounds one line of a streamed output.
	maxLineBytes = 1 << 20
)

// ErrOutputTooLong means a single line of a tool's output passed the bound, so
// the stream could not be read to its end.
var ErrOutputTooLong = errors.New("the tool wrote a line longer than the agent reads")

// boundedWriter gathers a tool's output up to a limit and remembers that it
// stopped. It builds a string, so handing the text on costs no second copy.
type boundedWriter struct {
	text  strings.Builder
	limit int
	over  bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	switch room := w.limit - w.text.Len(); {
	case room <= 0:
		w.over = w.over || len(p) > 0
	case len(p) > room:
		w.text.Write(p[:room])
		w.over = true
	default:
		w.text.Write(p)
	}
	// The tool is always told its bytes were taken: closing the pipe under a
	// transaction already under way would break it over a counter.
	return len(p), nil
}

func (w *boundedWriter) String() string { return w.text.String() }

// runtimeDir is a directory writable by the user of the process.
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
// sh -c, so the name of a package cannot become a command.
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

	// The tool was checked above; what runs is the tool behind the resource
	// scope the context asks for, when the helper put one there.
	argv := runscope.Apply(ctx, append([]string{path}, args...))

	stdout := &boundedWriter{limit: maxCommandOutput}
	stderr := &boundedWriter{limit: maxCommandError}
	cmd := exec.CommandContext(cmdCtx, argv[0], argv[1:]...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	cmd.Env = environment()

	runErr := cmd.Run()
	result := commandResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1,
		Err: runErr, Truncated: stdout.over || stderr.over}

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

// runLines starts a tool and hands the caller its output line by line. The
// whole output never exists at once, which is what a listing of every package
// of a distribution costs when it does.
func runLines(ctx context.Context, timeout time.Duration, onLine func(string),
	path string, args ...string) commandResult {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return commandResult{ExitCode: -1, Err: fmt.Errorf("%s: the tool is missing", path)}
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	argv := runscope.Apply(ctx, append([]string{path}, args...))
	cmd := exec.CommandContext(cmdCtx, argv[0], argv[1:]...)
	cmd.Env = environment()
	stderr := &boundedWriter{limit: maxCommandError}
	cmd.Stderr = stderr

	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return commandResult{ExitCode: -1, Err: err}
	}
	if err := cmd.Start(); err != nil {
		return commandResult{ExitCode: -1, Err: err}
	}

	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for scanner.Scan() {
		onLine(scanner.Text())
	}
	scanErr := scanner.Err()
	if scanErr != nil {
		// The rest is drained so the tool is never left blocked on a full pipe,
		// but nothing more of it is read.
		_, _ = io.Copy(io.Discard, pipe)
	}
	runErr := cmd.Wait()

	result := commandResult{Stderr: stderr.String(), ExitCode: -1, Err: runErr,
		Truncated: stderr.over}
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
	if scanErr != nil {
		// A line nobody could read means the listing has a hole in it; that is
		// not a shorter listing, it is one nothing may be concluded from.
		result.Ran, result.Truncated = false, true
		if errors.Is(scanErr, bufio.ErrTooLong) {
			scanErr = ErrOutputTooLong
		}
		result.Err = fmt.Errorf("%s: %w", filepath.Base(path), scanErr)
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
		// needrestart on Debian and Ubuntu restarts the services whose libraries
		// have changed on its own.
		"NEEDRESTART_MODE=l",
		"NEEDRESTART_SUSPEND=flotestro",
		// Dnf cuts its own messages to the width of the terminal, and without a
		// terminal it assumes eighty columns - the cause of an error was then lost
		// in the middle of a sentence ("scriptlet failed, exit stat").
		"COLUMNS=200",
		"HOME=" + runtimeDir,
		// checkupdates syncs a copy of the pacman database in a directory of its
		// own.
		"CHECKUPDATES_DB=" + checkupdatesDB(),
		"XDG_STATE_HOME=" + filepath.Join(runtimeDir, "state"),
		"XDG_CACHE_HOME=" + filepath.Join(runtimeDir, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(runtimeDir, "config"),
	}
}

// lockHeld checks the lock of a file without starting a process.
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
// visible to the process of the transaction.
func modulesHidden() (bool, string) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false, ""
	}
	release := strings.TrimRight(string(uts.Release[:]), "\x00")
	return modulesHiddenAt("/proc/modules", "/lib/modules", release)
}

// modulesHiddenAt is the check separated from the system paths.
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

// Hash computes the digest of a plan: the digest of its envelope, over every
// artifact with its version, architecture and origin, every step, every
// expected effect and the header.
func (p Plan) Hash() []byte {
	return p.Envelope().Hash()
}
