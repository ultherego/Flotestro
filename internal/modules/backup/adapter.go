// Package backup drives the backup tools already present on the host.
//
// Backup data does not flow through Flotestro and never will: the host
// talks to the repository directly, and the panel sees only metadata - when
// the backup succeeded, how much it takes and what it covers. A panel the
// copies of a hundred hosts flowed through would be a bottleneck and the
// most interesting target in the whole installation.
//
// Repository credentials do not go in command arguments. A process command
// line is readable by every user of the host through /proc, so a password
// given as an argument would be a password given publicly. They go through
// the environment, which only the process owner reads.
package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Tools supported by the module.
const (
	ToolRestic  = "restic"
	ToolBorg    = "borg"
	ToolRunbook = "runbook"
)

// Operation kinds. A runbook receives them as the first argument, so they
// are part of the contract visible outside this package.
const (
	OperationPlan    = "plan"
	OperationBackup  = "run"
	OperationVerify  = "verify"
	OperationRestore = "restore"
)

// Overwrite plan on restore.
//
// A restore without an overwrite plan is an operation whose effect nobody
// knows: the files may land next to the existing ones, on them or not at
// all. That is why the panel requires a decision, and the host checks it
// before unpacking anything.
const (
	// OverwriteEmpty requires the target directory to be empty.
	OverwriteEmpty = "empty-target"
	// OverwriteAllowed allows overwriting what is already in the directory.
	OverwriteAllowed = "overwrite"
)

// RunbookDir holds the scripts the panel may run.
//
// The panel does not send the script content and cannot create it: it only
// names a file the host administrator placed there earlier. Otherwise a
// "runbook" would be remote execution of arbitrary code under a different
// name.
const RunbookDir = "/etc/flotestro/backup-runbooks"

// Size limits. The output of a backup tool can be long, and the panel
// stores it in the task result.
const (
	MaxOutput = 256 << 10
	MaxPaths  = 64
)

var (
	definitionName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	runbookName    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	variableName   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
)

// Definition describes what to back up and where to.
//
// There are no credentials here: they are separate, because they have a
// different life - they come from the store right before the operation and
// stay nowhere but in the process memory.
type Definition struct {
	ID   string `json:"id"`
	Tool string `json:"tool"`
	// Repository is the reference to the backup target. The panel shows it,
	// but stores neither its content nor mediates through it.
	Repository string   `json:"repository"`
	Paths      []string `json:"paths,omitempty"`
	Excludes   []string `json:"excludes,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	// Retention describes how many copies stay. Zero means "do not clean
	// up": deleting old copies is a decision separate from making a new
	// one.
	KeepLast    int  `json:"keep_last,omitempty"`
	KeepDaily   int  `json:"keep_daily,omitempty"`
	KeepWeekly  int  `json:"keep_weekly,omitempty"`
	KeepMonthly int  `json:"keep_monthly,omitempty"`
	Prune       bool `json:"prune,omitempty"`
	// Runbook names the script in the runbook directory.
	Runbook string `json:"runbook,omitempty"`
	// Initialize allows creating the repository at the first copy. Without
	// this consent the host creates nothing: a repository created by a typo
	// in the address looks like a working backup and is an empty directory
	// next to the right one.
	Initialize bool `json:"initialize,omitempty"`
}

// Restore describes an ordered data restore.
type Restore struct {
	SnapshotID string   `json:"snapshot_id"`
	Target     string   `json:"target"`
	Include    []string `json:"include,omitempty"`
	Overwrite  string   `json:"overwrite"`
}

// Order is what the adapter receives to execute.
type Order struct {
	Definition
	Restore Restore
	// Password and Environment carry values from the store. They live in
	// the process memory for the duration of the operation and do not go
	// into the arguments, the result or the log.
	Password    []byte
	Environment map[string][]byte
	// Verify may read data, not only the repository structure. That is a
	// different cost and a different time, so it is an explicit choice.
	ReadData bool
}

// Snapshot is one copy in the repository.
type Snapshot struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname,omitempty"`
	Paths    []string  `json:"paths,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
	// SizeBytes may be unknown: not every tool computes the copy size when
	// merely listing snapshots. A nil pointer means no knowledge.
	SizeBytes *uint64 `json:"size_bytes,omitempty"`
}

// State describes the repository as seen from the host.
type State struct {
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version,omitempty"`
	Repository  string `json:"repository,omitempty"`
	// Snapshots is the list of copies, oldest first.
	Snapshots []Snapshot `json:"snapshots,omitempty"`
	// LastSuccessAt is the time of the last successful copy. Nil means a
	// repository without copies or an undetermined state - the reason tells
	// them apart.
	LastSuccessAt  *time.Time `json:"last_success_at,omitempty"`
	TotalSizeBytes *uint64    `json:"total_size_bytes,omitempty"`
	ObservedAt     time.Time  `json:"observed_at"`
	// UnavailableReason says why the state was not determined. An empty
	// repository and an unread repository are two different answers.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// Result describes the effect of an operation.
type Result struct {
	SnapshotID string `json:"snapshot_id,omitempty"`
	// The counters are pointers: a tool that does not report them leaves no
	// knowledge, not zero.
	BytesAdded          *uint64  `json:"bytes_added,omitempty"`
	TotalBytesProcessed *uint64  `json:"total_bytes_processed,omitempty"`
	FilesNew            *uint64  `json:"files_new,omitempty"`
	FilesChanged        *uint64  `json:"files_changed,omitempty"`
	FilesRestored       *uint64  `json:"files_restored,omitempty"`
	DurationSeconds     *float64 `json:"duration_seconds,omitempty"`
	// Removed counts the copies deleted by retention.
	Removed *int   `json:"snapshots_removed,omitempty"`
	Message string `json:"message,omitempty"`
	// Output is the tool output after masking the credentials.
	Output string `json:"output,omitempty"`
}

// Progress describes the progress of a long operation.
type Progress struct {
	Percent *uint32
	Message string
}

// ProgressFunc receives the operation progress.
type ProgressFunc func(Progress)

// Adapter is the driver of one backup tool.
//
// The module does not make backups itself and will not: the tools the host
// already has and the administrator already trusts do. The panel's job is
// to run them, read the result and show it next to a hundred other hosts.
type Adapter interface {
	Name() string
	Available() bool
	Version(ctx context.Context) string
	Plan(ctx context.Context, order Order) (State, error)
	Run(ctx context.Context, order Order, progress ProgressFunc) (Result, error)
	Verify(ctx context.Context, order Order) (Result, error)
	RestoreData(ctx context.Context, order Order) (Result, error)
}

// Select returns the adapter of the tool named in the definition.
func Select(tool string) (Adapter, error) {
	switch tool {
	case ToolRestic:
		return &Restic{}, nil
	case ToolBorg:
		return &Borg{}, nil
	case ToolRunbook:
		return &Runbook{}, nil
	}
	return nil, fmt.Errorf("unknown backup tool %q", tool)
}

// Validate checks the definition before executing anything.
func (d Definition) Validate() error {
	if !definitionName.MatchString(d.ID) {
		return fmt.Errorf("invalid definition identifier %q", d.ID)
	}
	switch d.Tool {
	case ToolRestic, ToolBorg:
		if strings.TrimSpace(d.Repository) == "" {
			return fmt.Errorf("the definition requires a repository address")
		}
	case ToolRunbook:
		if !runbookName.MatchString(d.Runbook) {
			return fmt.Errorf("invalid runbook name %q", d.Runbook)
		}
	default:
		return fmt.Errorf("unknown backup tool %q", d.Tool)
	}
	if strings.ContainsAny(d.Repository, "\n\r") || len(d.Repository) > 512 {
		return fmt.Errorf("the repository address contains a newline or is too long")
	}
	if len(d.Paths) > MaxPaths {
		return fmt.Errorf("the definition covers at most %d paths", MaxPaths)
	}
	for _, path := range d.Paths {
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\n\r") {
			return fmt.Errorf("the path %q is not absolute", path)
		}
	}
	for _, pattern := range d.Excludes {
		if strings.ContainsAny(pattern, "\n\r") {
			return fmt.Errorf("an exclude pattern contains a newline")
		}
	}
	for _, tag := range d.Tags {
		if tag == "" || strings.ContainsAny(tag, " \t\n\r,") {
			return fmt.Errorf("invalid tag %q", tag)
		}
	}
	for _, value := range []int{d.KeepLast, d.KeepDaily, d.KeepWeekly, d.KeepMonthly} {
		if value < 0 || value > 10000 {
			return fmt.Errorf("the number of kept copies is out of range")
		}
	}
	return nil
}

// Trees the panel does not restore data into.
//
// A restore straight into the host filesystem turns a backup into unpacking
// an old state onto a running system: the configuration, accounts and
// libraries come back in one jump, and nobody reviews it. Data is restored
// into a working directory, and what returns from it into place is a
// separate decision and a separate operation.
var forbiddenTrees = []string{
	"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot",
	"/dev", "/proc", "/sys", "/run",
	// The state of the panel and its helper is no place for restored data.
	"/var/lib/flotestro", "/var/lib/flotestro-helper",
	// The helper runs with PrivateTmp, so it has its own private /tmp and
	// /var/tmp. Data restored there vanishes together with the process,
	// and the operator sees a success and an empty directory - the worst
	// possible answer.
	"/tmp", "/var/tmp",
}

// forbiddenRoots lists the directories that are not touched themselves,
// although their interior is an ordinary place for data. A restore into
// /home/anna/copy is normal work; a restore into /home is not.
var forbiddenRoots = []string{"/", "/home", "/root", "/var", "/srv", "/opt", "/mnt", "/media"}

// ValidateRestore checks the target and the overwrite plan.
func ValidateRestore(restore Restore) error {
	if strings.TrimSpace(restore.SnapshotID) == "" {
		return fmt.Errorf("a restore requires naming a copy")
	}
	if strings.ContainsAny(restore.SnapshotID, " \t\n\r/") || len(restore.SnapshotID) > 128 {
		return fmt.Errorf("invalid copy identifier")
	}
	target := restore.Target
	if !strings.HasPrefix(target, "/") {
		return fmt.Errorf("a restore requires an absolute target path")
	}
	if target != filepath.Clean(target) || strings.Contains(target, "..") {
		return fmt.Errorf("the target path %q is not in normalised form", target)
	}
	if strings.ContainsAny(target, "\n\r") {
		return fmt.Errorf("the target path contains a newline")
	}
	for _, forbidden := range forbiddenRoots {
		if target == forbidden {
			return fmt.Errorf("the panel does not restore data straight into %s; name a working directory", forbidden)
		}
	}
	for _, tree := range forbiddenTrees {
		if target == tree || strings.HasPrefix(target, tree+"/") {
			if tree == "/tmp" || tree == "/var/tmp" {
				return fmt.Errorf("the helper has its own private %s: data restored there vanishes with the operation", tree)
			}
			return fmt.Errorf("the panel does not restore data straight into %s; name a working directory", tree)
		}
	}
	switch restore.Overwrite {
	case OverwriteEmpty, OverwriteAllowed:
	default:
		return fmt.Errorf("a restore requires an overwrite plan (%s or %s)",
			OverwriteEmpty, OverwriteAllowed)
	}
	for _, pattern := range restore.Include {
		if !strings.HasPrefix(pattern, "/") || strings.ContainsAny(pattern, "\n\r") {
			return fmt.Errorf("the scope %q is not an absolute path", pattern)
		}
	}
	return nil
}

// CheckTarget checks the target directory right before unpacking.
//
// The check is on the host, not in the panel, because only the host knows
// what really lies in this directory - and knows it only at the moment of
// the operation.
func CheckTarget(restore Restore) error {
	info, err := os.Stat(restore.Target)
	if os.IsNotExist(err) {
		// A directory that does not exist is not created half-way down the
		// tree: the parent must exist so that a typo does not create a
		// directory in a random place.
		parent := filepath.Dir(restore.Target)
		if info, err := os.Stat(parent); err != nil || !info.IsDir() {
			return fmt.Errorf("the directory %s does not exist", parent)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("the target %s is not a directory", restore.Target)
	}
	if restore.Overwrite == OverwriteAllowed {
		return nil
	}
	entries, err := os.ReadDir(restore.Target)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("the directory %s is not empty, and the overwrite plan does not allow that",
			restore.Target)
	}
	return nil
}

// ValidateEnvironment checks the names of the variables the panel sets for
// the tool.
func ValidateEnvironment(variables []string) error {
	for _, name := range variables {
		if !variableName.MatchString(name) {
			return fmt.Errorf("invalid environment variable name %q", name)
		}
	}
	return nil
}

// Mask removes from the output the values that must not leave it.
//
// Backup tools print the repository address, and that is at times an
// address with a password written in. The credential values themselves are
// masked too: one echo in a script is enough for the password to land in
// the task result, and from there in the panel database.
func Mask(output string, secrets [][]byte) string {
	result := output
	for _, value := range secrets {
		if len(value) < 4 {
			// A short value masked in text would turn the output into a
			// sieve; the store should not hand out such passwords anyway.
			continue
		}
		result = strings.ReplaceAll(result, string(value), "[masked]")
	}
	return maskAddresses(result)
}

// addressPattern catches credentials written into an address.
var addressPattern = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@`)

func maskAddresses(output string) string {
	return addressPattern.ReplaceAllString(output, "${1}${2}:[masked]@")
}

// Limit trims the output to the size the panel stores.
func Limit(output string) string {
	if len(output) <= MaxOutput {
		return output
	}
	// The end of the output matters more than the beginning: the errors
	// and the summary are there.
	return "[output trimmed at the module limit]\n" + output[len(output)-MaxOutput:]
}

// SortSnapshots orders the copies oldest first.
func SortSnapshots(snapshots []Snapshot) {
	sort.SliceStable(snapshots, func(i, j int) bool {
		return snapshots[i].Time.Before(snapshots[j].Time)
	})
}

// LastSuccess returns the time of the newest copy or nil.
func LastSuccess(snapshots []Snapshot) *time.Time {
	if len(snapshots) == 0 {
		return nil
	}
	newest := snapshots[0].Time
	for _, snapshot := range snapshots[1:] {
		if snapshot.Time.After(newest) {
			newest = snapshot.Time
		}
	}
	return &newest
}
