package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Tool paths. Restic is at times in /usr/bin or in /usr/local/bin - the
// latter is where a binary downloaded from the project site lands.
var resticPaths = []string{"/usr/bin/restic", "/usr/local/bin/restic"}

// ResticPasswordVariable is the name of the variable restic reads instead
// of asking.
const ResticPasswordVariable = "RESTIC_PASSWORD"

// Restic is the adapter of the restic tool.
type Restic struct{}

func (r *Restic) Name() string { return ToolRestic }

func (r *Restic) Available() bool { return r.path() != "" }

func (r *Restic) path() string {
	for _, path := range resticPaths {
		if exists(path) {
			return path
		}
	}
	return ""
}

func (r *Restic) Version(ctx context.Context) string {
	if r.path() == "" {
		return ""
	}
	result := run(ctx, r.path(), []string{"version"},
		toolEnvironment(Order{}, ""), nil, nil)
	return strings.TrimSpace(result.Stdout)
}

// baseArguments assembles the arguments common to every invocation.
//
// The repository address goes as an argument, because it is not a secret:
// it is the target name the panel shows anyway. The password goes through
// the environment.
func (r *Restic) baseArguments(order Order) []string {
	return []string{"--repo", order.Repository, "--json"}
}

// resticSnapshot is an entry of "restic snapshots --json".
type resticSnapshot struct {
	ID       string    `json:"id"`
	ShortID  string    `json:"short_id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	Paths    []string  `json:"paths"`
	Tags     []string  `json:"tags"`
}

// Plan reads the repository state: the copies and their size.
func (r *Restic) Plan(ctx context.Context, order Order) (State, error) {
	state := State{
		Tool: ToolRestic, Repository: order.Repository,
		ObservedAt: time.Now().UTC(),
	}
	if r.path() == "" {
		state.UnavailableReason = "this host does not have restic"
		return state, fmt.Errorf("this host does not have restic")
	}
	state.ToolVersion = r.Version(ctx)

	arguments := append(r.baseArguments(order), "snapshots")
	result := run(ctx, r.path(), arguments,
		toolEnvironment(order, ResticPasswordVariable), orderSecrets(order), nil)
	if !result.Ran || result.ExitCode != 0 || result.Err != nil {
		state.UnavailableReason = result.Reason()
		return state, fmt.Errorf("restic snapshots: %s", result.Reason())
	}

	var entries []resticSnapshot
	if err := json.Unmarshal([]byte(result.Stdout), &entries); err != nil {
		state.UnavailableReason = "the copy list was not recognised: " + err.Error()
		return state, err
	}
	for _, entry := range entries {
		identifier := entry.ShortID
		if identifier == "" {
			identifier = entry.ID
		}
		state.Snapshots = append(state.Snapshots, Snapshot{
			ID: identifier, Time: entry.Time.UTC(), Hostname: entry.Hostname,
			Paths: entry.Paths, Tags: entry.Tags,
		})
	}
	SortSnapshots(state.Snapshots)
	state.LastSuccessAt = LastSuccess(state.Snapshots)

	// The repository size is a separate question and a separate cost:
	// restic computes it by walking the index. A failed read leaves no
	// knowledge, not zero - a repository without a size still has copies.
	size := run(ctx, r.path(),
		append(r.baseArguments(order), "stats", "--mode", "raw-data"),
		toolEnvironment(order, ResticPasswordVariable), orderSecrets(order), nil)
	if size.Ran && size.ExitCode == 0 {
		var stats struct {
			TotalSize uint64 `json:"total_size"`
		}
		if err := json.Unmarshal([]byte(size.Stdout), &stats); err == nil {
			state.TotalSizeBytes = &stats.TotalSize
		}
	}
	return state, nil
}

// resticMessage is a line of the "--json" stream during a backup.
type resticMessage struct {
	MessageType    string  `json:"message_type"`
	PercentDone    float64 `json:"percent_done"`
	TotalFiles     uint64  `json:"total_files"`
	FilesDone      uint64  `json:"files_done"`
	TotalBytes     uint64  `json:"total_bytes"`
	BytesDone      uint64  `json:"bytes_done"`
	SnapshotID     string  `json:"snapshot_id"`
	FilesNew       uint64  `json:"files_new"`
	FilesChanged   uint64  `json:"files_changed"`
	DataAdded      uint64  `json:"data_added"`
	TotalBytesProc uint64  `json:"total_bytes_processed"`
	TotalDuration  float64 `json:"total_duration"`
	Error          struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Run makes a copy and after it - if the definition says so - cleans up
// old ones.
func (r *Restic) Run(ctx context.Context, order Order, progress ProgressFunc) (Result, error) {
	result := Result{}
	if r.path() == "" {
		return result, fmt.Errorf("this host does not have restic")
	}
	if len(order.Paths) == 0 {
		return result, fmt.Errorf("the definition does not say what to back up")
	}

	if err := r.ensureExists(ctx, order); err != nil {
		return result, err
	}

	arguments := append(r.baseArguments(order), "backup")
	arguments = append(arguments, order.Paths...)
	for _, pattern := range order.Excludes {
		arguments = append(arguments, "--exclude", pattern)
	}
	for _, tag := range order.Tags {
		arguments = append(arguments, "--tag", tag)
	}

	var summary resticMessage
	var errorsSeen []string
	execution := run(ctx, r.path(), arguments,
		toolEnvironment(order, ResticPasswordVariable), orderSecrets(order),
		func(line string) {
			var message resticMessage
			if err := json.Unmarshal([]byte(line), &message); err != nil {
				return
			}
			switch message.MessageType {
			case "status":
				if progress != nil {
					percent := uint32(message.PercentDone * 100)
					progress(Progress{
						Percent: &percent,
						Message: fmt.Sprintf("%s of %s",
							humanSize(message.BytesDone), humanSize(message.TotalBytes)),
					})
				}
			case "summary":
				summary = message
			case "error":
				if message.Error.Message != "" {
					errorsSeen = append(errorsSeen, message.Error.Message)
				}
			}
		})
	result.Output = execution.Stderr

	if execution.Err != nil || !execution.Ran {
		return result, fmt.Errorf("restic backup: %s", execution.Reason())
	}
	// Code 3 means a copy made despite files that could not be read. That
	// is not a success and not a failure: the copy exists, but is
	// incomplete - and that is how it has to be named.
	if execution.ExitCode != 0 && execution.ExitCode != 3 {
		return result, fmt.Errorf("restic backup: %s", execution.Reason())
	}

	result.SnapshotID = summary.SnapshotID
	if summary.SnapshotID != "" {
		added, processed := summary.DataAdded, summary.TotalBytesProc
		newFiles, changed := summary.FilesNew, summary.FilesChanged
		duration := summary.TotalDuration
		result.BytesAdded = &added
		result.TotalBytesProcessed = &processed
		result.FilesNew = &newFiles
		result.FilesChanged = &changed
		result.DurationSeconds = &duration
		result.Message = fmt.Sprintf("copy %s: %s of new data, %d new files",
			summary.SnapshotID, humanSize(summary.DataAdded), summary.FilesNew)
	}
	if execution.ExitCode == 3 || len(errorsSeen) > 0 {
		result.Message += "; some files could not be read"
		if len(errorsSeen) > 0 {
			result.Message += ": " + strings.Join(first(errorsSeen, 3), "; ")
		}
	}

	if removed, err := r.retention(ctx, order); err != nil {
		// The copy is made; a failed cleanup cannot invalidate it, but
		// cannot vanish from the result either.
		result.Message += "; retention failed: " + err.Error()
	} else if removed != nil {
		result.Removed = removed
	}
	return result, nil
}

// retention deletes the copies outside the policy. Zero in all thresholds
// means "do not clean up": deleting old copies is a separate decision.
func (r *Restic) retention(ctx context.Context, order Order) (*int, error) {
	thresholds := []struct {
		flag  string
		value int
	}{
		{"--keep-last", order.KeepLast},
		{"--keep-daily", order.KeepDaily},
		{"--keep-weekly", order.KeepWeekly},
		{"--keep-monthly", order.KeepMonthly},
	}
	arguments := append(r.baseArguments(order), "forget")
	set := false
	for _, threshold := range thresholds {
		if threshold.value > 0 {
			arguments = append(arguments, threshold.flag, strconv.Itoa(threshold.value))
			set = true
		}
	}
	if !set {
		return nil, nil
	}
	if order.Prune {
		arguments = append(arguments, "--prune")
	}

	result := run(ctx, r.path(), arguments,
		toolEnvironment(order, ResticPasswordVariable), orderSecrets(order), nil)
	if !result.Ran || result.ExitCode != 0 {
		return nil, fmt.Errorf("%s", result.Reason())
	}
	var groups []struct {
		Remove []resticSnapshot `json:"remove"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &groups); err != nil {
		return nil, nil
	}
	removed := 0
	for _, group := range groups {
		removed += len(group.Remove)
	}
	return &removed, nil
}

// Verify checks the repository.
func (r *Restic) Verify(ctx context.Context, order Order) (Result, error) {
	result := Result{}
	if r.path() == "" {
		return result, fmt.Errorf("this host does not have restic")
	}
	arguments := append(r.baseArguments(order), "check")
	if order.ReadData {
		// A structure check says the index agrees; only reading the data
		// says the copy can be restored. The latter costs traffic and time,
		// so it is the operator's explicit choice.
		arguments = append(arguments, "--read-data-subset", "5%")
	}
	execution := run(ctx, r.path(), arguments,
		toolEnvironment(order, ResticPasswordVariable), orderSecrets(order), nil)
	result.Output = execution.Stdout + execution.Stderr
	if !execution.Ran || execution.ExitCode != 0 || execution.Err != nil {
		return result, fmt.Errorf("restic check: %s", execution.Reason())
	}
	result.Message = "repository checked"
	if order.ReadData {
		result.Message += " together with reading a subset of the data"
	}
	return result, nil
}

// RestoreData unpacks a copy into the named directory.
func (r *Restic) RestoreData(ctx context.Context, order Order) (Result, error) {
	result := Result{}
	if r.path() == "" {
		return result, fmt.Errorf("this host does not have restic")
	}
	arguments := append(r.baseArguments(order), "restore",
		order.Restore.SnapshotID, "--target", order.Restore.Target)
	for _, pattern := range order.Restore.Include {
		arguments = append(arguments, "--include", pattern)
	}
	execution := run(ctx, r.path(), arguments,
		toolEnvironment(order, ResticPasswordVariable), orderSecrets(order), nil)
	result.Output = execution.Stdout + execution.Stderr
	if !execution.Ran || execution.ExitCode != 0 || execution.Err != nil {
		return result, fmt.Errorf("restic restore: %s", execution.Reason())
	}

	var summary struct {
		MessageType   string `json:"message_type"`
		FilesRestored uint64 `json:"files_restored"`
		TotalBytes    uint64 `json:"total_bytes"`
	}
	for _, line := range strings.Split(execution.Stdout, "\n") {
		if err := json.Unmarshal([]byte(line), &summary); err == nil &&
			summary.MessageType == "summary" {
			files, bytes := summary.FilesRestored, summary.TotalBytes
			result.FilesRestored = &files
			result.TotalBytesProcessed = &bytes
		}
	}
	result.Message = "copy " + order.Restore.SnapshotID +
		" restored into " + order.Restore.Target
	return result, nil
}

// humanSize describes a byte count the way a human reads it.
func humanSize(bytes uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(bytes)
	for _, unit := range units {
		if value < 1024 || unit == "TiB" {
			digits := 1
			if unit == "B" {
				digits = 0
			}
			return strconv.FormatFloat(value, 'f', digits, 64) + " " + unit
		}
		value /= 1024
	}
	return strconv.FormatUint(bytes, 10) + " B"
}

// first trims a list of messages to the first few.
func first(values []string, count int) []string {
	if len(values) <= count {
		return values
	}
	return values[:count]
}

// ensureExists creates the repository if the definition allows it.
//
// It is created only when the operator asked for it. A repository created
// quietly on a typo in the address looks like a working backup - and is an
// empty directory next to the right one.
func (r *Restic) ensureExists(ctx context.Context, order Order) error {
	check := run(ctx, r.path(),
		append(r.baseArguments(order), "cat", "config"),
		toolEnvironment(order, ResticPasswordVariable), orderSecrets(order), nil)
	if check.Ran && check.ExitCode == 0 {
		return nil
	}
	if !order.Initialize {
		return nil
	}
	creation := run(ctx, r.path(),
		append(r.baseArguments(order), "init"),
		toolEnvironment(order, ResticPasswordVariable), orderSecrets(order), nil)
	if !creation.Ran || creation.ExitCode != 0 {
		return fmt.Errorf("restic init: %s", creation.Reason())
	}
	return nil
}
