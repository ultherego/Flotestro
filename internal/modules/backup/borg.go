package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var borgPaths = []string{"/usr/bin/borg", "/usr/local/bin/borg"}

// BorgPasswordVariable is the name of the variable borg reads instead of
// asking.
const BorgPasswordVariable = "BORG_PASSPHRASE"

// Borg is the adapter of the borgbackup tool.
type Borg struct{}

func (b *Borg) Name() string { return ToolBorg }

func (b *Borg) Available() bool { return b.path() != "" }

func (b *Borg) path() string {
	for _, path := range borgPaths {
		if exists(path) {
			return path
		}
	}
	return ""
}

// environment adds the variables without which borg stops at a question.
//
// Borg asks a human for consent when the repository is unknown or changed
// its identity. A process without a terminal would wait for the answer
// until the time limit, so the answer is given up front: relocation is not
// accepted, because a change of repository identity is an event the
// operator is meant to learn about.
func (b *Borg) environment(order Order) []string {
	return append(toolEnvironment(order, BorgPasswordVariable),
		"BORG_RELOCATED_REPO_ACCESS_IS_OK=no",
		"BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=no",
		"BORG_EXIT_CODES=modern")
}

func (b *Borg) Version(ctx context.Context) string {
	if b.path() == "" {
		return ""
	}
	result := run(ctx, b.path(), []string{"--version"},
		toolEnvironment(Order{}, ""), nil, nil)
	return strings.TrimSpace(result.Stdout)
}

// Plan reads the repository archives.
func (b *Borg) Plan(ctx context.Context, order Order) (State, error) {
	state := State{Tool: ToolBorg, Repository: order.Repository, ObservedAt: time.Now().UTC()}
	if b.path() == "" {
		state.UnavailableReason = "this host does not have borg"
		return state, fmt.Errorf("this host does not have borg")
	}
	state.ToolVersion = b.Version(ctx)

	result := run(ctx, b.path(), []string{"list", "--json", order.Repository},
		b.environment(order), orderSecrets(order), nil)
	if !result.Ran || result.ExitCode != 0 || result.Err != nil {
		state.UnavailableReason = result.Reason()
		return state, fmt.Errorf("borg list: %s", result.Reason())
	}
	var list struct {
		Archives []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Start string `json:"start"`
		} `json:"archives"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &list); err != nil {
		state.UnavailableReason = "the archive list was not recognised: " + err.Error()
		return state, err
	}
	for _, archive := range list.Archives {
		snapshot := Snapshot{ID: archive.Name}
		// Borg reports the host local time without a zone; it is read as
		// written, without pretending to know more.
		if moment, err := time.Parse("2006-01-02T15:04:05.000000", archive.Start); err == nil {
			snapshot.Time = moment.UTC()
		} else if moment, err := time.Parse(time.RFC3339, archive.Start); err == nil {
			snapshot.Time = moment.UTC()
		}
		state.Snapshots = append(state.Snapshots, snapshot)
	}
	SortSnapshots(state.Snapshots)
	state.LastSuccessAt = LastSuccess(state.Snapshots)

	info := run(ctx, b.path(), []string{"info", "--json", order.Repository},
		b.environment(order), orderSecrets(order), nil)
	if info.Ran && info.ExitCode == 0 {
		var description struct {
			Cache struct {
				Stats struct {
					UniqueCSize uint64 `json:"unique_csize"`
					TotalSize   uint64 `json:"total_size"`
				} `json:"stats"`
			} `json:"cache"`
		}
		if err := json.Unmarshal([]byte(info.Stdout), &description); err == nil {
			size := description.Cache.Stats.UniqueCSize
			if size == 0 {
				size = description.Cache.Stats.TotalSize
			}
			if size > 0 {
				state.TotalSizeBytes = &size
			}
		}
	}
	return state, nil
}

// Run creates an archive and cleans up old ones.
func (b *Borg) Run(ctx context.Context, order Order, progress ProgressFunc) (Result, error) {
	result := Result{}
	if b.path() == "" {
		return result, fmt.Errorf("this host does not have borg")
	}
	if len(order.Paths) == 0 {
		return result, fmt.Errorf("the definition does not say what to back up")
	}

	if err := b.ensureExists(ctx, order); err != nil {
		return result, err
	}

	// The archive name must be unique in the repository; a timestamp is the
	// only sensible distinguisher here and information for a human at the
	// same time.
	name := order.ID + "-" + time.Now().UTC().Format("20060102T150405Z")
	arguments := []string{"create", "--json", "--stats",
		order.Repository + "::" + name}
	arguments = append(arguments, order.Paths...)
	for _, pattern := range order.Excludes {
		arguments = append(arguments, "--exclude", pattern)
	}
	if progress != nil {
		progress(Progress{Message: "archive " + name})
	}

	execution := run(ctx, b.path(), arguments,
		b.environment(order), orderSecrets(order), nil)
	result.Output = execution.Stderr
	if !execution.Ran || execution.Err != nil {
		return result, fmt.Errorf("borg create: %s", execution.Reason())
	}
	// Borg code 1 means warnings - most often files that could not be
	// read. The archive was created, but is incomplete.
	if execution.ExitCode != 0 && execution.ExitCode != 1 {
		return result, fmt.Errorf("borg create: %s", execution.Reason())
	}

	result.SnapshotID = name
	var stats struct {
		Archive struct {
			Stats struct {
				DeduplicatedSize uint64  `json:"deduplicated_size"`
				OriginalSize     uint64  `json:"original_size"`
				NFiles           uint64  `json:"nfiles"`
				Duration         float64 `json:"duration"`
			} `json:"stats"`
		} `json:"archive"`
	}
	if err := json.Unmarshal([]byte(execution.Stdout), &stats); err == nil {
		added := stats.Archive.Stats.DeduplicatedSize
		processed := stats.Archive.Stats.OriginalSize
		files := stats.Archive.Stats.NFiles
		duration := stats.Archive.Stats.Duration
		result.BytesAdded = &added
		result.TotalBytesProcessed = &processed
		result.FilesNew = &files
		result.DurationSeconds = &duration
	}
	result.Message = "archive " + name + " created"
	if execution.ExitCode == 1 {
		result.Message += "; some files could not be read"
	}

	if err := b.retention(ctx, order); err != nil {
		result.Message += "; retention failed: " + err.Error()
	}
	return result, nil
}

// retention deletes the archives outside the policy.
func (b *Borg) retention(ctx context.Context, order Order) error {
	arguments := []string{"prune", "--glob-archives", order.ID + "-*"}
	set := false
	for _, threshold := range []struct {
		flag  string
		value int
	}{
		{"--keep-last", order.KeepLast},
		{"--keep-daily", order.KeepDaily},
		{"--keep-weekly", order.KeepWeekly},
		{"--keep-monthly", order.KeepMonthly},
	} {
		if threshold.value > 0 {
			arguments = append(arguments, threshold.flag, strconv.Itoa(threshold.value))
			set = true
		}
	}
	if !set {
		return nil
	}
	arguments = append(arguments, order.Repository)

	result := run(ctx, b.path(), arguments,
		b.environment(order), orderSecrets(order), nil)
	if !result.Ran || (result.ExitCode != 0 && result.ExitCode != 1) {
		return fmt.Errorf("%s", result.Reason())
	}
	if !order.Prune {
		return nil
	}
	// Cleanup in borg is a separate step: prune detaches the archives, and
	// only compact frees the space.
	compact := run(ctx, b.path(), []string{"compact", order.Repository},
		b.environment(order), orderSecrets(order), nil)
	if !compact.Ran || (compact.ExitCode != 0 && compact.ExitCode != 1) {
		return fmt.Errorf("%s", compact.Reason())
	}
	return nil
}

// Verify checks the repository.
func (b *Borg) Verify(ctx context.Context, order Order) (Result, error) {
	result := Result{}
	if b.path() == "" {
		return result, fmt.Errorf("this host does not have borg")
	}
	arguments := []string{"check"}
	if order.ReadData {
		arguments = append(arguments, "--verify-data")
	}
	arguments = append(arguments, order.Repository)

	execution := run(ctx, b.path(), arguments,
		b.environment(order), orderSecrets(order), nil)
	result.Output = execution.Stdout + execution.Stderr
	if !execution.Ran || execution.ExitCode != 0 || execution.Err != nil {
		return result, fmt.Errorf("borg check: %s", execution.Reason())
	}
	result.Message = "repository checked"
	if order.ReadData {
		result.Message += " together with reading the data"
	}
	return result, nil
}

// RestoreData unpacks an archive into the named directory.
func (b *Borg) RestoreData(ctx context.Context, order Order) (Result, error) {
	result := Result{}
	if b.path() == "" {
		return result, fmt.Errorf("this host does not have borg")
	}
	arguments := []string{"extract",
		order.Repository + "::" + order.Restore.SnapshotID}
	for _, pattern := range order.Restore.Include {
		// Borg matches the paths inside the archive, that is without the
		// leading slash. The conversion is here, not in the panel: it is a
		// tool detail.
		arguments = append(arguments, strings.TrimPrefix(pattern, "/"))
	}
	execution := runInDir(ctx, order.Restore.Target, b.path(), arguments,
		b.environment(order), orderSecrets(order), nil)
	result.Output = execution.Stdout + execution.Stderr
	if !execution.Ran || execution.ExitCode != 0 || execution.Err != nil {
		return result, fmt.Errorf("borg extract: %s", execution.Reason())
	}
	result.Message = "archive " + order.Restore.SnapshotID +
		" restored into " + order.Restore.Target
	return result, nil
}

// ensureExists creates the repository if the definition allows it.
func (b *Borg) ensureExists(ctx context.Context, order Order) error {
	check := run(ctx, b.path(), []string{"info", "--json", order.Repository},
		b.environment(order), orderSecrets(order), nil)
	if check.Ran && check.ExitCode == 0 {
		return nil
	}
	if !order.Initialize {
		return nil
	}
	// Encryption with the key in the repository: the password comes from
	// the store, and a key next to the repository survives a host rebuild.
	creation := run(ctx, b.path(),
		[]string{"init", "--encryption", "repokey", order.Repository},
		b.environment(order), orderSecrets(order), nil)
	if !creation.Ran || creation.ExitCode != 0 {
		return fmt.Errorf("borg init: %s", creation.Reason())
	}
	return nil
}
