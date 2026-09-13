package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Runbook runs a script prepared by the host administrator.
//
// This is the only place in the whole system where the panel runs something
// it does not know itself - and that is why it is fenced with three rules.
// The panel does not send the script content, only its name. The script
// must already lie in a directory only root writes to. And it must answer
// with an agreed contract, not arbitrary text: otherwise a "runbook" would
// be remote execution of arbitrary code under a prettier name.
type Runbook struct{}

func (r *Runbook) Name() string { return ToolRunbook }

// Available says whether the host has the runbook directory at all.
func (r *Runbook) Available() bool {
	info, err := os.Stat(RunbookDir)
	return err == nil && info.IsDir()
}

func (r *Runbook) Version(context.Context) string { return "" }

// Path checks the script and returns its full path.
//
// The owner and the permissions are checked, not only existence: a script
// writable by an ordinary user would mean every user of the host can plant
// code for the panel to run with root privileges.
func (r *Runbook) Path(name string) (string, error) {
	if !runbookName.MatchString(name) {
		return "", fmt.Errorf("invalid runbook name %q", name)
	}
	path := filepath.Join(RunbookDir, name)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return "", fmt.Errorf("this host has no runbook %q", name)
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("the runbook %q is not a regular file", name)
	}
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok {
		return "", fmt.Errorf("the owner of the runbook %q could not be read", name)
	}
	if stat.Uid != 0 {
		return "", fmt.Errorf("the runbook %q does not belong to root", name)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("the runbook %q is writable outside root", name)
	}
	if info.Mode().Perm()&0o100 == 0 {
		return "", fmt.Errorf("the runbook %q is not executable", name)
	}
	return path, nil
}

// environment assembles the variables describing the order.
//
// Everything goes through the environment, not the arguments: the
// arguments are seen by every user of the host through /proc, and the
// variables include the repository password.
func (r *Runbook) environment(order Order, operation string) []string {
	environment := append(toolEnvironment(order, "FLOTESTRO_BACKUP_PASSWORD"),
		"FLOTESTRO_BACKUP_OPERATION="+operation,
		"FLOTESTRO_BACKUP_ID="+order.ID,
		"FLOTESTRO_BACKUP_REPOSITORY="+order.Repository,
		"FLOTESTRO_BACKUP_PATHS="+strings.Join(order.Paths, "\n"),
		"FLOTESTRO_BACKUP_EXCLUDES="+strings.Join(order.Excludes, "\n"),
		"FLOTESTRO_BACKUP_TAGS="+strings.Join(order.Tags, "\n"),
	)
	if operation == OperationRestore {
		environment = append(environment,
			"FLOTESTRO_BACKUP_SNAPSHOT="+order.Restore.SnapshotID,
			"FLOTESTRO_BACKUP_TARGET="+order.Restore.Target,
			"FLOTESTRO_BACKUP_INCLUDE="+strings.Join(order.Restore.Include, "\n"),
			"FLOTESTRO_BACKUP_OVERWRITE="+order.Restore.Overwrite,
		)
	}
	if operation == OperationVerify && order.ReadData {
		environment = append(environment, "FLOTESTRO_BACKUP_READ_DATA=1")
	}
	return environment
}

// invoke runs the runbook and returns the last line of its output and the
// whole of it.
//
// The contract is deliberately narrow: the runbook may write what it wants,
// but the last line must be a JSON document. The panel reads only that -
// the rest is a log for a human, not data.
func (r *Runbook) invoke(ctx context.Context, order Order,
	operation string, progress ProgressFunc) (string, commandResult, error) {
	path, err := r.Path(order.Runbook)
	if err != nil {
		return "", commandResult{}, err
	}
	var last string
	execution := run(ctx, path, []string{operation},
		r.environment(order, operation), orderSecrets(order),
		func(line string) {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				return
			}
			if strings.HasPrefix(trimmed, "{") {
				last = trimmed
				return
			}
			if progress != nil {
				progress(Progress{Message: trimmed})
			}
		})
	if !execution.Ran || execution.Err != nil || execution.ExitCode != 0 {
		return last, execution, fmt.Errorf("runbook %s %s: %s",
			order.Runbook, operation, execution.Reason())
	}
	return last, execution, nil
}

// runbookAnswer is the contract of the script output.
type runbookAnswer struct {
	Snapshots []struct {
		ID        string   `json:"id"`
		Time      string   `json:"time"`
		SizeBytes uint64   `json:"size_bytes"`
		Paths     []string `json:"paths"`
	} `json:"snapshots"`
	TotalSizeBytes  uint64  `json:"total_size_bytes"`
	SnapshotID      string  `json:"snapshot_id"`
	BytesAdded      uint64  `json:"bytes_added"`
	FilesNew        uint64  `json:"files_new"`
	FilesRestored   uint64  `json:"files_restored"`
	DurationSeconds float64 `json:"duration_seconds"`
	Message         string  `json:"message"`
}

// Plan asks the runbook about the repository state.
func (r *Runbook) Plan(ctx context.Context, order Order) (State, error) {
	state := State{Tool: ToolRunbook, Repository: order.Repository, ObservedAt: time.Now().UTC()}
	line, execution, err := r.invoke(ctx, order, OperationPlan, nil)
	if err != nil {
		state.UnavailableReason = execution.Reason()
		if state.UnavailableReason == "" {
			state.UnavailableReason = err.Error()
		}
		return state, err
	}
	if line == "" {
		state.UnavailableReason = "the runbook did not answer with a JSON document"
		return state, fmt.Errorf("the runbook %s did not answer with a JSON document", order.Runbook)
	}
	var answer runbookAnswer
	if err := json.Unmarshal([]byte(line), &answer); err != nil {
		state.UnavailableReason = "the runbook answer was not recognised: " + err.Error()
		return state, err
	}
	for _, entry := range answer.Snapshots {
		snapshot := Snapshot{ID: entry.ID, Paths: entry.Paths}
		if moment, err := time.Parse(time.RFC3339, entry.Time); err == nil {
			snapshot.Time = moment.UTC()
		}
		if entry.SizeBytes > 0 {
			size := entry.SizeBytes
			snapshot.SizeBytes = &size
		}
		state.Snapshots = append(state.Snapshots, snapshot)
	}
	SortSnapshots(state.Snapshots)
	state.LastSuccessAt = LastSuccess(state.Snapshots)
	if answer.TotalSizeBytes > 0 {
		size := answer.TotalSizeBytes
		state.TotalSizeBytes = &size
	}
	return state, nil
}

// Run orders the runbook to make a copy.
func (r *Runbook) Run(ctx context.Context, order Order, progress ProgressFunc) (Result, error) {
	return r.operationResult(ctx, order, OperationBackup, progress)
}

// Verify orders the runbook to verify the copy.
func (r *Runbook) Verify(ctx context.Context, order Order) (Result, error) {
	return r.operationResult(ctx, order, OperationVerify, nil)
}

// RestoreData orders the runbook to restore the copy.
func (r *Runbook) RestoreData(ctx context.Context, order Order) (Result, error) {
	return r.operationResult(ctx, order, OperationRestore, nil)
}

func (r *Runbook) operationResult(ctx context.Context, order Order,
	operation string, progress ProgressFunc) (Result, error) {
	result := Result{}
	line, execution, err := r.invoke(ctx, order, operation, progress)
	result.Output = execution.Stdout + execution.Stderr
	if err != nil {
		return result, err
	}
	if line == "" {
		// Silence after an operation changing the state is worse than an
		// error: it is unknown whether the copy was made.
		return result, fmt.Errorf("the runbook %s did not answer with a JSON document", order.Runbook)
	}
	var answer runbookAnswer
	if err := json.Unmarshal([]byte(line), &answer); err != nil {
		return result, fmt.Errorf("the runbook answer was not recognised: %w", err)
	}
	result.SnapshotID = answer.SnapshotID
	result.Message = answer.Message
	if answer.BytesAdded > 0 {
		value := answer.BytesAdded
		result.BytesAdded = &value
	}
	if answer.FilesNew > 0 {
		value := answer.FilesNew
		result.FilesNew = &value
	}
	if answer.FilesRestored > 0 {
		value := answer.FilesRestored
		result.FilesRestored = &value
	}
	if answer.DurationSeconds > 0 {
		value := answer.DurationSeconds
		result.DurationSeconds = &value
	}
	if result.Message == "" {
		result.Message = "the runbook " + order.Runbook + " finished the operation " + operation
	}
	return result, nil
}

// ListRunbooks lists the scripts the panel may run on this host.
//
// Whether the directory could be read is returned too: a directory without
// runbooks and an unread directory are two different answers.
func ListRunbooks() ([]string, bool) {
	entries, err := os.ReadDir(RunbookDir)
	if err != nil {
		return nil, false
	}
	runbook := &Runbook{}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Only those the panel really runs are shown: a script writable
		// outside root is not a runbook, only a hole.
		if _, err := runbook.Path(entry.Name()); err != nil {
			continue
		}
		names = append(names, entry.Name())
	}
	return names, true
}
