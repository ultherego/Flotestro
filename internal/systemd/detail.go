package systemd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/modules/files"
)

const journalctlPath = "/usr/bin/journalctl"

// UnitDetail is the full picture of one unit: what it depends on, what
// starts it, what overrides its file and what it last wrote to the journal.
//
// The picture is read on request for one open row in the panel. It costs
// several processes and a few file reads, so it is not part of the listing
// and not part of a health check.
type UnitDetail struct {
	State        UnitState `json:"state"`
	Description  string    `json:"description,omitempty"`
	FragmentPath string    `json:"fragment_path,omitempty"`
	// The dependency lists, as systemd names them. An empty list is the
	// truth for a unit without that kind of dependency.
	Requires []string `json:"requires,omitempty"`
	Wants    []string `json:"wants,omitempty"`
	After    []string `json:"after,omitempty"`
	Before   []string `json:"before,omitempty"`
	BindsTo  []string `json:"binds_to,omitempty"`
	PartOf   []string `json:"part_of,omitempty"`
	// TriggeredBy lists the socket, timer and path units that activate this
	// unit; Triggers lists what this unit activates.
	TriggeredBy []string `json:"triggered_by,omitempty"`
	Triggers    []string `json:"triggers,omitempty"`
	DropIns     []DropIn `json:"drop_ins,omitempty"`
	// ExecMainStart is the start time of the main process: RFC 3339 when
	// the host's words could be read as a date, otherwise the words
	// themselves. Empty for a unit without a running main process.
	ExecMainStart string `json:"exec_main_start,omitempty"`
	// The last journal lines of the unit and the cursor of the last one, so
	// a longer read can continue from there. The list is never nil: no
	// lines is an answer, not a missing one.
	JournalLines     []string `json:"journal_lines"`
	JournalCursor    string   `json:"journal_cursor,omitempty"`
	JournalTruncated bool     `json:"journal_truncated,omitempty"`
	// JournalError says why the journal could not be read; the rest of the
	// detail stands on its own.
	JournalError string `json:"journal_error,omitempty"`
}

// DropIn is one override file with its content.
type DropIn struct {
	Path      string `json:"path"`
	Content   string `json:"content,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	// Error says why the content could not be read: a path outside the
	// allowed directories or a file the agent may not open.
	Error string `json:"error,omitempty"`
}

// The bounds of one detail read. A unit with more drop-ins or a longer
// override than this is unusual enough to be looked at on the host.
const (
	maxDropIns      = 16
	maxDropInBytes  = 16 << 10
	journalTailSize = 30
	maxJournalBytes = 64 << 10
)

// dropInPatterns are the only places the detail reads override files from.
// The packaged drop-ins under /usr/lib are the distribution's and are
// reported by path only; the administrator's overrides live here.
var dropInPatterns = []string{
	"/etc/systemd/system/*.d/*.conf",
	"/run/systemd/system/*.d/*.conf",
}

var detailProperties = append(append([]string{}, shownProperties...),
	"Description", "FragmentPath",
	"Requires", "Wants", "After", "Before", "BindsTo", "PartOf",
	"TriggeredBy", "Triggers", "DropInPaths", "ExecMainStartTimestamp")

// ShowDetail reads the full picture of a unit.
//
// The state and the dependencies come from one "systemctl show" call in
// the key=value form; the drop-ins are read from the file system through
// the safe reader of the files module; the journal tail is a separate,
// bounded call. A journal that cannot be read does not fail the detail:
// the operator still sees the state and the dependencies, together with
// the reason.
func ShowDetail(ctx context.Context, unit string) (UnitDetail, error) {
	if !unitPattern.MatchString(unit) {
		return UnitDetail{}, fmt.Errorf("%w: %q", ErrInvalidUnit, unit)
	}
	args := []string{"show", unit, "--no-pager", "--property=" + strings.Join(detailProperties, ",")}
	stdout, _, err := run(ctx, 15*time.Second, args...)
	if err != nil {
		return UnitDetail{}, err
	}

	detail := UnitDetail{State: UnitState{Name: unit}, JournalLines: []string{}}
	var dropInPaths []string
	for _, line := range strings.Split(stdout, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "Names":
			if value != "" {
				detail.State.Name = strings.Fields(value)[0]
			}
		case "LoadState":
			detail.State.LoadState = value
		case "ActiveState":
			detail.State.ActiveState = value
		case "SubState":
			detail.State.SubState = value
		case "UnitFileState":
			detail.State.UnitFileState = value
		case "Result":
			detail.State.Result = value
		case "MainPID":
			detail.State.MainPID = parseUint32(value)
		case "NRestarts":
			detail.State.NRestarts = parseUint32(value)
		case "Description":
			detail.Description = value
		case "FragmentPath":
			detail.FragmentPath = value
		case "Requires":
			detail.Requires = strings.Fields(value)
		case "Wants":
			detail.Wants = strings.Fields(value)
		case "After":
			detail.After = strings.Fields(value)
		case "Before":
			detail.Before = strings.Fields(value)
		case "BindsTo":
			detail.BindsTo = strings.Fields(value)
		case "PartOf":
			detail.PartOf = strings.Fields(value)
		case "TriggeredBy":
			detail.TriggeredBy = strings.Fields(value)
		case "Triggers":
			detail.Triggers = strings.Fields(value)
		case "DropInPaths":
			dropInPaths = strings.Fields(value)
		case "ExecMainStartTimestamp":
			detail.ExecMainStart = mainStart(value)
		}
	}
	detail.DropIns = readDropIns(dropInPaths)

	lines, cursor, truncated, err := journalTail(ctx, unit)
	detail.JournalLines, detail.JournalCursor, detail.JournalTruncated = lines, cursor, truncated
	if err != nil {
		detail.JournalError = err.Error()
	}
	return detail, nil
}

// mainStart turns the timestamp systemd prints into RFC 3339. The host's
// words are "Mon 2026-09-14 10:00:00 CEST"; they are read in the host's
// own zone, which is the one the abbreviation belongs to. Words that do
// not read as a date are passed on as they are - "n/a" is an answer too.
func mainStart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "n/a" {
		return ""
	}
	if parsed, err := time.ParseInLocation("Mon 2006-01-02 15:04:05 MST", value, time.Local); err == nil {
		return parsed.Format(time.RFC3339)
	}
	return value
}

// readDropIns reads the override files the unit loads.
//
// Every path is checked against the drop-in directories before it is
// opened, and opened without following symlinks: the list comes from
// systemd, but the file it points at could still be somebody's link into
// a directory the panel never shows.
func readDropIns(paths []string) []DropIn {
	allowlist := files.Allowlist{Patterns: dropInPatterns, Source: "unit drop-in directories"}
	var dropIns []DropIn
	for _, path := range paths {
		if len(dropIns) >= maxDropIns {
			break
		}
		dropIn := DropIn{Path: path}
		if err := allowlist.Allows(path); err != nil {
			dropIn.Error = "outside the drop-in directories the panel reads"
			dropIns = append(dropIns, dropIn)
			continue
		}
		dropIn.Content, dropIn.Truncated, dropIn.Error = readBounded(path, maxDropInBytes)
		dropIns = append(dropIns, dropIn)
	}
	return dropIns
}

// readBounded reads at most limit bytes of a file without following
// symlinks and says whether there was more.
func readBounded(path string, limit int) (content string, truncated bool, problem string) {
	file, err := files.OpenWithoutSymlinks(path, os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, files.ErrSymlink) {
			return "", false, "the path leads through a symbolic link"
		}
		if errors.Is(err, os.ErrNotExist) {
			return "", false, "the file does not exist"
		}
		if errors.Is(err, os.ErrPermission) {
			return "", false, "the agent may not read the file"
		}
		return "", false, err.Error()
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return "", false, err.Error()
	}
	if len(data) > limit {
		return string(data[:limit]), true, ""
	}
	return string(data), false, ""
}

// journalTail reads the last lines of the unit's journal and the cursor of
// the last one.
//
// The cursor is what lets the Logs page continue where the detail ended:
// journalctl prints it as the final line when asked, and the panel hands
// it back with --after-cursor. The read is bounded by the line count, by
// the byte limit and by its own timeout.
func journalTail(ctx context.Context, unit string) (lines []string, cursor string, truncated bool, err error) {
	args := []string{
		"--unit=" + unit, "--lines=" + fmt.Sprint(journalTailSize),
		"--no-pager", "--output=short-iso", "--show-cursor",
	}
	stdout, stderr, err := runTool(ctx, 15*time.Second, journalctlPath, args...)
	if err != nil {
		reason := strings.TrimSpace(stderr)
		if reason == "" {
			reason = err.Error()
		}
		return []string{}, "", false, fmt.Errorf("the journal could not be read: %s", firstLine(reason))
	}
	if len(stdout) > maxJournalBytes {
		// The cut is made from the start: the freshest lines are at the end
		// and the cursor is the last line of all.
		stdout = stdout[len(stdout)-maxJournalBytes:]
		if index := strings.IndexByte(stdout, '\n'); index >= 0 {
			stdout = stdout[index+1:]
		}
		truncated = true
	}
	lines = []string{}
	for _, line := range strings.Split(stdout, "\n") {
		switch {
		case line == "":
		case strings.HasPrefix(line, "-- cursor: "):
			cursor = strings.TrimSpace(strings.TrimPrefix(line, "-- cursor: "))
		case strings.HasPrefix(line, "-- No entries"):
			// An empty journal is an answer, not a line of it.
		default:
			lines = append(lines, line)
		}
	}
	return lines, cursor, truncated, nil
}

func firstLine(text string) string {
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return text[:index]
	}
	return text
}
