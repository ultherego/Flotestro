package schedules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Cron runs the command through a shell, so an argument with a
// metacharacter stops being an argument and becomes a second command. The
// basic module does not accept an arbitrary shell line.
func TestCommandRejectsShellCharacters(t *testing.T) {
	bad := [][]string{
		{"/usr/bin/backup; reboot"},
		{"/usr/bin/backup", "&&", "reboot"},
		{"/usr/bin/backup", "$(reboot)"},
		{"/usr/bin/backup", "`reboot`"},
		{"/usr/bin/backup", "file*"},
		{"/usr/bin/backup", "a\nb"},
		// The percent sign has its own meaning in cron: it ends the command.
		{"/usr/bin/date", "+%Y"},
		{},
		{""},
	}
	for _, command := range bad {
		if _, err := ComposeCommand(command); err == nil {
			t.Errorf("accepted command %v", command)
		}
	}
}

// A relative path depends on cron's PATH, which is often different from the
// operator's PATH. An entry working by hand and not from cron is the
// hardest failure to diagnose in this module.
func TestCommandRequiresAbsolutePath(t *testing.T) {
	if _, err := ComposeCommand([]string{"backup.sh"}); err == nil {
		t.Error("accepted a relative path")
	}
	result, err := ComposeCommand([]string{"/usr/local/bin/backup.sh", "--full"})
	if err != nil {
		t.Fatalf("rejected a valid command: %v", err)
	}
	if result != "/usr/local/bin/backup.sh --full" {
		t.Errorf("command = %q", result)
	}
}

// Cron skips files with names containing a dot and other special
// characters, so an entry with a bad name would silently never run.
func TestIdentifierMustBeValidFileName(t *testing.T) {
	for _, id := range []string{"", "backup.nightly", "backup nightly", "../etc/passwd", "-backup", "_backup"} {
		if ValidIdentifier(id) {
			t.Errorf("accepted identifier %q", id)
		}
	}
	// Underscore and upper-case letters are allowed by cron itself, so the
	// panel allows them too: otherwise the "e2scrub_all" entry could not be
	// taken over.
	for _, id := range []string{"backup", "backup-nightly", "b", "copy-2", "e2scrub_all", "Backup"} {
		if !ValidIdentifier(id) {
			t.Errorf("rejected identifier %q", id)
		}
	}
}

// An entry created by the panel is recognised as managed and has a stable
// identifier; an entry found on the host belongs to the host administrator.
func TestManagedEntriesAreDistinguished(t *testing.T) {
	dir := t.TempDir()
	entry := Schedule{
		ID: "nightly-backup", Expression: "0 3 * * *", Enabled: true,
		Command: []string{"/usr/local/bin/backup.sh"}, Comment: "database backup",
	}
	if err := WriteEntry(dir, entry); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A host administrator entry next to ours.
	manual := filepath.Join(dir, "cleanup")
	if err := os.WriteFile(manual, []byte("0 4 * * * root /usr/bin/find /tmp -delete\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	entries := ReadCron(filepath.Join(dir, "no-crontab"), dir, now)
	if len(entries) != 2 {
		t.Fatalf("entries = %d: %+v", len(entries), entries)
	}

	var managed, manualEntry *Schedule
	for i := range entries {
		if entries[i].Source == SourceManaged {
			managed = &entries[i]
		} else {
			manualEntry = &entries[i]
		}
	}
	if managed == nil || manualEntry == nil {
		t.Fatalf("both kinds not recognised: %+v", entries)
	}
	if managed.ID != "nightly-backup" {
		t.Errorf("managed identifier = %q", managed.ID)
	}
	if managed.NextRun == nil || managed.NextRun.Hour() != 3 {
		t.Errorf("next run = %v", managed.NextRun)
	}
	if managed.Comment != "database backup" {
		t.Errorf("comment = %q", managed.Comment)
	}
	// A found entry is often a shell line, so it stays a line: split into
	// arguments it would show something cron does not run that way.
	if manualEntry.User != "root" || manualEntry.CommandLine == "" || len(manualEntry.Command) != 0 {
		t.Errorf("manual entry = %+v", manualEntry)
	}
}

// Disabling is not removal: the content is meant to survive, and the entry
// must not have a next date, because it will not run.
func TestDisabledEntryKeepsContentWithoutDate(t *testing.T) {
	dir := t.TempDir()
	entry := Schedule{
		ID: "nightly-backup", Expression: "0 3 * * *", Enabled: false,
		Command: []string{"/usr/local/bin/backup.sh"},
	}
	if err := WriteEntry(dir, entry); err != nil {
		t.Fatal(err)
	}

	content, _ := os.ReadFile(EntryPath(dir, "nightly-backup"))
	if !strings.Contains(string(content), "/usr/local/bin/backup.sh") {
		t.Error("the entry content was lost on disabling")
	}

	entries := ReadCron("", dir, time.Now())
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Enabled {
		t.Error("a disabled entry was read as active")
	}
	if entries[0].NextRun != nil {
		t.Error("a disabled entry has a next run")
	}
}

// Removing an entry that does not exist is the target state of the
// operation, not an error.
func TestRemovingMissingEntryIsSuccess(t *testing.T) {
	if err := RemoveEntry(t.TempDir(), "no-such-thing"); err != nil {
		t.Errorf("removing a missing entry = %v", err)
	}
	if err := RemoveEntry(t.TempDir(), "../etc/passwd"); err == nil {
		t.Error("accepted an identifier with a path")
	}
}

// Environment variable assignments are not a schedule.
func TestEnvironmentAssignmentsAreNotEntries(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cleanup")
	content := "SHELL=/bin/sh\nPATH=/usr/bin:/bin\nMAILTO=root\n0 4 * * * root /usr/bin/true\n"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	entries := ReadCron("", dir, time.Now())
	if len(entries) != 1 {
		t.Fatalf("entries = %d: %+v", len(entries), entries)
	}
}

// Timers and cron are two mechanisms of the same thing: the operator wants
// to see one table of jobs, not two lists to merge in their head.
func TestTimersLandInTheSameTable(t *testing.T) {
	list := strings.Join([]string{
		"NEXT                        LEFT       LAST                        PASSED   UNIT                         ACTIVATES",
		"Sun 2026-08-23 06:00:00 UTC 5h left    Sat 2026-08-22 06:00:00 UTC 18h ago  logrotate.timer              logrotate.service",
		"-                           -          -                           -        systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service",
	}, "\n")
	units := strings.Join([]string{
		"logrotate.timer                loaded active waiting Daily rotation",
		"systemd-tmpfiles-clean.timer   loaded inactive dead  Cleanup",
	}, "\n")

	// Order as on the host: records are separated by an empty line, and
	// systemd prints TimersCalendar before Id. A timer without a calendar
	// (monotonic) has only Id in its record.
	calendars := strings.Join([]string{
		"Id=systemd-tmpfiles-clean.timer",
		"",
		"TimersCalendar={ OnCalendar=*-*-* 06:00:00 ; next_elapse=Sun 2026-08-23 06:00:00 UTC }",
		"Id=logrotate.timer",
	}, "\n")

	entries := ReadTimers(list, units, calendars)
	if len(entries) != 2 {
		t.Fatalf("timers = %d: %+v", len(entries), entries)
	}

	byID := map[string]Schedule{}
	for _, entry := range entries {
		byID[entry.ID] = entry
	}
	logrotate := byID["logrotate.timer"]
	if logrotate.Kind != KindTimer || !logrotate.Enabled {
		t.Errorf("logrotate = %+v", logrotate)
	}
	if logrotate.NextRun == nil || logrotate.NextRun.Hour() != 6 {
		t.Errorf("logrotate date = %v", logrotate.NextRun)
	}
	// A timer shows its OnCalendar, not a fixed "systemd timer" label:
	// without the expression the row does not explain where the next date
	// came from.
	if logrotate.Expression != "*-*-* 06:00:00" {
		t.Errorf("logrotate expression = %q", logrotate.Expression)
	}
	// A monotonic timer has no calendar expression and must not get
	// somebody else's: read line by line it would get exactly that.
	if byID["systemd-tmpfiles-clean.timer"].Expression != "" {
		t.Errorf("a monotonic timer got the expression %q",
			byID["systemd-tmpfiles-clean.timer"].Expression)
	}
	// A timer without a scheduled date must not get a zero date pretending
	// to be a specific moment.
	if byID["systemd-tmpfiles-clean.timer"].NextRun != nil {
		t.Error("a timer without a date got one")
	}
	if byID["systemd-tmpfiles-clean.timer"].Enabled {
		t.Error("an inactive timer was read as active")
	}
}
