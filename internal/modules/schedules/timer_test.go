package schedules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The entry every test in this file starts from: one job, one account, one
// expression the operator typed.
func timerEntry() Schedule {
	return Schedule{
		ID:         "nightly-report",
		Expression: "15 3 * * *",
		Command:    []string{"/usr/local/bin/report", "--weekly"},
		User:       "backup",
		Comment:    "the weekly report",
		Enabled:    true,
	}
}

// A managed timer is two files that say who wrote them, when the job runs and
// as whom.
func TestRenderTimerWritesBothUnitsWithTheMarker(t *testing.T) {
	plan, err := RenderTimer(SystemdUnitDir, timerEntry())
	if err != nil {
		t.Fatalf("rendering the timer: %v", err)
	}
	if plan.Timer.Path != "/etc/systemd/system/"+UnitPrefix+"nightly-report.timer" ||
		plan.Service.Path != "/etc/systemd/system/"+UnitPrefix+"nightly-report.service" {
		t.Fatalf("the pair goes to %q and %q", plan.Timer.Path, plan.Service.Path)
	}
	if len(plan.Files) != 2 {
		t.Fatalf("the plan has %d files, want the two units", len(plan.Files))
	}
	for _, file := range plan.Files {
		if !strings.Contains(file.Content, FileHeader) {
			t.Errorf("%s carries no marker of the panel:\n%s", file.Path, file.Content)
		}
		if !strings.Contains(file.Content, MarkerEntry+"nightly-report") {
			t.Errorf("%s does not name the entry:\n%s", file.Path, file.Content)
		}
		if !strings.Contains(file.Content, MarkerComment+"the weekly report") {
			t.Errorf("%s does not carry the comment:\n%s", file.Path, file.Content)
		}
	}
	// The timer says when, in systemd's language, and which unit it starts;
	// the service says what runs and as whom.
	if !strings.Contains(plan.Timer.Content, "OnCalendar=*-*-* 03:15:00") {
		t.Errorf("the timer does not run on the expression that was ordered:\n%s", plan.Timer.Content)
	}
	if plan.Calendar != "*-*-* 03:15:00" || plan.Expression != "15 3 * * *" {
		t.Errorf("calendar = %q, expression = %q", plan.Calendar, plan.Expression)
	}
	// The cron expression stays in the file: the entry reads back in the
	// language the operator typed it in.
	if !strings.Contains(plan.Timer.Content, MarkerCron+"15 3 * * *") {
		t.Errorf("the timer does not keep the expression it was ordered with:\n%s", plan.Timer.Content)
	}
	if !strings.Contains(plan.Timer.Content, "Unit="+UnitPrefix+"nightly-report.service") {
		t.Errorf("the timer does not name its service:\n%s", plan.Timer.Content)
	}
	if !strings.Contains(plan.Timer.Content, "WantedBy=timers.target") {
		t.Errorf("the timer cannot be enabled:\n%s", plan.Timer.Content)
	}
	if !strings.Contains(plan.Service.Content, "User=backup") {
		t.Errorf("the service does not run as the account that was ordered:\n%s", plan.Service.Content)
	}
	if !strings.Contains(plan.Service.Content, "ExecStart=/usr/local/bin/report --weekly") {
		t.Errorf("the service does not run the command:\n%s", plan.Service.Content)
	}
	if !strings.Contains(plan.Service.Content, "Type=oneshot") {
		t.Errorf("the service is not a job that ends:\n%s", plan.Service.Content)
	}
}

// The account rules of cron apply to a timer as well: an entry without an
// account is not an entry for root, a name outside the allowed set is refused,
// and so is a command that is not an argument list.
func TestRenderTimerKeepsTheRulesOfACronEntry(t *testing.T) {
	for _, bad := range []struct {
		what  string
		entry func(Schedule) Schedule
	}{
		{"no account", func(e Schedule) Schedule { e.User = ""; return e }},
		{"an account name with a space", func(e Schedule) Schedule { e.User = "root /bin/sh"; return e }},
		{"an upper-case account name", func(e Schedule) Schedule { e.User = "Root"; return e }},
		{"a shell line", func(e Schedule) Schedule { e.Command = []string{"/bin/sh", "-c", "rm -rf /; echo x"}; return e }},
		{"a relative path", func(e Schedule) Schedule { e.Command = []string{"report.sh"}; return e }},
		{"no command", func(e Schedule) Schedule { e.Command = nil; return e }},
		{"an identifier with a dot", func(e Schedule) Schedule { e.ID = "nightly.report"; return e }},
		{"no identifier", func(e Schedule) Schedule { e.ID = ""; return e }},
	} {
		if _, err := RenderTimer(SystemdUnitDir, bad.entry(timerEntry())); err == nil {
			t.Errorf("an entry with %s was rendered as a timer", bad.what)
		}
	}
}

// A comment is one line in a unit file. A newline in it would end the
// marker and start a setting the entry never meant to carry.
func TestRenderTimerFoldsTheCommentIntoOneLine(t *testing.T) {
	entry := timerEntry()
	entry.Comment = "nightly\nExecStart=/bin/sh -c reboot"
	plan, err := RenderTimer(SystemdUnitDir, entry)
	if err != nil {
		t.Fatalf("rendering the timer: %v", err)
	}
	for _, file := range plan.Files {
		for _, line := range strings.Split(file.Content, "\n") {
			if strings.HasPrefix(line, "ExecStart=/bin/sh") {
				t.Errorf("the comment became a setting in %s:\n%s", file.Path, file.Content)
			}
		}
	}
}

// Cron runs a job when the day of the month or the day of the week matches,
// systemd only when both do.
func TestCalendarFromCron(t *testing.T) {
	for _, tc := range []struct{ expression, calendar string }{
		{"15 3 * * *", "*-*-* 03:15:00"},
		{"0 0 * * *", "*-*-* 00:00:00"},
		{"@daily", "*-*-* 00:00:00"},
		{"*/30 * * * *", "*-*-* *:00,30:00"},
		{"0 4 1 * *", "*-*-01 04:00:00"},
		{"0 4 * 1 *", "*-01-* 04:00:00"},
		{"15 2 * * 1-5", "Mon,Tue,Wed,Thu,Fri *-*-* 02:15:00"},
		// Sunday has two numbers in cron and one name in systemd.
		{"0 5 * * 0", "Sun *-*-* 05:00:00"},
		{"0 5 * * 7", "Sun *-*-* 05:00:00"},
		// A day field that allows every day is not a narrowing at all.
		{"0 5 * * 0-6", "*-*-* 05:00:00"},
	} {
		calendar, err := CalendarFromCron(tc.expression)
		if err != nil {
			t.Errorf("%q: %v", tc.expression, err)
			continue
		}
		if calendar != tc.calendar {
			t.Errorf("%q became %q, want %q", tc.expression, calendar, tc.calendar)
		}
	}

	if _, err := CalendarFromCron("0 4 1 * 1"); !errors.Is(err, ErrCalendarUnsupported) {
		t.Errorf("an expression naming both days became a timer: %v", err)
	}
	if _, err := CalendarFromCron("99 * * * *"); err == nil {
		t.Error("an expression cron does not understand became a timer")
	}
}

// The plan says what would be written and what is already there.
func TestPlanTimerSeesWhatIsAlreadyOnTheHost(t *testing.T) {
	dir := t.TempDir()
	plan, err := PlanTimer(dir, timerEntry())
	if err != nil {
		t.Fatalf("planning the timer: %v", err)
	}
	if !plan.Read || plan.Present || !plan.Changed {
		t.Fatalf("plan on an empty host = %+v", plan)
	}

	for _, file := range plan.Files {
		if err := os.WriteFile(file.Path, []byte(file.Content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", file.Path, err)
		}
	}
	again, err := PlanTimer(dir, timerEntry())
	if err != nil {
		t.Fatalf("planning the timer again: %v", err)
	}
	if !again.Present || again.Changed {
		t.Errorf("the same order would write again: %+v", again)
	}

	changed := timerEntry()
	changed.Expression = "45 3 * * *"
	third, err := PlanTimer(dir, changed)
	if err != nil {
		t.Fatalf("planning the changed timer: %v", err)
	}
	if !third.Present || !third.Changed {
		t.Errorf("a changed expression would write nothing: %+v", third)
	}
}

// A unit under the name a managed timer would use, without the marker, belongs
// to the host administrator.
func TestATimerThePanelDidNotWriteIsNeverTouched(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, UnitPrefix+"nightly-report.service")
	const content = "[Unit]\nDescription=written by the host administrator\n"
	if err := os.WriteFile(foreign, []byte(content), 0o644); err != nil {
		t.Fatalf("writing the foreign unit: %v", err)
	}

	if _, err := PlanTimer(dir, timerEntry()); !errors.Is(err, ErrTimerNotManaged) {
		t.Errorf("the plan overwrites a unit of the host administrator: %v", err)
	}
	if err := RemoveTimer(dir, "nightly-report"); !errors.Is(err, ErrTimerNotManaged) {
		t.Errorf("the removal takes a unit of the host administrator: %v", err)
	}
	present, owned, path := TimerOwnership(dir, "nightly-report")
	if !present || owned || path != foreign {
		t.Errorf("ownership = present %v, owned %v, path %q", present, owned, path)
	}
	if data, err := os.ReadFile(foreign); err != nil || string(data) != content {
		t.Errorf("the foreign unit was changed: %q, %v", string(data), err)
	}
}

// The removal takes both units of our own pair, and a pair that is not
// there is the target state of a removal, not a failure.
func TestRemoveTimerTakesOurOwnPair(t *testing.T) {
	dir := t.TempDir()
	plan, err := RenderTimer(dir, timerEntry())
	if err != nil {
		t.Fatalf("rendering the timer: %v", err)
	}
	for _, file := range plan.Files {
		if err := os.WriteFile(file.Path, []byte(file.Content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", file.Path, err)
		}
	}
	if err := RemoveTimer(dir, "nightly-report"); err != nil {
		t.Fatalf("removing the timer: %v", err)
	}
	for _, file := range plan.Files {
		if _, err := os.Stat(file.Path); !os.IsNotExist(err) {
			t.Errorf("%s survived the removal: %v", file.Path, err)
		}
	}
	if err := RemoveTimer(dir, "nightly-report"); err != nil {
		t.Errorf("removing an entry that is not there: %v", err)
	}
	if err := RemoveTimer(dir, "nightly report"); err == nil {
		t.Error("an identifier that is not one reached the file system")
	}
}

// The files say which entry a unit is, what it runs and as whom; systemd says
// whether it is installed and when it fires next.
func TestReadAndMergeManagedTimers(t *testing.T) {
	dir := t.TempDir()
	plan, err := RenderTimer(dir, timerEntry())
	if err != nil {
		t.Fatalf("rendering the timer: %v", err)
	}
	for _, file := range plan.Files {
		if err := os.WriteFile(file.Path, []byte(file.Content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", file.Path, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "flotestro-foreign.timer"),
		[]byte("[Timer]\nOnCalendar=daily\n"), 0o644); err != nil {
		t.Fatalf("writing the foreign timer: %v", err)
	}

	managed := ReadManagedTimers(dir)
	if len(managed) != 1 {
		t.Fatalf("read %d managed timers, want the one the panel wrote: %+v", len(managed), managed)
	}
	entry := managed[0]
	if entry.ID != "nightly-report" || entry.Kind != KindTimer || entry.Source != SourceManaged {
		t.Errorf("entry = %+v", entry)
	}
	if entry.Expression != "15 3 * * *" || entry.Calendar != "*-*-* 03:15:00" {
		t.Errorf("expression = %q, calendar = %q", entry.Expression, entry.Calendar)
	}
	if entry.User != "backup" || entry.CommandLine != "/usr/local/bin/report --weekly" {
		t.Errorf("the service was not read back: %+v", entry)
	}
	if entry.Comment != "the weekly report" {
		t.Errorf("comment = %q", entry.Comment)
	}

	// systemd knows the same timer as a unit and says whether it is
	// installed; the found list keeps everything else the host has.
	found := []Schedule{
		{ID: UnitPrefix + "nightly-report.timer", Kind: KindTimer, Source: SourceManual, Enabled: true},
		{ID: "logrotate.timer", Kind: KindTimer, Source: SourceManual, Enabled: true},
	}
	merged := MergeManagedTimers(found, managed, map[string]string{
		UnitPrefix + "nightly-report.timer": "enabled",
	})
	if len(merged) != 2 {
		t.Fatalf("the merge kept %d entries: %+v", len(merged), merged)
	}
	if merged[0].ID != "nightly-report" || merged[0].Source != SourceManaged || !merged[0].Enabled {
		t.Errorf("the managed timer after the merge = %+v", merged[0])
	}
	if merged[1].ID != "logrotate.timer" || merged[1].Source != SourceManual {
		t.Errorf("the found timer was lost: %+v", merged[1])
	}

	// A timer systemd reports as not installed is switched off, and it stays in
	// the list: an entry that disappears when it is switched off cannot be
	// switched back on.
	off := MergeManagedTimers(found, managed, map[string]string{
		UnitPrefix + "nightly-report.timer": "disabled",
	})
	if len(off) != 2 || off[0].Enabled {
		t.Errorf("a disabled timer after the merge = %+v", off[0])
	}
}

// A managed entry writes into /etc/systemd/system, which is the directory
// systemd prefers over the one a package installs into.
func TestAUnitThatWouldShadowAnotherIsRefused(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	lib := filepath.Join(root, "usr-lib")
	for _, dir := range []string{etc, lib} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("preparing %s: %v", dir, err)
		}
	}
	shadowed := filepath.Join(lib, ServiceUnitName("nightly-report"))
	if err := os.WriteFile(shadowed, []byte("[Unit]\nDescription=the package's own unit\n"), 0o644); err != nil {
		t.Fatalf("writing the packaged unit: %v", err)
	}

	previous := unitSearchDirs
	unitSearchDirs = []string{etc, lib}
	defer func() { unitSearchDirs = previous }()

	_, err := PlanTimer(etc, timerEntry())
	if !errors.Is(err, ErrTimerNotManaged) {
		t.Fatalf("the plan would have shadowed a unit of the host: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), shadowed) {
		t.Errorf("the refusal does not name the unit it would shadow: %v", err)
	}

	// A unit of ours in the same place is not somebody else's work, so it
	// does not stop the plan.
	if err := os.WriteFile(shadowed, []byte(FileHeader+"\n"+MarkerEntry+"nightly-report\n"), 0o644); err != nil {
		t.Fatalf("rewriting the unit: %v", err)
	}
	if _, err := PlanTimer(etc, timerEntry()); err != nil {
		t.Errorf("a managed unit further down stopped the plan: %v", err)
	}
}

// The namespace of a managed entry is the protection itself: no identifier an
// operator can type reaches a unit of the product, and none reaches the
// transient unit a manual run uses either.
func TestAManagedEntryCannotReachTheProductsOwnUnits(t *testing.T) {
	for _, id := range []string{"agent", "helper", "relay", "control-plane", "schedule-nightly"} {
		for _, name := range []string{TimerUnitName(id), ServiceUnitName(id)} {
			for _, reserved := range []string{
				"flotestro-agent.service", "flotestro-helper.service", "flotestro-helper.socket",
				"flotestro-relay.service", "flotestro-control-plane.service",
				"flotestro-schedule-nightly.service",
			} {
				if name == reserved {
					t.Errorf("the entry %q writes the unit %s, which is %s", id, name, reserved)
				}
			}
		}
	}
}
