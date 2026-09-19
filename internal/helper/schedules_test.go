package helper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/modules/schedules"
)

// hostWith points the helper at a host made of temporary directories: the cron
// directory, the unit directory and the marker of a running systemd, each of
// them there or not.
func hostWith(t *testing.T, cron, systemd bool) (string, string) {
	t.Helper()
	root := t.TempDir()
	previousCron, previousUnits, previousMarker := cronDir, unitDir, systemdMarker
	t.Cleanup(func() { cronDir, unitDir, systemdMarker = previousCron, previousUnits, previousMarker })

	cronDir = filepath.Join(root, "cron.d")
	unitDir = filepath.Join(root, "system")
	systemdMarker = filepath.Join(root, "run-systemd")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if cron {
		if err := os.MkdirAll(cronDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if systemd {
		if err := os.MkdirAll(systemdMarker, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return cronDir, unitDir
}

// The mechanism is a visible decision.
func TestChooseMechanismKeepsTheDecisionVisible(t *testing.T) {
	t.Run("a host with both", func(t *testing.T) {
		hostWith(t, true, true)
		for _, tc := range []struct{ kind, want string }{
			{"", schedules.KindCron},
			{schedules.KindCron, schedules.KindCron},
			{schedules.KindTimer, schedules.KindTimer},
			{schedules.KindAny, schedules.KindCron},
		} {
			mechanism, refusal := chooseMechanism(tc.kind)
			if refusal != nil {
				t.Errorf("kind %q was refused: %s", tc.kind, refusal.GetMessage())
				continue
			}
			if mechanism != tc.want {
				t.Errorf("kind %q was written as %q, want %q", tc.kind, mechanism, tc.want)
			}
		}
	})

	t.Run("a host with systemd only", func(t *testing.T) {
		cron, _ := hostWith(t, false, true)
		// An order without a kind is a cron entry, which is what every order meant
		// before timers could be written: the host says what it does not have and
		// what it does.
		mechanism, refusal := chooseMechanism("")
		if refusal == nil {
			t.Fatalf("a host without %s wrote a cron entry as %q", cron, mechanism)
		}
		if refusal.GetErrorCode() != ErrorUnsupported {
			t.Errorf("code = %q, want %q", refusal.GetErrorCode(), ErrorUnsupported)
		}
		if !strings.Contains(refusal.GetMessage(), cron) {
			t.Errorf("the refusal does not name the directory: %q", refusal.GetMessage())
		}
		if !strings.Contains(refusal.GetMessage(), "timer") {
			t.Errorf("the refusal does not say what this host can carry: %q", refusal.GetMessage())
		}
		if mechanism, refusal := chooseMechanism(schedules.KindAny); refusal != nil ||
			mechanism != schedules.KindTimer {
			t.Errorf("a free choice on a systemd host = %q, %v", mechanism, refusal)
		}
	})

	t.Run("a host without systemd", func(t *testing.T) {
		hostWith(t, true, false)
		if _, refusal := chooseMechanism(schedules.KindTimer); refusal == nil {
			t.Error("a host without systemd took an order for a managed timer")
		}
	})

	t.Run("a host with neither", func(t *testing.T) {
		hostWith(t, false, false)
		if _, refusal := chooseMechanism(schedules.KindAny); refusal == nil {
			t.Error("a host with nowhere to write took a managed entry")
		}
	})

	t.Run("a kind nobody knows", func(t *testing.T) {
		hostWith(t, true, true)
		_, refusal := chooseMechanism("anacron")
		if refusal == nil {
			t.Fatal("a mechanism the panel does not know was accepted")
		}
		if refusal.GetErrorCode() != ErrorMalformed {
			t.Errorf("code = %q, want %q", refusal.GetErrorCode(), ErrorMalformed)
		}
	})
}

// The units are staged and renamed into place, as the files module writes a
// managed file: systemd reads the directory whenever it is told to, and a file
// written in place could be read half-way - with a timer nobody ordered.
func TestWriteUnitPairPutsBothUnitsInPlace(t *testing.T) {
	_, units := hostWith(t, false, true)
	plan, err := schedules.RenderTimer(units, schedules.Schedule{
		ID: "nightly-report", Expression: "15 3 * * *",
		Command: []string{"/usr/local/bin/report"}, User: "backup", Enabled: true,
	})
	if err != nil {
		t.Fatalf("rendering the timer: %v", err)
	}
	if err := writeUnitPair(plan); err != nil {
		t.Fatalf("writing the pair: %v", err)
	}
	for _, file := range plan.Files {
		content, err := os.ReadFile(file.Path)
		if err != nil {
			t.Fatalf("reading %s: %v", file.Path, err)
		}
		if string(content) != file.Content {
			t.Errorf("%s holds something else than the plan:\n%s", file.Path, content)
		}
	}
	// Nothing is left behind: a staging file in the unit directory would be
	// read by systemd on the next reload.
	entries, err := os.ReadDir(units)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("the unit directory holds %d files, want the two units", len(entries))
	}

	// Writing the same pair again is writing the same content: the rename
	// replaces what is there instead of refusing a name it already owns.
	if err := writeUnitPair(plan); err != nil {
		t.Errorf("writing the pair a second time: %v", err)
	}
}

// systemd answers about a unit in records, and the order of the properties
// inside a record is not the order they were asked in.
func TestParseUnitFileStatesReadsWholeRecords(t *testing.T) {
	states := parseUnitFileStates("UnitFileState=enabled\nId=flotestro-a.timer\n\n" +
		"Id=flotestro-b.timer\nUnitFileState=disabled\n\n" +
		"Id=flotestro-c.timer\n")
	if states["flotestro-a.timer"] != "enabled" || states["flotestro-b.timer"] != "disabled" {
		t.Errorf("states = %v", states)
	}
	// A unit systemd could not answer for is not an enabled one, and it is
	// not a disabled one either.
	if _, known := states["flotestro-c.timer"]; known {
		t.Errorf("a unit without a state got one: %v", states)
	}
}

// The runs of a timer are computed by systemd from its calendar expression.
func TestTimerCalendarAsksSystemdInItsOwnLanguage(t *testing.T) {
	managed := schedules.Schedule{Expression: "15 3 * * *", Calendar: "*-*-* 03:15:00"}
	if got := timerCalendar(managed); got != "*-*-* 03:15:00" {
		t.Errorf("the calendar of a managed timer = %q", got)
	}
	found := schedules.Schedule{Expression: "daily"}
	if got := timerCalendar(found); got != "daily" {
		t.Errorf("the calendar of a found timer = %q", got)
	}
}
