package agent

import (
	"slices"
	"testing"
	"time"
)

// clock is an injected clock: the tests move it by hand instead of waiting.
type clock struct{ at time.Time }

func (c *clock) advance(d time.Duration) time.Time {
	c.at = c.at.Add(d)
	return c.at
}

// TestEveryModuleHasACadenceClass guards the table: a module added to the
// collection order without a class would silently become a static one and
// be read once a day.
func TestEveryModuleHasACadenceClass(t *testing.T) {
	for _, name := range ModuleOrder {
		if _, ok := moduleCadence[name]; !ok {
			t.Errorf("the module %s has no cadence class", name)
		}
	}
	for name := range moduleCadence {
		if !slices.Contains(ModuleOrder, name) {
			t.Errorf("the cadence table names %s, which is not a collected module", name)
		}
	}
	if ModuleCadence("something-new") != CadenceStatic {
		t.Error("an unknown module is not read as a static one")
	}
}

// TestCadenceReadsTheClassesAtTheirOwnPace: the fast modules go every cycle,
// the normal ones every fourth, the static ones never in the periodic cycle.
func TestCadenceReadsTheClassesAtTheirOwnPace(t *testing.T) {
	tick := &clock{at: time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)}
	cadence := newCadence(15*time.Minute, "host-a")
	// The window is fixed away from the test's hours, so the daily report
	// does not fall into a cycle by coincidence.
	cadence.FullHourUTC = 3
	cadence.started(tick.at)

	fast := ModulesOfCadence(CadenceFast)
	normal := ModulesOfCadence(CadenceFast, CadenceNormal)
	for cycle := 1; cycle <= 8; cycle++ {
		modules, full := cadence.due(tick.advance(15 * time.Minute))
		if full {
			t.Fatalf("cycle %d asked for the whole inventory", cycle)
		}
		want := fast
		if cycle%4 == 0 {
			want = normal
		}
		if !slices.Equal(modules, want) {
			t.Errorf("cycle %d collects %v, expected %v", cycle, modules, want)
		}
		for _, name := range modules {
			if ModuleCadence(name) == CadenceStatic {
				t.Errorf("cycle %d reads the static module %s", cycle, name)
			}
		}
	}
	if slices.Contains(fast, ModulePackages) || !slices.Contains(normal, ModulePackages) {
		t.Errorf("packages are a normal module; fast = %v, normal = %v", fast, normal)
	}
	if !slices.Contains(fast, ModuleServices) {
		t.Errorf("services are a fast module; fast = %v", fast)
	}
}

// TestCadenceSendsTheFullReportOnceADayInTheHostsHour: the full report goes
// in the hour derived from the host identifier and no more than once a day,
// even when several cycles fall into that hour.
func TestCadenceSendsTheFullReportOnceADayInTheHostsHour(t *testing.T) {
	tick := &clock{at: time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)}
	cadence := newCadence(15*time.Minute, "host-b")
	cadence.FullHourUTC = 7
	cadence.started(tick.at)

	var fullAt []time.Time
	for cycle := 0; cycle < 2*24*4; cycle++ {
		at := tick.advance(15 * time.Minute)
		if _, full := cadence.due(at); full {
			fullAt = append(fullAt, at)
		}
	}
	if len(fullAt) != 2 {
		t.Fatalf("two days gave %d full reports at %v, expected 2", len(fullAt), fullAt)
	}
	for _, at := range fullAt {
		if at.Hour() != 7 {
			t.Errorf("a full report went at %v, outside the hour 7", at)
		}
	}
	if gap := fullAt[1].Sub(fullAt[0]); gap != 24*time.Hour {
		t.Errorf("the full reports are %v apart, expected a day", gap)
	}
}

// TestCadenceDoesNotRepeatTheOpeningReport: a session that opened with a
// full report inside the window does not send another one minutes later.
func TestCadenceDoesNotRepeatTheOpeningReport(t *testing.T) {
	tick := &clock{at: time.Date(2026, 9, 14, 7, 5, 0, 0, time.UTC)}
	cadence := newCadence(15*time.Minute, "host-c")
	cadence.FullHourUTC = 7
	cadence.started(tick.at)
	for cycle := 0; cycle < 4; cycle++ {
		if _, full := cadence.due(tick.advance(15 * time.Minute)); full {
			t.Fatalf("a full report was repeated at %v, right after the opening one", tick.at)
		}
	}
}

// TestCadenceCatchesUpAMissedWindow: a host whose cycle is longer than the
// window never hits its hour; the report goes at the first cycle after it,
// and still once a day.
func TestCadenceCatchesUpAMissedWindow(t *testing.T) {
	tick := &clock{at: time.Date(2026, 9, 14, 0, 30, 0, 0, time.UTC)}
	cadence := newCadence(2*time.Hour, "host-d")
	cadence.FullHourUTC = 7
	cadence.started(tick.at)
	var fullAt []time.Time
	for cycle := 0; cycle < 24; cycle++ {
		at := tick.advance(2 * time.Hour)
		if _, full := cadence.due(at); full {
			fullAt = append(fullAt, at)
		}
	}
	if len(fullAt) != 2 {
		t.Fatalf("two days of a two-hour cycle gave %d full reports at %v, expected 2", len(fullAt), fullAt)
	}
	if fullAt[0].Hour() != 8 || fullAt[0].Minute() != 30 {
		t.Errorf("the first report went at %v, expected the first cycle after the window", fullAt[0])
	}
	if gap := fullAt[1].Sub(fullAt[0]); gap != 24*time.Hour {
		t.Errorf("the reports are %v apart, expected a day", gap)
	}
}

// TestCadenceJittersTheInterval: every wait is within ten per cent of the
// base, and the waits are not all the same.
func TestCadenceJittersTheInterval(t *testing.T) {
	cadence := newCadence(10*time.Minute, "host-e")
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		wait := cadence.next()
		if wait < 9*time.Minute || wait > 11*time.Minute {
			t.Fatalf("a wait of %v is outside the ten per cent spread", wait)
		}
		seen[wait] = true
	}
	if len(seen) < 2 {
		t.Error("the waits are all the same; the interval is not jittered")
	}
}

// TestFullReportHourSpreadsTheFleet: the hour is stable for a host and
// differs between hosts, so the fleet does not report at once.
func TestFullReportHourSpreadsTheFleet(t *testing.T) {
	if fullReportHour("host-1") != fullReportHour("host-1") {
		t.Fatal("the hour of a host is not stable")
	}
	hours := map[int]bool{}
	for i := 0; i < 200; i++ {
		hour := fullReportHour(string(rune('a'+i%26)) + string(rune('0'+i%10)) + "-host")
		if hour < 0 || hour > 23 {
			t.Fatalf("hour %d is not an hour", hour)
		}
		hours[hour] = true
	}
	if len(hours) < 12 {
		t.Errorf("two hundred hosts landed in %d hours only", len(hours))
	}
}

// TestRemoteCadenceOverridesOnlyWhatItNames: a zero field from the panel
// keeps the agent's own value.
func TestRemoteCadenceOverridesOnlyWhatItNames(t *testing.T) {
	cadence := newCadence(15*time.Minute, "host-f")
	own := cadence.FullHourUTC
	cadence.applyRemote(0, 6, nil)
	if cadence.Interval != 15*time.Minute || cadence.NormalEvery != 6 || cadence.FullHourUTC != own {
		t.Fatalf("cadence = %+v after a partial override", cadence)
	}
	hour := int32(23)
	cadence.applyRemote(600, 0, &hour)
	if cadence.Interval != 10*time.Minute || cadence.NormalEvery != 6 || cadence.FullHourUTC != 23 {
		t.Fatalf("cadence = %+v after the second override", cadence)
	}
	bad := int32(24)
	cadence.applyRemote(0, 0, &bad)
	if cadence.FullHourUTC != 23 {
		t.Fatalf("an hour that is not an hour was taken: %d", cadence.FullHourUTC)
	}
}

// TestCadenceReadsTheSlowModulesEverySixHours: the platform picture and
// the sudo policy go with the opening report, then every six hours, and
// never split from each other.
func TestCadenceReadsTheSlowModulesEverySixHours(t *testing.T) {
	tick := &clock{at: time.Date(2026, 9, 14, 8, 0, 0, 0, time.UTC)}
	cadence := newCadence(15*time.Minute, "host-g")
	// The window is fixed just before the run ends, so the daily report
	// does not fall into a cycle by coincidence.
	cadence.FullHourUTC = 7
	started := tick.at
	cadence.started(started)

	var slowAt []time.Time
	for cycle := 0; cycle < 90; cycle++ {
		at := tick.advance(15 * time.Minute)
		modules, full := cadence.due(at)
		if full {
			t.Fatalf("a full report at %v, outside the hour 7", at)
		}
		if slices.Contains(modules, ModuleSystem) != slices.Contains(modules, ModuleSudoers) {
			t.Fatalf("the slow modules were split at %v: %v", at, modules)
		}
		if slices.Contains(modules, ModuleSystem) {
			slowAt = append(slowAt, at)
		}
	}
	if len(slowAt) != 3 {
		t.Fatalf("22 hours gave %d slow reads at %v, expected 3", len(slowAt), slowAt)
	}
	// The read lands two cycles before the six hours are up, so the panel
	// never holds a picture older than six hours.
	if slowAt[0].Sub(started) != 6*time.Hour-30*time.Minute {
		t.Errorf("the first slow read went at %v, expected two cycles short of six hours after the opening report", slowAt[0])
	}
	for i := 1; i < len(slowAt); i++ {
		if gap := slowAt[i].Sub(slowAt[i-1]); gap != 6*time.Hour {
			t.Errorf("slow reads %v apart, expected six hours", gap)
		}
	}
	if ModuleCadence(ModuleSystem) != CadenceSlow || ModuleCadence(ModuleSudoers) != CadenceSlow {
		t.Error("the platform picture and the sudo policy are not slow modules")
	}
}
