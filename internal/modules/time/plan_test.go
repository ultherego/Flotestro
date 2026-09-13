package hosttime

import (
	"strings"
	"testing"
)

func TestTimePlanDistinguishesDaemonsAndFoundState(t *testing.T) {
	chrony := Snapshot{Service: DaemonChrony,
		ManagedPath: "/etc/chrony/sources.d/flotestro.sources"}
	plan := Compute(chrony, []string{"192.168.56.50"}, false)
	if plan.Action != PlanUpdate || plan.Restart || plan.Refusal != "" {
		t.Errorf("chrony with a sources directory: %+v", plan)
	}
	if !strings.Contains(strings.Join(plan.Changes, ";"), "without a daemon restart") {
		t.Errorf("chrony changes: %v", plan.Changes)
	}

	chrony.Managed, _ = ComposeChrony([]string{"192.168.56.50"}, KindSources)
	chrony.Configured = []Server{{Address: "192.168.56.50", Managed: true}}
	none := Compute(chrony, []string{"192.168.56.50"}, false)
	if none.Action != PlanNoChange || len(none.Changes) != 0 {
		t.Errorf("target state counted as a change: %+v", none)
	}

	timesyncd := Snapshot{Service: DaemonTimesyncd}
	ts := Compute(timesyncd, []string{"192.168.56.50"}, false)
	if ts.Action != PlanUpdate || !ts.Restart || ts.ManagedPath != TimesyncdFile {
		t.Errorf("timesyncd: %+v", ts)
	}
	if plan.PlanHash == ts.PlanHash || plan.PlanHash == none.PlanHash {
		t.Error("plan fingerprints do not differ")
	}
}

func TestTimePlanRefusesWithoutDirectoryAndWithoutDaemon(t *testing.T) {
	noDir := Snapshot{Service: DaemonChrony, ConfigPath: "/etc/chrony/chrony.conf",
		CanAddSourceDir: true, WriteReason: "chrony includes no directory"}
	refused := Compute(noDir, []string{"192.168.56.50"}, false)
	if refused.Refusal != "chrony includes no directory" {
		t.Errorf("no directory without a refusal: %+v", refused)
	}
	consent := Compute(noDir, []string{"192.168.56.50"}, true)
	if consent.Refusal != "" || !consent.EnablesSourceDir || !consent.Restart {
		t.Errorf("consent to the directory: %+v", consent)
	}
	noDaemon := Compute(Snapshot{}, []string{"192.168.56.50"}, false)
	if !strings.Contains(noDaemon.Refusal, "time daemon") {
		t.Errorf("no daemon without a refusal: %+v", noDaemon)
	}
	if empty := Compute(noDir, nil, true); empty.Refusal == "" {
		t.Error("an empty server list passed without a refusal")
	}
}
