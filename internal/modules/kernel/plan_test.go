package kernel

import (
	"strings"
	"testing"
)

func TestBlacklistPlanDistinguishesCurrentState(t *testing.T) {
	state := Snapshot{
		Modules:   []Module{{Name: "pcspkr", UsedBy: []string{"snd"}}},
		Blacklist: []string{"floppy"},
		Managed:   "# file\nblacklist floppy\n",
	}
	created := PlanBlacklist(state, "pcspkr", true)
	if created.Action != PlanCreate || !created.Loaded || created.Blacklisted || len(created.Changes) != 3 {
		t.Errorf("block of a loaded module: %+v", created)
	}
	if !strings.Contains(created.Changes[1], "after a reboot") || !strings.Contains(created.Changes[2], "snd") {
		t.Errorf("changes without warnings: %v", created.Changes)
	}
	existing := PlanBlacklist(state, "floppy", true)
	if existing.Action != PlanNoChange || !existing.Blacklisted {
		t.Errorf("block already present: %+v", existing)
	}
	removed := PlanBlacklist(state, "floppy", false)
	if removed.Action != PlanRemove {
		t.Errorf("block removal: %+v", removed)
	}
	if created.PlanHash == existing.PlanHash || existing.PlanHash == removed.PlanHash || created.ManagedHash == "" {
		t.Error("plan fingerprints do not differ or the file fingerprint is missing")
	}
}

func TestBlacklistPlanRefusesProtectedModule(t *testing.T) {
	plan := PlanBlacklist(Snapshot{}, "ext4", true)
	if !strings.Contains(plan.Refusal, "does not block") || plan.PlanHash == "" {
		t.Errorf("protected module without a refusal: %+v", plan)
	}
	if bad := PlanBlacklist(Snapshot{}, "../x", true); bad.Refusal == "" {
		t.Error("a bad name passed without a refusal")
	}
}
