package opspec

import (
	"slices"
	"testing"
)

func TestAnOperationNamesTheModuleItLeavesStale(t *testing.T) {
	for _, c := range []struct {
		action ActionType
		want   string
	}{
		// Named after the tool on one side and after what it holds on the other.
		{ActionDockerStart, "containers"},
		{ActionNetworkLinkApply, "network"},
		{ActionLocalUserCreate, "accounts"},
		{ActionUnitEnableSet, "services"},
		{ActionMountEnsure, "storage"},
		{ActionSysctlEnsure, "kernel"},
		// A read leaves the picture exactly as it found it.
		{ActionDockerRead, ""},
		{ActionInventoryRefresh, ""},
		{ActionReadJournal, ""},
	} {
		if got := c.action.InventoryModule(); got != c.want {
			t.Errorf("%s: module = %q, want %q", c.action, got, c.want)
		}
	}
}

// Every change the fleet can be ordered to make has to name the module it makes
// older, because the alternative is a host page that answers from before the
// change for the rest of the inventory interval. The one exception is written
// down here rather than left to the map: signalling a process changes no picture
// the inventory keeps, as there is no module that holds processes.
func TestTheModuleAnOperationNamesCanBeRefreshed(t *testing.T) {
	for prefix, module := range inventoryModuleOfAction {
		if !IsInventoryModule(module) {
			t.Errorf("operations named %s.* leave %q stale, which is not a module "+
				"the panel can refresh", prefix, module)
		}
	}
}

func TestEveryChangeNamesAModuleExceptTheOnesThatChangeNoPicture(t *testing.T) {
	deliberate := []ActionType{ActionProcessSignal}
	var unmapped []ActionType
	for action := range actionSpecs {
		if action.Mutating() && action.InventoryModule() == "" && !slices.Contains(deliberate, action) {
			unmapped = append(unmapped, action)
		}
	}
	slices.Sort(unmapped)
	if len(unmapped) > 0 {
		t.Errorf("these changes name no inventory module, so the panel would keep "+
			"a picture from before them: %v", unmapped)
	}
	for _, action := range deliberate {
		if !action.Mutating() {
			t.Errorf("%s is listed as an exception but changes nothing", action)
		}
	}
}
