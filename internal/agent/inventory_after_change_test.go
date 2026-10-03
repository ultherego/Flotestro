package agent

import (
	"slices"
	"testing"

	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// The names of the modules live in two packages: the panel's refresh scope is in
// opspec, and the collector that answers it is here. A name that exists on one
// side only orders a collection of nothing, silently, and the host page then
// stays as stale as it was before the order existed.
func TestEveryModuleThePanelCanRefreshIsOneTheAgentCanCollect(t *testing.T) {
	for _, module := range opspec.InventoryModules {
		if _, known := moduleCollectors[module]; !known {
			t.Errorf("an operation names the inventory module %q, which no collector knows", module)
		}
		if !slices.Contains(ModuleOrder, module) {
			t.Errorf("an operation names the inventory module %q, which is outside "+
				"the collection order", module)
		}
	}
}

func TestTheModuleIsCollectedHoweverTheChangeEnded(t *testing.T) {
	// The task's own verdict says nothing about whether the host moved. A change
	// that was made and could not be read back ends FAILED with
	// applied_unverified; a transaction that broke halfway ends FAILED over a host
	// it already changed; a change rolled back is a second change. All of them
	// leave the panel holding a picture it has to stop believing.
	for _, name := range []string{"succeeded", "applied_unverified", "failed halfway", "rolled back"} {
		t.Run(name, func(t *testing.T) {
			var ordered []string
			executor := &TaskExecutor{inventoryStale: func(modules []string) {
				ordered = append(ordered, modules...)
			}}
			executor.inventoryBehindTheHost(opspec.ActionNetworkLinkApply)
			if want := []string{"network"}; !slices.Equal(ordered, want) {
				t.Errorf("collected %v, want %v", ordered, want)
			}
		})
	}
}

func TestAnOperationThatChangesNoPictureCollectsNothing(t *testing.T) {
	for _, action := range []opspec.ActionType{
		// A read moves nothing.
		opspec.ActionDockerRead,
		// The refresh is itself an operation on the inventory; ordering another
		// one from its own result would never end.
		opspec.ActionInventoryRefresh,
		opspec.ActionReadJournal,
		// A change the inventory keeps no picture of.
		opspec.ActionProcessSignal,
	} {
		var ordered []string
		executor := &TaskExecutor{inventoryStale: func(modules []string) {
			ordered = append(ordered, modules...)
		}}
		executor.inventoryBehindTheHost(action)
		if len(ordered) != 0 {
			t.Errorf("%s collected %v", action, ordered)
		}
	}
}

// Without a session there is no collector, and the answer of the task still has
// to come back.
func TestAChangeWithoutASessionIsStillAnswered(t *testing.T) {
	executor := &TaskExecutor{}
	executor.inventoryBehindTheHost(opspec.ActionNetworkLinkApply)
}

// Every package adapter has to be able to answer the question the verifier of a
// repair asks. Only apt can name the packages waiting for their configuration -
// that is a notion of dpkg - and asking only for that left the others answering
// nothing, so a repair on Arch ended applied_unverified however well it had gone.
func TestEveryPackageAdapterCanAnswerAboutItsDatabase(t *testing.T) {
	for _, manager := range []any{&packages.APT{}, &packages.DNF{}, &packages.Pacman{}} {
		_, attention := manager.(attentionReader)
		_, database := manager.(databaseReader)
		if !attention && !database {
			t.Errorf("%T can say nothing about its database, so a repair on that host "+
				"cannot be verified", manager)
		}
	}
}
