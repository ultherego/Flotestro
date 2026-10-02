package agent

import (
	"slices"
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
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

func TestAChangeThatSucceededLeavesItsModuleStale(t *testing.T) {
	for _, c := range []struct {
		name   string
		action opspec.ActionType
		status agentv1.TaskResult_Status
		want   []string
	}{
		{"a change that succeeded", opspec.ActionNetworkLinkApply,
			agentv1.TaskResult_STATUS_SUCCEEDED, []string{"network"}},
		// A change that did not happen leaves the host as the panel believes it
		// to be, so there is nothing to collect again.
		{"a change that failed", opspec.ActionNetworkLinkApply,
			agentv1.TaskResult_STATUS_FAILED, nil},
		{"a change that was refused", opspec.ActionNetworkLinkApply,
			agentv1.TaskResult_STATUS_REJECTED, nil},
		{"a read", opspec.ActionDockerRead,
			agentv1.TaskResult_STATUS_SUCCEEDED, nil},
		// The refresh is itself an operation on the inventory; ordering another
		// one from its own result would never end.
		{"a refresh", opspec.ActionInventoryRefresh,
			agentv1.TaskResult_STATUS_SUCCEEDED, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			var ordered []string
			executor := &TaskExecutor{inventoryStale: func(modules []string) {
				ordered = append(ordered, modules...)
			}}
			executor.inventoryBehindTheHost(c.action, &agentv1.TaskResult{Status: c.status})
			if !slices.Equal(ordered, c.want) {
				t.Errorf("collected %v, want %v", ordered, c.want)
			}
		})
	}
}

// Without a session there is no collector, and the answer of the task still has
// to come back.
func TestAChangeWithoutASessionIsStillAnswered(t *testing.T) {
	executor := &TaskExecutor{}
	executor.inventoryBehindTheHost(opspec.ActionNetworkLinkApply,
		&agentv1.TaskResult{Status: agentv1.TaskResult_STATUS_SUCCEEDED})
}
