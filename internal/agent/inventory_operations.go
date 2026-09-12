package agent

import (
	"context"
	"strings"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// The result codes of an inventory refresh. They are part of the contract: they
// are what tells the panel why the picture did not arrive.
const (
	// ErrorInventoryUnavailable means there is no session in which a new picture
	// could be sent back. A refresh without a receiver makes no sense.
	ErrorInventoryUnavailable = "inventory_refresh_unavailable"
	// ErrorInventoryFailed means a failed read of the host.
	ErrorInventoryFailed = "inventory_refresh_failed"
)

// refreshInventory collects the inventory on request and sends back the
// revision that came out of it.
//
// The task ends only when a new picture has really been built and sent.
// Accepting the order proves nothing on its own: the read could fail or not
// arrive, and the panel would still show the state from a quarter of an hour
// ago with the note "refreshed".
//
// Concurrent refresh requests join the collection already running instead of
// starting a second one: the host would pay twice for the same picture.
func (e *TaskExecutor) refreshInventory(ctx context.Context,
	task *agentv1.TaskEnvelope) *agentv1.TaskResult {
	if e.inventoryRefresh == nil {
		// Without a session there is nowhere to send the picture. A refusal with
		// a reason is better than a success after which nothing arrived.
		return rejected(agentv1.TaskResult_STATUS_REJECTED, ErrorInventoryUnavailable,
			"the agent has no session in which it could send the inventory back")
	}
	modules := task.GetRefreshInventory().GetModules()

	result := e.refresh(ctx, modules)
	if result.Err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, ErrorInventoryFailed,
			result.Err.Error())
	}

	description := "the inventory was refreshed"
	if len(result.Modules) > 0 {
		description += " (" + strings.Join(result.Modules, ", ") + ")"
	}
	if !result.Changed {
		// No change is a true answer and not a failure: a host that looks the
		// same looks the same.
		description += "; the picture is unchanged"
	}
	return &agentv1.TaskResult{
		Status: agentv1.TaskResult_STATUS_SUCCEEDED, ExitCode: 0, Message: description,
		InventoryRefreshResult: &agentv1.InventoryRefreshResult{
			Revision: result.Revision,
			Changed:  result.Changed,
			Modules:  result.Modules,
		},
	}
}

// refresh calls the hook of the session. A separate method, because a field and
// a method cannot share a name.
func (e *TaskExecutor) refresh(ctx context.Context, modules []string) Refresh {
	return e.inventoryRefresh(ctx, modules)
}
