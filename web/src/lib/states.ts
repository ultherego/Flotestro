/**
 * The words the panel uses for the states the server names.
 *
 * It lived in the panel being replaced, which drew pills around it; the
 * words themselves belong to neither panel, so they are here where both
 * could reach them and where the one that is left still can.
 */

/**
 * The states come from the database as contract identifiers and looked like
 * that in the interface: "awaiting_approval" or "partially_applied".
 */
export function stateName(state: string): string {
  const names: Record<string, string> = {
    online: "online", offline: "offline", stale: "stale", unknown: "unknown",
    queued: "queued", planned: "planned", leased: "assigned",
    dispatched: "dispatched", running: "running",
    cancel_requested: "cancel requested",
    awaiting_approval: "awaiting approval",
    // The campaign computes a plan on every host; it changes nothing yet.
    planning: "planning per host",
    // The host is ready, but the fleet or the site has no capacity now.
    awaiting_budget: "waiting for capacity",
    // The host will not carry out this operation: it lacks the adapter or
    // does not meet the condition.
    ineligible: "cannot run this",
    // The agent holds the task and waits for a resource of the host.
    awaiting_lock: "waiting for a lock",
    succeeded: "succeeded", failed: "failed", timed_out: "timed out",
    // A success without a mutation, and an end without a result.
    no_change: "no change",
    canceled: "canceled", cancelled: "canceled", canceling: "canceling", expired: "expired",
    completed_with_issues: "completed with issues", plan_failed: "planning failed",
    lease_expired: "lease expired", superseded_by_result: "superseded",
    rejected: "rejected", replayed: "replayed",
    active: "active", paused: "paused", pausing: "pausing", completed: "completed",
    partially_applied: "partially applied",
    denied: "denied", success: "success", failure: "failure",
  };
  return names[state] ?? state;
}
