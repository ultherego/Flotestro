package opspec

// The guide to error codes.
//
// A code answers two questions: what happened and what can safely be done
// next. The message is for people; the code is for policy and automation,
// so it never carries a hostname, a path or a package name - those are in
// the structured detail. Whether a retry helps is a decision of the server
// derived from the class of the error and the stage it happened at, never
// from matching the message.

// RetryPolicy says whether repeating the same thing can succeed.
type RetryPolicy string

const (
	// RetryNever: the same order will fail the same way; a decision is needed.
	RetryNever RetryPolicy = "never"
	// RetryAutomatic: the system repeats on its own, e.g. once capacity frees up.
	RetryAutomatic RetryPolicy = "automatic"
	// RetryAfterChange: a retry makes sense once the named thing changed.
	RetryAfterChange RetryPolicy = "after_change"
	// RetryAfterReplan: the plan has to be computed again and approved again.
	RetryAfterReplan RetryPolicy = "after_replan"
	// RetryReadState: read the state of the host first; never repeat a
	// destructive step blind.
	RetryReadState RetryPolicy = "read_state"
)

// ErrorGuide describes one code.
type ErrorGuide struct {
	Code string `json:"code"`
	// Stage is where the code arises: materialize, preflight, planning,
	// admission, dispatch, agent, helper, verify, reconcile, approval.
	Stage string      `json:"stage"`
	Retry RetryPolicy `json:"retry"`
	// What happened, in one sentence.
	Meaning string `json:"meaning"`
	// What the operator does next.
	Action string `json:"action"`
	// CountsAsFailure says whether the code raises the failure rate of a
	// campaign. An excluded or skipped host is visible but not a failure.
	CountsAsFailure bool `json:"counts_as_failure"`
}

// ErrorGuides lists every code the campaign machinery, the agent and the
// helper can put on a target or an attempt.
func ErrorGuides() []ErrorGuide {
	return errorGuides
}

// ErrorGuideFor returns the guide for a code. An unknown code gets an empty
// guide: the panel shows the code as it came rather than inventing advice.
func ErrorGuideFor(code string) (ErrorGuide, bool) {
	for _, guide := range errorGuides {
		if guide.Code == code {
			return guide, true
		}
	}
	return ErrorGuide{}, false
}

var errorGuides = []ErrorGuide{
	// Materialize and eligibility.
	{Code: "campaign_mode_unsupported", Stage: "planning", Retry: RetryNever,
		Meaning: "The operation has no bulk mode in the registry.",
		Action:  "Run it host by host, or deploy an adapter that declares a campaign mode."},
	{Code: "not_a_campaign_action", Stage: "planning", Retry: RetryNever,
		Meaning: "The operation is excluded from campaigns on purpose.",
		Action:  "Run it host by host with an operator present."},
	{Code: "selector_too_broad", Stage: "materialize", Retry: RetryAfterChange,
		Meaning: "The selector names more hosts than one campaign may carry.",
		Action:  "Narrow the selector or split the change into several campaigns."},
	{Code: "capability_missing", Stage: "preflight", Retry: RetryAfterChange,
		Meaning: "The host has no adapter for this operation.",
		Action:  "Exclude the host or install what the adapter needs; not a failure."},
	{Code: "capability_unknown", Stage: "preflight", Retry: RetryAfterChange,
		Meaning: "The host has not reported its adapters yet.",
		Action:  "Wait for the host to connect and report; not a failure."},
	{Code: "maintenance", Stage: "dispatch", Retry: RetryAfterChange,
		Meaning: "The host is in a maintenance window and was skipped.",
		Action:  "Run again after the window; not a failure."},
	{Code: "quarantined", Stage: "preflight", Retry: RetryAfterChange,
		Meaning: "The host is quarantined and takes no operations.",
		Action:  "Release the quarantine first."},
	{Code: "recovery", Stage: "preflight", Retry: RetryAfterChange,
		Meaning: "The host is recovering its identity and takes no operations until the new certificate connects.",
		Action:  "Finish the recovery on the host; the state ends by itself with the first session of the new key. Not a failure."},
	{Code: "retiring", Stage: "preflight", Retry: RetryNever,
		Meaning: "The host is being decommissioned and takes no operations.",
		Action:  "Nothing; the host is leaving the fleet. Not a failure."},
	{Code: "retired", Stage: "preflight", Retry: RetryNever,
		Meaning: "The host is retired and takes no operations.",
		Action:  "Nothing; a retired host does not come back. Enroll the machine as a new host once its retention has passed. Not a failure."},
	{Code: "out_of_scope", Stage: "preflight", Retry: RetryNever,
		Meaning: "The host lies outside the operator's scope.",
		Action:  "Ask somebody with the scope, or narrow the selector."},
	{Code: "excluded", Stage: "materialize", Retry: RetryNever,
		Meaning: "The operator left the host out of this campaign by name, with a reason.",
		Action:  "Nothing; order another campaign without the exclusion if the host is meant to change. Not a failure."},
	{Code: "conflict", Stage: "preflight", Retry: RetryAutomatic,
		Meaning: "Another campaign already works on this host.",
		Action:  "Nothing; the host waits for the other campaign's lock."},
	{Code: "offline", Stage: "dispatch", Retry: RetryAfterChange,
		Meaning: "The host was not connected when its turn came.",
		Action:  "Under require_online the host was skipped: bring it back and order again. Under a waiting policy it starts by itself when it comes back before the deadline. Not a failure."},
	{Code: "skipped_offline", Stage: "dispatch", Retry: RetryAfterChange,
		Meaning: "The host was not connected and the campaign's policy leaves such a host out.",
		Action:  "Nothing, or order again once the host is back. Not a failure."},
	{Code: "offline_deadline", Stage: "dispatch", Retry: RetryAfterChange,
		Meaning: "The host stayed disconnected until the campaign's deadline passed.",
		Action:  "Order again once the host is back; the campaign no longer waits for it. Not a failure."},
	{Code: "plan_changed_offline", Stage: "planning", Retry: RetryAfterReplan,
		Meaning: "The host came back with a state that gives a different plan than the one approved.",
		Action:  "Read the new plan and order a campaign that approves it; the consent covered the old one. Not a failure."},
	{Code: "offline_policy_loosened", Stage: "planning", Retry: RetryNever,
		Meaning: "The request asked for a weaker offline policy than the operation declares.",
		Action:  "Keep the operation's policy or tighten it; it may not be loosened."},
	{Code: "host_unavailable", Stage: "dispatch", Retry: RetryAfterChange,
		Meaning: "The host record could not be read when its turn came.",
		Action:  "Check the host; it was skipped."},
	{Code: "incomplete_coverage", Stage: "materialize", Retry: RetryAfterChange,
		Meaning: "An operation that must reach the whole fleet has hosts it cannot reach.",
		Action:  "Bring every host back or verify it, then order again."},

	// Planning.
	{Code: "plan_refused", Stage: "planning", Retry: RetryNever,
		Meaning: "The host computed the plan and refused the change with a reason.",
		Action:  "Read the reason; the host will not take this change as it is."},
	{Code: "plan_failed", Stage: "planning", Retry: RetryAfterChange,
		Meaning: "The planning operation failed on the host.",
		Action:  "Look at the plan job; fix the host and plan again."},
	{Code: "plan_hash_missing", Stage: "planning", Retry: RetryAfterChange,
		Meaning: "The host gave no plan digest, so nothing can be approved.",
		Action:  "Update the agent; a plan without a digest cannot be bound to a consent."},
	{Code: "plan_create_failed", Stage: "planning", Retry: RetryAfterChange,
		Meaning: "The planning job could not be created.",
		Action:  "Check the panel log and order again."},
	{Code: "plan_stale", Stage: "dispatch", Retry: RetryAfterReplan,
		Meaning: "The state of the host moved after the plan was computed.",
		Action:  "Compute the plans again and approve the new set."},
	{Code: "approval_stale", Stage: "approval", Retry: RetryNever,
		Meaning: "The campaign changed since the consent was given.",
		Action:  "Read the current plans and approve again."},
	{Code: "fingerprint_mismatch", Stage: "approval", Retry: RetryNever,
		Meaning: "The approval carried a fingerprint of something else.",
		Action:  "Reload the campaign and approve what is on screen."},
	{Code: "reauthentication_required", Stage: "approval", Retry: RetryAfterChange,
		Meaning: "The operation needs a fresh authentication.",
		Action:  "Sign in again with the required level and repeat."},

	// Admission.
	{Code: "budget_capacity", Stage: "admission", Retry: RetryAutomatic,
		Meaning: "The named budget has no free token.",
		Action:  "Nothing; the host starts when a token frees up. Raise the budget if it should not wait."},
	{Code: "budget_fair_share", Stage: "admission", Retry: RetryAutomatic,
		Meaning: "This campaign already holds its share of the budget.",
		Action:  "Nothing; it is promoted by age. Raise the budget if it should not wait."},

	// Execution on the host.
	{Code: "resource_busy", Stage: "agent", Retry: RetryAutomatic,
		Meaning: "Another operation holds the resource on the host.",
		Action:  "Look at the blocker; the operation waits until its deadline.", CountsAsFailure: true},
	{Code: "precondition_failed", Stage: "helper", Retry: RetryAfterReplan,
		Meaning: "The host checked the plan against its state just before the change and refused.",
		Action:  "Do not repeat the old plan; compute it again.", CountsAsFailure: true},
	{Code: "payload_hash_mismatch", Stage: "dispatch", Retry: RetryAfterReplan,
		Meaning: "The payload delivered differs from the one approved.",
		Action:  "Order again; if it repeats, the panel and the agent disagree on the contract.", CountsAsFailure: true},
	{Code: "preflight_failed", Stage: "agent", Retry: RetryAfterChange,
		Meaning: "A precondition of the operation does not hold on the host.",
		Action:  "Read the checks in the result and fix the host.", CountsAsFailure: true},
	{Code: "packages_still_blocked", Stage: "agent", Retry: RetryAfterChange,
		Meaning: "The package database is still blocked after the repair.",
		Action:  "Repair the package database by hand on the host.", CountsAsFailure: true},
	{Code: "helper_unavailable", Stage: "agent", Retry: RetryAutomatic,
		Meaning: "The root helper did not answer.",
		Action:  "Check flotestro-helper.socket on the host; the attempt is repeated.", CountsAsFailure: true},
	{Code: "secret_unavailable", Stage: "dispatch", Retry: RetryAutomatic,
		Meaning: "The secret the operation needs could not be issued.",
		Action:  "Fix the secret store; the attempt is repeated until the deadline.", CountsAsFailure: true},
	{Code: "lease_expired", Stage: "reconcile", Retry: RetryReadState,
		Meaning: "No result arrived within the lease; the outcome on the host is unknown.",
		Action:  "Read the state of the host; do not repeat a destructive step blind.", CountsAsFailure: true},
	{Code: "timeout", Stage: "agent", Retry: RetryReadState,
		Meaning: "The operation exceeded its time limit on the host.",
		Action:  "Read the state of the host before repeating.", CountsAsFailure: true},
	{Code: "exec_failed", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The tool the helper ran ended with an error.",
		Action:  "Read the output in the attempt; fix the host.", CountsAsFailure: true},
	{Code: "unit_unhealthy", Stage: "verify", Retry: RetryAfterChange,
		Meaning: "After the change a unit is not active.",
		Action:  "Look at the unit on the host; pause the campaign if it repeats.", CountsAsFailure: true},
	{Code: "health_check_failed", Stage: "verify", Retry: RetryAfterChange,
		Meaning: "The post-change check of the host failed.",
		Action:  "Inspect the host; the campaign pauses at the threshold.", CountsAsFailure: true},
	{Code: "reboot_timeout", Stage: "verify", Retry: RetryReadState,
		Meaning: "The host did not come back with a new boot ID in time.",
		Action:  "Check the host out of band; it may be up without the agent.", CountsAsFailure: true},
	{Code: "reboot_failed", Stage: "verify", Retry: RetryReadState,
		Meaning: "The reboot operation failed on the host.",
		Action:  "Check the host out of band.", CountsAsFailure: true},
	{Code: "job_create_failed", Stage: "dispatch", Retry: RetryAfterChange,
		Meaning: "The operation for the host could not be created.",
		Action:  "Check the panel log; order again.", CountsAsFailure: true},
	{Code: "reboot_create_failed", Stage: "dispatch", Retry: RetryAfterChange,
		Meaning: "The reboot operation for the host could not be created.",
		Action:  "Check the panel log; reboot the host by hand if needed.", CountsAsFailure: true},
	{Code: "health_create_failed", Stage: "dispatch", Retry: RetryAfterChange,
		Meaning: "The post-change check could not be created.",
		Action:  "Check the panel log; verify the host by hand.", CountsAsFailure: true},
	{Code: "unsupported", Stage: "helper", Retry: RetryNever,
		Meaning: "The host does not support this operation.",
		Action:  "Exclude the host or change the operation.", CountsAsFailure: true},
	{Code: "hostname_conflict", Stage: "agent", Retry: RetryAfterChange,
		Meaning: "The new hostname resolves in DNS to an address that is not this host's.",
		Action:  "Fix the DNS record or pick another name; the host was not renamed.", CountsAsFailure: true},
	{Code: "protected_account", Stage: "helper", Retry: RetryNever,
		Meaning: "The account belongs to the system or to the agent and is not changed through the panel.",
		Action:  "Pick another account; system accounts belong to the packages that created them.", CountsAsFailure: true},
	{Code: "unknown_action", Stage: "agent", Retry: RetryAfterChange,
		Meaning: "The agent does not know this operation.",
		Action:  "Update the agent on the host.", CountsAsFailure: true},
	{Code: "host_retiring", Stage: "agent", Retry: RetryNever,
		Meaning: "The task reached the host after its final task: the host is leaving the fleet and started nothing new.",
		Action:  "Nothing; the operation was cut off by the decommission. Order it on another host if it is still wanted."},
	{Code: "remote_cleanup_unconfirmed", Stage: "reconcile", Retry: RetryReadState,
		Meaning: "The host was retired without confirming it stopped: it had no session, or did not answer the final task in time. Its identity files may still be on its disk.",
		Action:  "Wipe the machine out of band, or check it before it is handed over; the certificates are revoked, so it cannot come back."},
	{Code: "malformed_request", Stage: "helper", Retry: RetryNever,
		Meaning: "The helper rejected the shape of the request.",
		Action:  "The panel and the helper disagree on the contract; update both.", CountsAsFailure: true},
	{Code: "expired", Stage: "dispatch", Retry: RetryNever,
		Meaning: "The operation was not delivered within its time to live.",
		Action:  "Order again once the host is reachable.", CountsAsFailure: true},
	{Code: "canceled", Stage: "dispatch", Retry: RetryNever,
		Meaning: "The operation was cancelled before it ran.",
		Action:  "Nothing; order again if it is still wanted."},
	{Code: "rolled_back", Stage: "verify", Retry: RetryAfterReplan,
		Meaning: "The host undid the change itself because the connectivity check failed.",
		Action:  "Fix the plan; the host is on its previous configuration.", CountsAsFailure: true},
}
