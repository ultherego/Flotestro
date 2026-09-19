package opspec

import "errors"

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
	// admission, dispatch, agent, helper, verify, reconcile, approval,
	// cancel, startup for the states the panel refuses to start in,
	// notification for the dead letters of the notification queue,
	// directory for the phases of a change the control plane carries out
	// in the directory, or monitoring for the machinery behind the charts
	// and the alert rules.
	Stage string      `json:"stage"`
	Retry RetryPolicy `json:"retry"`
	// What happened, in one sentence.
	Meaning string `json:"meaning"`
	// What the operator does next.
	Action string `json:"action"`
	// CountsAsFailure says whether the code raises the failure rate of a
	// campaign. An excluded or skipped host is visible but not a failure.
	CountsAsFailure bool `json:"counts_as_failure"`
	// Alias is the code the panel really puts on a job or a target when
	// this entry is one of the names the campaigns document uses for the
	// same condition. The document's name stays searchable in the guide
	// ("also reported as ..."), and a screen looking up a code from the
	// document lands on the same advice as one looking up the reported
	// code; a plain entry has no alias.
	Alias string `json:"alias,omitempty"`
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

// errorGuides is the guide as served: the codes the machinery reports,
// followed by the names of the campaigns document that stand for one of
// them. The aliases are derived at start from the entries they point at,
// so the two can never say different things about the same condition.
var errorGuides = withAliases(reportedGuides, documentAliases)

// documentAlias is a name the campaigns document (chapter 51) gives a
// condition the panel reports under another code. Meaning says, in the
// document's terms, which reported codes it stands for; the stage, the
// retry policy, the action and the failure count come from the reported
// code.
type documentAlias struct {
	code, reportedAs, meaning string
}

var documentAliases = []documentAlias{
	{code: "verification_failed", reportedAs: "health_check_failed",
		meaning: "The post-change verification of the host failed: the panel reports it as health_check_failed for a failed check and as unit_unhealthy for a unit that is not active after the change."},
	{code: "connectivity_rollback", reportedAs: "rolled_back",
		meaning: "The host's connectivity watchdog undid the change on its own because the management channel did not come back; the panel reports it as rolled_back."},
	{code: "target_limit_policy", reportedAs: "selector_too_broad",
		meaning: "The selector names more hosts than the policy lets one campaign carry; the panel reports it as selector_too_broad."},
}

// withAliases appends the document's names to the guide. An alias whose
// reported code is not in the guide is a mistake in this file and fails
// at start rather than serving advice about nothing.
func withAliases(guides []ErrorGuide, aliases []documentAlias) []ErrorGuide {
	result := make([]ErrorGuide, 0, len(guides)+len(aliases))
	result = append(result, guides...)
	for _, alias := range aliases {
		var target *ErrorGuide
		for i := range guides {
			if guides[i].Code == alias.reportedAs {
				target = &guides[i]
				break
			}
		}
		if target == nil {
			panic("opspec: the error code " + alias.code + " is an alias of " + alias.reportedAs + ", which the guide does not list")
		}
		result = append(result, ErrorGuide{
			Code: alias.code, Alias: alias.reportedAs,
			Stage: target.Stage, Retry: target.Retry,
			Meaning: alias.meaning, Action: target.Action,
			CountsAsFailure: target.CountsAsFailure,
		})
	}
	return result
}

var reportedGuides = []ErrorGuide{
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
	{Code: RefusalProtocolIncompatible, Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The target agent release speaks a protocol this panel does not.",
		Action:  "Upgrade the panel first, or pick a release the panel can talk to."},
	{Code: "capability_missing", Stage: "preflight", Retry: RetryAfterChange,
		Meaning: "The host has no adapter for this operation.",
		Action:  "Exclude the host or install what the adapter needs; not a failure."},
	{Code: "capability_unknown", Stage: "preflight", Retry: RetryAfterChange,
		Meaning: "The host has not reported its adapters yet.",
		Action:  "Wait for the host to connect and report; not a failure."},
	{Code: "inventory_stale", Stage: "preflight", Retry: RetryAfterChange,
		Meaning: "The module a policy or a campaign judges the host from was read more than twice its cadence ago; a verdict on it would describe a host that has been silent, not the host as it is.",
		Action:  "Refresh the named module - order its read, or find out why the host stopped reporting; until then the verdict is unknown. Not a failure."},
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
	{Code: "dispatch_ambiguous", Stage: "dispatch", Retry: RetryAutomatic,
		Meaning: "When its turn came the host had a session open on more than one gateway, so the panel could not tell which one carries the task; it went back to the queue untouched.",
		Action:  "Nothing; the next pass finds one session. If it repeats, read the agent journal on the host - it is reconnecting in a loop - and check that the gateways see the same database. Not a failure."},
	{Code: "session_stale", Stage: "dispatch", Retry: RetryAutomatic,
		Meaning: "The task was sent over a session the host had already left for another gateway; the delivery was not recorded and the task went back to the queue.",
		Action:  "Nothing; the next pass delivers over the host's current session. If it repeats, the host is switching gateways in a loop - read the agent journal on the host. Not a failure."},
	{Code: "session_unowned", Stage: "dispatch", Retry: RetryAutomatic,
		Meaning: "When its turn came the host had no live owner: no session had claimed it, or the claim's lease had run out; the task stayed in the queue and was not marked delivered.",
		Action:  "Nothing; the host's next session claims it and the next pass delivers. If it repeats for a connected host, the panel instance holding its session is not renewing its claims - check that instance's database access. Not a failure."},
	{Code: "session_fence_stale", Stage: "dispatch", Retry: RetryAutomatic,
		Meaning: "The panel instance that wrote this no longer owns the host's session: a newer session claimed the host with a higher fencing token, and the database refused the delivery or the result written under the older one; the write was refused and the newer instance carries on.",
		Action:  "Nothing; the owner delivers the task again or settles it from the host's replay. A refused delivery goes back to the queue; a refused result is on the trail as not applied. If it repeats on one instance, that instance keeps streams it no longer owns - restart it. Not a failure."},
	{Code: "targets_invalid", Stage: "materialize", Retry: RetryNever,
		Meaning: "The explicit host list of the order names a host it cannot carry; the answer names each one with its reason: unknown_host, out_of_scope, excluded_and_listed or invalid_host_id.",
		Action:  "Take the named hosts out of the list, or ask for the right over their site; the list is never trimmed quietly."},
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
		Meaning: "Another operation holds the resource on the host. The same operation delivered again is not refused: the host reports it as still in progress.",
		Action:  "Look at the blocker; the operation waits until its deadline.", CountsAsFailure: true},
	{Code: "precondition_failed", Stage: "helper", Retry: RetryAfterReplan,
		Meaning: "The host checked the plan against its state just before the change and refused.",
		Action:  "Do not repeat the old plan; compute it again.", CountsAsFailure: true},
	{Code: "precondition_changed", Stage: "agent", Retry: RetryAfterReplan,
		Meaning: "The preconditions held when the task was accepted and no longer did once it had waited for a resource of the host: the host rebooted or changed under the plan while another operation held the lock.",
		Action:  "Do not repeat the old plan; compute it again on the host as it is now.", CountsAsFailure: true},
	{Code: "payload_hash_mismatch", Stage: "dispatch", Retry: RetryAfterReplan,
		Meaning: "The payload delivered differs from the one approved.",
		Action:  "Order again; if it repeats, the panel and the agent disagree on the contract.", CountsAsFailure: true},
	{Code: "preflight_failed", Stage: "agent", Retry: RetryAfterChange,
		Meaning: "A precondition of the operation does not hold on the host.",
		Action:  "Read the checks in the result and fix the host.", CountsAsFailure: true},
	{Code: "missing_credential", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The join reached the host without its one-time password: the panel had no directory connector to fetch one from.",
		Action:  "Configure the directory connector of the panel and order again.", CountsAsFailure: true},
	{Code: "enroll_failed", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "ipa-client-install did not join the host; the preflight had passed, so the cause is in the directory's answer.",
		Action:  "Read the tool's output in the attempt; a spent or expired one-time password is refreshed by ordering again.", CountsAsFailure: true},
	{Code: "leave_failed", Stage: "helper", Retry: RetryReadState,
		Meaning: "ipa-client-install --uninstall did not finish; the host may be half out of the domain.",
		Action:  "Refresh the identity inventory and read the tool's output before ordering again.", CountsAsFailure: true},
	{Code: "insufficient_space", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "A file system the package change writes to - the package cache, /usr or /boot - has fewer free bytes than the change needs; nothing was changed.",
		Action:  "The message names the mount point, the bytes needed and the bytes free. Free space there - old kernels in /boot, the package cache, logs and journals in /var - and order again.", CountsAsFailure: true},
	{Code: "packages_still_blocked", Stage: "agent", Retry: RetryAfterChange,
		Meaning: "The package database is still blocked after the repair.",
		Action:  "Repair the package database by hand on the host.", CountsAsFailure: true},
	{Code: "journal_unavailable", Stage: "agent", Retry: RetryAfterChange,
		Meaning: "The agent could not write the in-flight marker to its journal before the change - the state directory is full or read-only - and started nothing: a change nobody could tell from a repeat is not carried out.",
		Action:  "Free space under the agent's state directory, then order again.", CountsAsFailure: true},
	{Code: "helper_unavailable", Stage: "agent", Retry: RetryAutomatic,
		Meaning: "The root helper did not answer.",
		Action:  "Check flotestro-helper.socket on the host; the attempt is repeated.", CountsAsFailure: true},
	{Code: "secret_unavailable", Stage: "dispatch", Retry: RetryAutomatic,
		Meaning: "The secret the operation needs could not be issued.",
		Action:  "Fix the secret store; the attempt is repeated until the deadline.", CountsAsFailure: true},
	// The states the control plane refuses to start in. They never land on
	// a job; they are in the guide because the log names them and the
	// operator looks them up here first.
	{Code: "secrets_key_unavailable", Stage: "startup", Retry: RetryAfterChange,
		Meaning: "The installation has secrets or a recorded key, and the key that opens them is missing or is not the installation's.",
		Action:  "Restore keys/<key-id>.key (or secrets.key) from the backup of the state directory; never generate a key in its place. See docs/runbooks/db-restore.md."},
	{Code: "issuer_key_unavailable", Stage: "startup", Retry: RetryAfterChange,
		Meaning: "The certificate of the fleet CA is there and its private key is not, or the installation records a CA and the state directory holds none.",
		Action:  "Restore ca.key (and ca.pem) from the backup of the state directory; a new CA would cut every host off. See docs/runbooks/db-restore.md."},
	{Code: "pki_state_mismatch", Stage: "startup", Retry: RetryAfterChange,
		Meaning: "The CA material does not fit together, or the CA on disk is not the one the installation records.",
		Action:  "Restore the whole state directory from the backup taken with the database dump; do not mix files of two installations. See docs/runbooks/db-restore.md."},
	{Code: "crypto_state_ambiguous", Stage: "startup", Retry: RetryAfterChange,
		Meaning: "The installation has no record and what exists does not add up to either an empty installation or a complete old one.",
		Action:  "Read the reason in the log: restore the missing part of the state directory, or clear a leftover of an abandoned installation. See docs/runbooks/db-restore.md."},
	{Code: "envelope_rejected", Stage: "dispatch", Retry: RetryAfterChange,
		Meaning: "The task could not be assembled for delivery: a credential the operation needs was not issued, or the payload no longer fits the contract.",
		Action:  "Read the message - it names what was refused (the directory, the secret store, the payload); fix it and order again.", CountsAsFailure: true},
	{Code: "lease_expired", Stage: "reconcile", Retry: RetryReadState,
		Meaning: "No result arrived within the lease; the outcome on the host is unknown.",
		Action:  "Read the state of the host; do not repeat a destructive step blind.", CountsAsFailure: true},
	{Code: "superseded_by_result", Stage: "reconcile", Retry: RetryNever,
		Meaning: "The host finished the earlier attempt after its lease had expired; the job was settled from that result and this attempt did no work.",
		Action:  "Nothing to repeat; read the result of the job. The operation outlasted its lease once - give it a longer time limit if it is a regular one."},
	{Code: "timeout", Stage: "agent", Retry: RetryReadState,
		Meaning: "The operation exceeded its time limit on the host.",
		Action:  "Read the state of the host before repeating.", CountsAsFailure: true},
	{Code: "outcome_unknown", Stage: "agent", Retry: RetryReadState,
		Meaning: "The agent restarted while the host was carrying the operation; the helper may have finished it.",
		Action:  "Read the host state (packages.list / unit.status) before ordering again; the operation was not repeated.", CountsAsFailure: true},
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
		Meaning: "The host did not come back with a new boot ID within the campaign's reboot timeout.",
		Action:  "Check the host out of band; it may be up without the agent.", CountsAsFailure: true},
	{Code: "reboot_window_closed", Stage: "verify", Retry: RetryReadState,
		Meaning: "The maintenance window of the campaign ended while the host was still rebooting; the change is done, the return is not confirmed.",
		Action:  "Check the host out of band and resume the campaign once the fleet may be touched again; the campaign paused for this host.", CountsAsFailure: true},
	{Code: "reboot_failed", Stage: "verify", Retry: RetryReadState,
		Meaning: "The reboot operation failed on the host.",
		Action:  "Check the host out of band.", CountsAsFailure: true},
	// The verifier of the operation: a change is a success only once the
	// host was read after it and showed the state the operator asked for.
	{Code: ErrorAppliedUnverified, Stage: "verify", Retry: RetryReadState,
		Meaning: "The change was made and the read of the host after it did not show the state the operator asked for: the unit is not active, the file has another digest, the package is at another version, the mount is not there. The result names the verifier, what was expected and what was observed, and says whether the host put the previous state back.",
		Action:  "Read the host - the verifier's observation is in the result - before ordering anything again; the change happened, so a blind repeat is not the answer. Where the result says the previous state was put back, the host stands as before the change.", CountsAsFailure: true},
	{Code: ErrorRebootNotObserved, Stage: "verify", Retry: RetryReadState,
		Meaning: "The reboot was ordered and accepted by the host, and no session with a new boot identifier followed within the wait: the host is down, is up without the agent, or came back so late that the wait ran out first.",
		Action:  "Check the host out of band. A host that comes back later reconnects on its own; the job stays failed, because nobody saw the return in time.", CountsAsFailure: true},
	// The gate in front of a vulnerability feed: a fetch that lost most of
	// what the snapshot in force holds is a source in trouble far more
	// often than a fleet that became safe overnight.
	{Code: "feed_shrank", Stage: "startup", Retry: RetryAfterChange,
		Meaning: "A fetch of a vulnerability feed carried far fewer findings than the snapshot in force, so it was not activated.",
		Action:  "Compare the two counts on the Vulnerabilities screen; accept the fetch there if the vendor really retired the findings, otherwise fix the source. The previous snapshot stays in force and ages into stale."},
	{Code: "feed_release_missing", Stage: "startup", Retry: RetryAfterChange,
		Meaning: "A fetch of a vulnerability feed stopped covering a release the snapshot in force covered, so it was not activated.",
		Action:  "Check the feed URL and the release list on the Vulnerabilities screen; accept the fetch there if the release really went out of the feed. Hosts of that release would otherwise all read as clean."},
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
	{Code: "user_required", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The schedule entry names no account to run as; the host does not put root there by default.",
		Action:  "Name the user in the order. An entry for root additionally needs the permission schedule.root.exec.", CountsAsFailure: true},
	{Code: "unknown_user", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The host has no account under the name the schedule entry names, or the name is not one a cron line can carry; nothing was written.",
		Action:  "Name an account that exists on the host under exactly that spelling, or create it first.", CountsAsFailure: true},
	{Code: "unit_not_managed", Stage: "helper", Retry: RetryNever,
		Meaning: "A unit file under the name a managed timer would use is on the host without the panel's marker: it belongs to the host administrator. Nothing was written and nothing was removed.",
		Action:  "Read the unit on the host. Keep it and order the entry under another name, or remove it by hand to hand the name over to the panel.", CountsAsFailure: true},
	{Code: "managed_timers_unsupported", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The agent of this host reads systemd timers but does not write them: its schedules adapter does not name the managed_timers feature. An order for a timer would be ignored there and written as a cron entry under the name of a timer, so it was refused instead.",
		Action:  "Order the entry as a cron entry, or upgrade the agent on the host and order the timer again."},
	{Code: "timer_calendar_unsupported", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The expression cannot be written as a systemd timer: it names both a day of the month and a day of the week, which cron runs when either matches and a timer only when both do. The two would run on different days, so neither was written.",
		Action:  "Order the entry as a cron entry, where the expression means what it says, or restrict only one of the two days in the timer."},
	{Code: "directory_provisioning_incomplete", Stage: "provisioning", Retry: RetryAfterChange,
		Meaning: "The step that gives the connector's service account the right to move an entry into the container of preserved accounts could not finish on its own: the directory refused the connector one of the objects, or it does not publish the permission that carries the ACI at all. Nothing was half-granted - the step stops at the first refusal and every object it did create is one it may create again without effect.",
		Action:  "The report names the exact ipa commands, in order, for a directory administrator to run, or the ACI to add when the directory does not publish the permission - a permission cannot express moddn, so that one is added with an LDAP client. Run the step again afterwards; it changes nothing that is already in place and confirms with the directory's own answer about the move."},
	{Code: "secret_source_invalid", Stage: "startup", Retry: RetryAfterChange,
		Meaning: "The panel refused to start because a secret is configured in a way it will not read: the variable and its _FILE form are both set, the variable is set but empty, or the file the _FILE form names is a symlink, a directory, a pipe, a socket, a device, larger than 64 KiB, owned by somebody else, or readable by the group or by others. A secret that reaches the process as an environment variable is readable in the inspection output of the container engine, in the shell history and in every child process, which is why the file form exists.",
		Action:  "Mount the secret as a regular file owned by root or by the service user with mode 600 and point FLOTESTRO_..._FILE at it, or set the plain variable alone - never both. The message names the variable and the path; it never names the value."},
	{Code: "secret_gone", Stage: "dispatch", Retry: RetryAfterChange,
		Meaning: "The secret the task needs does not exist any more: somebody retired it or deleted it between the order and the delivery. Neither comes back by itself, so the task was settled rather than repeated until its deadline. Nothing was sent to the host.",
		Action:  "Point the order at a secret that exists, or put the secret back, and order the task again."},
	{Code: "preview_required", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "This panel requires a campaign to be ordered from a preview, and the order named none. The preview is what binds the order to the set of hosts somebody actually read.",
		Action:  "Preview the selector and place the order from that answer; the panel's own screens do this by themselves."},
	{Code: "preview_unknown", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The order names a preview this panel did not issue, or one old enough to have been swept.",
		Action:  "Preview the selector again and order from the new answer."},
	{Code: "preview_consumed", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The preview named by the order already created a campaign. One approved picture of the fleet orders one campaign, so a repeated order does not quietly create a second.",
		Action:  "Look for the campaign that preview created. If another one is really wanted, preview again and order from the new answer."},
	{Code: "preview_expired", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The preview stood longer than a preview stands, so what it counted is no longer a description of the fleet.",
		Action:  "Preview the selector again and order from the new answer."},
	{Code: "preview_principal_mismatch", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The preview was taken by another identity. A preview is not transferable: the rights that counted the hosts are the rights that may order them.",
		Action:  "Preview the campaign under your own identity and order from that answer."},
	{Code: "preview_permission_mismatch", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The preview counted the fleet by one permission and the order asks for another, so the hosts shown are not the hosts this order concerns.",
		Action:  "Preview the operation you are ordering and place the order from that answer."},
	{Code: "preview_action_mismatch", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The preview was taken for a different operation. What qualifies a host depends on the operation, so the eligible hosts of one are not those of another.",
		Action:  "Preview the operation you are ordering and place the order from that answer."},
	{Code: "preview_selector_changed", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The order names a different set of hosts than the preview did: another site, another expression, another exclusion list.",
		Action:  "Preview the selector as it now stands and order from that answer."},
	{Code: "preview_scope_changed", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The ordering identity's role bindings changed after the preview, so the count on the screen was computed with rights that are not the current ones.",
		Action:  "Preview again; the new answer is what may be ordered now."},
	{Code: "preview_targets_changed", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The fleet moved between the preview and the order: a host enrolled, was retired, entered a maintenance window or lost the adapter the operation needs. The order would run on a set of hosts nobody approved.",
		Action:  "Preview again and read what changed before ordering."},
	{Code: "preview_digest_mismatch", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The preview named by the order is not the preview it was answered with: the identifier and the fingerprint describe different pictures of the fleet.",
		Action:  "Preview again and order from a single answer, carrying its identifier and fingerprint together."},
	{Code: "root_grant_required", Stage: "helper", Retry: RetryNever,
		Meaning: "The host refused a schedule entry for root because the signed capability of the request carries no schedule.root.exec grant.",
		Action:  "Order the entry as a principal with schedule.root.exec, or run it as a service account.", CountsAsFailure: true},
	{Code: "validator_unavailable", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The order relies on a content check the host cannot run: the validator tool is not installed there. Nothing was written, because a write nobody checked is not the write that was ordered.",
		Action:  "Install the tool on the host, or order again with allow_missing_validator as a principal holding file.write.unvalidated; the result then says the content went unchecked.", CountsAsFailure: true},
	{Code: "file_version_unknown", Stage: "helper", Retry: RetryAfterReplan,
		Meaning: "The order asked to go back to a content this host does not keep a copy of. Nothing was written: the operator named one version, and the newest copy is not it.",
		Action:  "Read the file's kept versions from the host and order the return to one of them; the refusal lists what the host has.", CountsAsFailure: true},
	{Code: "file_version_not_kept", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The content about to be replaced or removed could not be copied aside, or the copy asked for no longer matches its digest. Nothing was written, because a change this host could not undo is not the change this operation promises.",
		Action:  "Check the free space and the state of /var/lib/flotestro-helper/files on the host, then order the change again.", CountsAsFailure: true},
	{Code: "payload_permission_missing", Stage: "admission", Retry: RetryNever,
		Meaning: "The content of the order asks for more than the operation's own permission: an entry for root needs schedule.root.exec, a write allowed to skip its validator needs file.write.unvalidated. The panel refused the order before it became a job.",
		Action:  "Change the order - a service account instead of root, a write with its validator - or have a principal with the permission place it."},
	{Code: "malformed_request", Stage: "helper", Retry: RetryNever,
		Meaning: "The helper rejected the shape of the request.",
		Action:  "The panel and the helper disagree on the contract; update both.", CountsAsFailure: true},
	{Code: "helper_rejected", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The root helper refused the request at its final check of the host, before running anything; the message carries the helper's own word - malformed_request, unsupported_version or unknown_action.",
		Action:  "The agent and the helper on the host disagree on the contract: bring both to the same release, then order again.", CountsAsFailure: true},
	{Code: "expired", Stage: "dispatch", Retry: RetryNever,
		Meaning: "The operation was not delivered within its time to live.",
		Action:  "Order again once the host is reachable.", CountsAsFailure: true},
	{Code: "canceled", Stage: "dispatch", Retry: RetryNever,
		Meaning: "The operation was cancelled before it ran.",
		Action:  "Nothing; order again if it is still wanted."},
	{Code: "operation_non_cancelable", Stage: "cancel", Retry: RetryNever,
		Meaning: "The cancel reached an operation whose contract says impossible_after_start - a package transaction, a filesystem resize - after the host reported it had started; the request was recorded, the operation runs to its end.",
		Action:  "Nothing can stop it safely: let it drain and read its result. If the outcome is unwanted, order the compensating change the contract names."},
	{Code: "rolled_back", Stage: "verify", Retry: RetryAfterReplan,
		Meaning: "The host undid the change itself because the connectivity check failed.",
		Action:  "Fix the plan; the host is on its previous configuration.", CountsAsFailure: true},

	// The signed capability of the root helper. The helper answers with
	// these before it runs anything; the agent passes them on unchanged.
	{Code: "capability_required", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The helper runs in enforce mode and the request carried no capability of the panel: the agent on the host is from before the capability, or the panel has no signing key.",
		Action:  "Upgrade the agent on the host, or check that the panel signs capabilities (helper-signing.key in its state directory); then order again.", CountsAsFailure: true},
	{Code: "capability_version", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The helper does not read the layout of the capability the panel signed.",
		Action:  "Bring the helper and the panel to the same release, then order again.", CountsAsFailure: true},
	{Code: "capability_wrong_host", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The capability names another host than the one the helper's own identity names, or the helper has no identity yet because the panel's trust bundle has not reached it.",
		Action:  "Check that the agent connects and hands the bundle over (the helper journal says); a host that was cloned or re-enrolled needs the bundle of its new identity.", CountsAsFailure: true},
	{Code: "capability_wrong_action", Stage: "helper", Retry: RetryNever,
		Meaning: "The capability authorizes another operation than the request the agent made.",
		Action:  "The agent on the host asks for something the panel did not approve; inspect the host before ordering anything else on it.", CountsAsFailure: true},
	{Code: "capability_expired", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The capability's window closed before the helper started the operation - the task waited for a resource of the host longer than the window - or the host's clock is far from the panel's.",
		Action:  "Order again when the host is free; if it repeats on an idle host, fix the clock of the host.", CountsAsFailure: true},
	{Code: "capability_ttl_too_long", Stage: "helper", Retry: RetryNever,
		Meaning: "The capability's window is longer than the class of the operation allows, which the panel never issues.",
		Action:  "The capability was not minted by this panel's code; inspect the panel and the host.", CountsAsFailure: true},
	{Code: "payload_binding_mismatch", Stage: "helper", Retry: RetryNever,
		Meaning: "The payload the capability binds names another target - a unit, a package set, a schedule entry, a path, an account - than the request the agent made.",
		Action:  "The agent on the host asks for something other than the approved plan; inspect the host before ordering anything else on it.", CountsAsFailure: true},
	{Code: "capability_unknown_key", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The helper's keyring holds no key of the identifier the capability names: the panel rotated its key and the host has not received the new one, or the host was enrolled with another panel.",
		Action:  "Let the agent reconnect - the session carries the current keys - and order again; a helper whose keyring is empty needs the agent to hand the bundle over once.", CountsAsFailure: true},
	{Code: "capability_bad_signature", Stage: "helper", Retry: RetryNever,
		Meaning: "The signature of the capability does not verify under the named key.",
		Action:  "The capability was altered on the way or minted with another key; inspect the host and the panel.", CountsAsFailure: true},
	{Code: "capability_invalid_nonce", Stage: "helper", Retry: RetryNever,
		Meaning: "The capability's nonce is not of the required length.",
		Action:  "The capability was not minted by this panel's code; inspect the panel and the host.", CountsAsFailure: true},
	{Code: "capability_replay", Stage: "helper", Retry: RetryNever,
		Meaning: "The capability's nonce was consumed before, by another task or by an earlier life of the helper: the same authorization was presented twice.",
		Action:  "Nothing ran the second time. Order again for a fresh capability; a replay nobody ordered is a host to inspect.", CountsAsFailure: true},
	{Code: "helper_capability_unsupported", Stage: "dispatch", Retry: RetryAfterChange,
		Meaning: "The panel runs the capability rollout in enforce mode and the agent of the host does not forward a helper capability, so no mutating task is delivered to it.",
		Action:  "Upgrade the agent on the host; until then the host takes reads only.", CountsAsFailure: true},
	{Code: "boot_filter_unsupported", Stage: "preflight", Retry: RetryAfterChange,
		Meaning: "The read asked for one boot of the host and the agent of the host does not apply a boot filter: an older agent would ignore it and answer with every boot under the name of one, so the read was not sent.",
		Action:  "Read the journal without the boot filter and narrow it by time, or upgrade the agent on the host; not a failure."},

	// The plan envelope: the binding of a plan to its execution (security
	// remediation, chapter 7.1 and 7.2). stale_plan, the shared refusal of
	// a plan whose fingerprint moved, is listed with the plans bound to a
	// stable identity below.
	{Code: "replan_required", Stage: "helper", Retry: RetryAfterReplan,
		Meaning: "The plan was made by another version of the planner than the one that would execute it - the agent or the helper was upgraded between the plan and the change. That is not a change of the host and not a broken plan: the new planner computes something else for the same host, so the old consent cannot be carried over.",
		Action:  "Compute the plan again with the current planner and approve the new set; the previous approval does not apply.", CountsAsFailure: true},
	{Code: "plan_expired", Stage: "helper", Retry: RetryAfterReplan,
		Meaning: "The plan reached the host past its expiry: the state it described is too old to be trusted blind, whatever its fingerprint still looks like.",
		Action:  "Compute the plan again and approve the new set.", CountsAsFailure: true},
	{Code: "effects_partial", Stage: "helper", Retry: RetryReadState,
		Meaning: "The transaction ran and the state read afterwards does not show every effect the plan promised: the result lists each effect achieved and each not achieved, with the version found instead.",
		Action:  "Read the missed effects in the result and the package state of the host before ordering anything else; a repeat of the same plan is refused as stale, because the host no longer computes it.", CountsAsFailure: true},

	// Plans bound to a stable identity: mounts, disks, filesystems and
	// Compose projects (security remediation, chapter 7.3).
	{Code: "stale_plan", Stage: "helper", Retry: RetryAfterReplan,
		Meaning: "The host computed the plan again under its lock right before the change and got another fingerprint: the device, the fstab, the mount point, the repository or the image digest behind a tag moved since the operator approved.",
		Action:  "Do not repeat the old plan; compute it again on the host as it is now and approve the new set. The previous consent does not carry over.", CountsAsFailure: true},
	{Code: "stable_identity_required", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "A destructive disk operation names its device by nothing that survives a reboot: no /dev/disk/by-id link, and neither a WWN nor a serial. The size of the device is a description and is never taken as its identity.",
		Action:  "Read the device row on the host's storage tab: a device without a by-id link is not formatted or wiped by the panel. Give the disk a serial (virtual machines) or do the operation by hand on the console.", CountsAsFailure: true},
	{Code: "disk_changed", Stage: "helper", Retry: RetryAfterReplan,
		Meaning: "The device under the path is not the one the plan was computed for: the by-id link, the WWN, the serial or the filesystem UUID differ. A disk of the same size with another WWN is another disk.",
		Action:  "Read the host's storage again, find the disk the operator meant by its serial or WWN, and plan the operation once more against it.", CountsAsFailure: true},
	{Code: "disk_in_use", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The device carries the root filesystem, has a mounted partition or swap under it, or is held by a volume group, an array or an encrypted container. Nothing was written.",
		Action:  "Unmount what stands on the device, remove it from the volume group or array, and plan again; the root disk is never formatted by the panel.", CountsAsFailure: true},
	{Code: "filesystem_errors_remain", Stage: "helper", Retry: RetryNever,
		Meaning: "The repair ran on the filesystem and a second, read-only pass still finds errors. fsck exits non-zero for a successful repair and for a failed one alike, so the operation is settled by that second pass and not by the code of the first.",
		Action:  "The filesystem needs a person at the console: unmount it, run the check by hand and read what it says, or restore from a backup. Ordering the same repair again changes nothing.", CountsAsFailure: true},

	// The layers above a bare disk: the software array and the volume
	// manager. An array is named by the UUID in its superblock and a group
	// or a volume by its LVM UUID, because a path and a name both belong to
	// something else after a reboot or a rename.
	{Code: "array_unknown", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The host has no software array under that path, the kernel has no md driver at all, or the array carries no UUID to bind the change to - which is what an array whose superblock could not be read looks like. Nothing was done to any array.",
		Action:  "Read the storage tab: an array without a UUID says why it has none (usually a host without mdadm). Install mdadm on the host, or order the change on the host that really holds the array.", CountsAsFailure: true},
	{Code: "array_member_unknown", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The device the order names is not a member of that array. A slot the array lists as removed is not a member either: there is nothing in it to fail or take out.",
		Action:  "Read the array's member list on the storage tab and name a device that is in it; a device that is already out needs adding, not removing.", CountsAsFailure: true},
	{Code: "array_redundancy_lost", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The change would leave the array without a copy of the data: the level keeps none (raid0, linear), the array is already degraded, the member named is the last one carrying data, or a member that still carries data was ordered removed before being failed.",
		Action:  "Add a member and let the array rebuild before taking another one out. A member that is dying is failed first and removed second - two orders, because they are two decisions.", CountsAsFailure: true},
	{Code: "array_rebuilding", Stage: "helper", Retry: RetryReadState,
		Meaning: "The array is putting a member back (recovery, resync, reshape or repair). That is the moment it is least able to lose another member, and a member change interrupts the rebuild. Nothing was changed.",
		Action:  "Wait for the rebuild to finish - the storage tab shows how far it has got - and order the change again."},
	{Code: "array_lifecycle_out_of_scope", Stage: "admission", Retry: RetryNever,
		Meaning: "The order asks the panel to create or destroy a software array. The panel manages the members of an array that exists and nothing beyond that: which arrays a machine has is a decision about its whole disk layout, taken when the machine is built.",
		Action:  "Build or destroy the array on the machine itself; the panel will read it, judge it and manage its members afterwards.", CountsAsFailure: true},
	{Code: "volume_unknown", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The host has no such volume group or logical volume, has no LVM at all, or the group or the volume reports no UUID to bind the change to. Nothing was created and nothing was removed.",
		Action:  "Read the volume tables on the storage tab and name a group or a volume the host really has; a host without LVM says so there in its own words.", CountsAsFailure: true},
	{Code: "volume_group_full", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The group has no free extents for what the order asks - for a new volume, for a snapshot's copy-on-write space, or for the growth requested. Nothing was created.",
		Action:  "Add a disk to the group (a group extension is its own operation), ask for less, or free a volume that is no longer needed.", CountsAsFailure: true},
	{Code: "snapshot_of_snapshot", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The volume named as the origin is itself a snapshot. LVM would copy the copy-on-write space rather than the data, which is not what the word means to anybody.",
		Action:  "Take the snapshot of the origin volume the snapshot was made from; the storage tab names it in the snapshot's row.", CountsAsFailure: true},

	{Code: "image_digest_unresolved", Stage: "planning", Retry: RetryAfterChange,
		Meaning: "A Compose service or a declared container names its image by a tag the host could resolve to a digest neither at the registry (no network, or a private registry the host is not logged into) nor among the images already on the host. The plan binds digests, so it was not computed.",
		Action:  "Pin the digest in the description (image@sha256:...), pull the image on the host first, or give the host access to the registry; then plan again.", CountsAsFailure: true},

	// Declared containers, networks and volumes. The engine can change a
	// handful of a running container's settings and refuses the rest, and
	// it can change nothing at all about a network's address range or a
	// volume's driver - so a description that differs is carried out by
	// destroying the object and making it again. These are the refusals
	// that stop such a replacement where nobody consented to what it
	// costs.
	{Code: "docker_object_conflict", Stage: "planning", Retry: RetryAfterChange,
		Meaning: "The object on the host differs in a setting the engine cannot change in place - a volume's driver or driver option, a network's address range - so bringing it to the description means destroying it and creating it again. A volume recreated is a volume emptied, and the order did not say it accepts that.",
		Action:  "Read the change list of the plan. Declare the object the way it already stands, give the new one another name, or order the change again with force once the data in it is accounted for.", CountsAsFailure: true},
	{Code: "docker_object_in_use", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "Something on the host still holds the object: containers are attached to the network, or a container - running or stopped - references the volume. Nothing was removed and nothing was recreated.",
		Action:  "Read which containers the plan lists. Remove or redeclare them first, or order again with force, which disconnects the containers named in the plan and leaves them running without that network.", CountsAsFailure: true},
	{Code: "docker_network_predefined", Stage: "admission", Retry: RetryNever,
		Meaning: "The order is about bridge, host or none: networks of the engine itself. The engine does not allow removing or recreating them, so the panel does not offer it.",
		Action:  "Declare a network of your own and attach the containers to it; the built-in ones stay as the engine made them.", CountsAsFailure: true},
	{Code: "docker_object_missing", Stage: "helper", Retry: RetryNever,
		Meaning: "The object the order names is not on the host. A removal says so rather than reporting success: silence would leave the operator believing they cleaned something up.",
		Action:  "Read the engine state of the host again; the object is already gone, or it was never on this host.", CountsAsFailure: true},

	// The inner identity envelope of a session through a relay (security
	// remediation, chapter 4). The gateway refuses the session, the
	// message or the call and writes the code on the host as its last
	// connection refusal; none of these sits on a job, so none counts
	// against a campaign.
	{Code: "relay_envelope_invalid", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The identity envelope of a relayed message could not be accepted: another layout, a relay or a host other than the one the message came through or was named for, a message kind other than the payload, a missing envelope on a session that signed its Hello (that message alone is dropped), a spent or foreign renewal challenge, or no public key on record to check it against.",
		Action:  "Read the detail on the host. A layout or a missing key is a release to bring level - panel, relay, agent, in that order; a relay or a host that does not match is a path to inspect before the host is trusted again."},
	{Code: "relay_body_hash_mismatch", Stage: "admission", Retry: RetryNever,
		Meaning: "The payload of a relayed message is not the one the host signed: it changed on the way, or it carries a field this panel does not know.",
		Action:  "If the panel is older than the agent, upgrade the panel first - the fleet rule. Otherwise the relay or the path altered the message: inspect the relay before the host is trusted again."},
	{Code: "relay_sequence_replayed", Stage: "admission", Retry: RetryNever,
		Meaning: "A signed relayed message was carried a second time under a sequence the session had already accepted; the second copy was dropped and not handled.",
		Action:  "One after a broken link is the relay retrying its buffer honestly and needs nothing. A stream of them is a relay or a path replaying the host's messages: inspect the relay."},
	{Code: "relay_host_signature_invalid", Stage: "admission", Retry: RetryNever,
		Meaning: "The signature of the host on a relayed message, a renewal proof or a one-time secret key does not verify under the certificate the host named.",
		Action:  "The message was not signed by the key of the certificate on record: a host whose key was replaced outside the panel, or a relay speaking in its name. Inspect the host and the relay; order an identity recovery if the host's key is in doubt."},
	{Code: "blocked_upgrade_required", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The host's agent predates a proof this installation requires: behind a relay under FLOTESTRO_RELAY_IDENTITY=enforce it does not sign the identity envelope (relay.identity v2), or it renews or fetches a secret through a relay without the host's proof.",
		Action:  "Upgrade the agent on the host - the relay did its part. Until then the host connects directly if it can, or stays refused; not a failure of any change."},
	{Code: "cancel_ack_timeout", Stage: "reconcile", Retry: RetryReadState,
		Meaning: "A cancel was asked of the host holding the task and no acknowledgement came within the operation's own timeout; the host may have run the operation to its end, cut it short or never started it. The job ended with an unknown outcome that needs reconciliation, and a campaign host ends unknown with this code.",
		Action:  "Read the state of the host (packages.list, unit.status) before ordering anything again; do not repeat a destructive step blind. A host that answers nothing is offline or runs an agent from before the cancel protocol - upgrade it.", CountsAsFailure: true},
	{Code: "canceled_before_start", Stage: "cancel", Retry: RetryNever,
		Meaning: "A cancel reached the task on the host before it touched anything - during its checks, while it waited for a resource of the host, or before it was delivered - and the host refused to start it.",
		Action:  "Nothing ran on the host; order again if the change is still wanted."},
	{Code: "skipped_by_operator", Stage: "dispatch", Retry: RetryNever,
		Meaning: "An operator left the host out of the campaign by name while it waited for its connection - the offline canary the wave barrier was waiting for - with a reason recorded on the host, its step and the trail.",
		Action:  "Nothing; the host took no part. Run the change on it separately or in a retry campaign once it is back."},
	{Code: "skip_not_allowed", Stage: "cancel", Retry: RetryAfterChange,
		Meaning: "The skip named a host that is not waiting for its connection: a host under way settles on its own, a host in the queue starts on the next pass, and a settled host is settled.",
		Action:  "Read the host's state again. Cancel the campaign to stop a host that has not started; a host carrying its task cannot be skipped."},

	// Local accounts and their keys (security remediation, chapter 14.1).
	// The host edits the key file line by line under the account lock and
	// refuses, with the code, what would cut an account off or write
	// what nobody reviewed.
	{Code: "account_without_credential", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The order would create an account with no key and, since the panel sets no passwords, no way to log in - and did not say so.",
		Action:  "Give the account a key, or set inactive: true to create it deliberately without a way in; the panel then shows it as locked."},
	{Code: "key_not_found", Stage: "helper", Retry: RetryReadState,
		Meaning: "A removal named a fingerprint the account's key file does not carry: the key was taken away in between, or the list came from another host.",
		Action:  "Read the account's keys again and remove what is there; an order that may find the key already gone says ignore_missing: true."},
	{Code: "last_key_lockout", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The removal or the replace would take the last key of an account that has no password login (no password, or a locked one, or a password state the host could not read), and nobody could enter as it afterwards. Nothing was written.",
		Action:  "Add the replacement key first and remove the old one after, or - when cutting the account off is the intent - order the removal with allow_lockout: true, or lock the account instead."},
	{Code: "managed_file_not_read", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The order asked for the panel's own key file under /etc/ssh/authorized_keys.d and sshd on this host does not list it in AuthorizedKeysFile: keys written there would grant nothing.",
		Action:  "Add /etc/ssh/authorized_keys.d/%u/60-flotestro.keys to AuthorizedKeysFile through the sshd module, or order the change without managed_file and edit the user's authorized_keys."},
	{Code: "invalid_ssh_key", Stage: "helper", Retry: RetryNever,
		Meaning: "The material given as a public key is not one sshd would read: the host parsed it before writing and could not.",
		Action:  "Paste the public key as ssh-keygen prints it (type, material, optional comment); options in front of it are allowed, a private key never is.", CountsAsFailure: true},
	{Code: "system_account", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The account's identifier lies outside the UID range of people in the host's login.defs (UID_MIN..UID_MAX): it belongs to a service or to the system, and the order did not say it meant one.",
		Action:  "Pick the account of a person; a change to a service account is ordered with system: true, and root and the agent's own account are never changed through the panel.", CountsAsFailure: true},

	// The dead letters of the notification queue (security remediation,
	// chapter 10). The stage is the delivery of a notification, not a
	// task; none of them counts against a campaign.
	{Code: "channel_credentials_rejected", Stage: "notification", Retry: RetryAfterChange,
		Meaning: "The receiver of a notification channel answered 401 or 403, or the mail relay refused the login: the credential of the channel is wrong or revoked. The message is a dead letter.",
		Action:  "Replace the credential on the channel (the incoming webhook address, the signing secret, the password secret) and retry the dead letters from the notifications screen."},
	{Code: "permanent_http_error", Stage: "notification", Retry: RetryAfterChange,
		Meaning: "The receiver of a notification channel answered a status that is neither a success nor one that passes - a 404, a 400 - so the address or the shape of the message is wrong for it. The message is a dead letter.",
		Action:  "Check the address and what the receiver expects; send a test from the channel; then retry the dead letters."},
	{Code: "permanent_smtp_error", Stage: "notification", Retry: RetryAfterChange,
		Meaning: "The mail relay refused the message with a permanent reply (5xx): a sender or a recipient it does not accept, a message it will not take. The message is a dead letter.",
		Action:  "Read the reply on the delivery, correct the sender or the recipients on the channel, send a test, then retry the dead letters."},
	{Code: "delivery_attempts_exhausted", Stage: "notification", Retry: RetryAfterChange,
		Meaning: "The receiver of a notification channel kept failing in a way that passes - a 5xx, a 429, an unreachable address - until the attempts ran out. The message is a dead letter. Deliveries written before this release carry this code; a delivery written now carries the transport's own reason instead, and its state says the queue gave up.",
		Action:  "Bring the receiver back or fix the address, send a test from the channel, then retry the dead letters; nothing was lost."},
	{Code: "channel_misconfigured", Stage: "notification", Retry: RetryAfterChange,
		Meaning: "A notification channel cannot send as it is: it was disabled while its messages waited, its configuration does not read, or the panel has no sender for its kind.",
		Action:  "Enable or correct the channel and retry the dead letters; the messages of a channel that is to stay disabled can be left as they are."},

	// The lifecycle orders that travel between the instances of the
	// control plane (security remediation, chapter 6). None of them is a
	// failure of a change on a host: they say where the decision is and
	// what has not been confirmed yet.
	{Code: "lifecycle_handover_pending", Stage: "reconcile", Retry: RetryReadState,
		Meaning: "The host holds its session on another instance of the panel, the order to end its membership was written for that instance, and it had not answered within the wait. The host stands in retiring; nothing about its disk is decided.",
		Action:  "Read the host page: the owning instance finishes the handshake on its own and the host turns retired. Repeating the decommission afterwards picks the host up from retiring; do not wipe the machine until the phase says committed. Not a failure."},
	{Code: "lifecycle_handover_failed", Stage: "reconcile", Retry: RetryReadState,
		Meaning: "The instance holding the host's session took the order to end its membership and could not finish it; its reason is on the answer and on the trail. The host stands in retiring.",
		Action:  "Read the reason, then order the decommission again - it picks the host up from retiring. A host whose owning instance keeps failing is retired offline once its session is gone, with the cleanup unconfirmed."},
	{Code: "session_close_unconfirmed", Stage: "reconcile", Retry: RetryReadState,
		Meaning: "A quarantine or an identity recovery asked the instance holding the host's session to end it, and that instance did not answer within the wait. The decision itself is recorded, and the gateway refuses the host at its next connection.",
		Action:  "Nothing at once: the ownership claim of a dead instance runs out within a minute and the session with it. Check the host's connection state on its page; a host that still heartbeats after that has an instance that is not reading its orders - restart it."},

	// Replacing the agent with a named release (security remediation,
	// chapter 14.5). Each of these is answered before the package database
	// is touched, so the host keeps the version it runs.
	{Code: "agent_upgrade_metadata_stale", Stage: "agent", Retry: RetryAutomatic,
		Meaning: "The host did not confirm that it refreshed its repository metadata, so the version the order names may not be installable from the lists its package manager holds. The replacement was not started.",
		Action:  "Read the reason the refresh carries in the message - an unreachable repository, a busy package manager - and order again once the host can reach its repository.", CountsAsFailure: true},
	{Code: "agent_package_digest_mismatch", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The package file the host obtained for the ordered version does not hash to the digest of the release. The repository signature says where the file came from; the digest says whether it is the file the release published, and it is not. Nothing was installed.",
		Action:  "Compare the digest on the release with the repository the host uses: a stale mirror and a package rebuilt under the same version both look like this. Do not order the upgrade again until they agree.", CountsAsFailure: true},
	{Code: "agent_package_unavailable", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The host could not obtain the package file of the ordered version at all: the repository does not carry that version, or the download failed. Nothing was installed.",
		Action:  "Check that the release reached the repository the host uses and that the host can reach it, then order again.", CountsAsFailure: true},
	{Code: "agent_rollback_unavailable", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The order named a version to go back to and the host could not keep its package file: it is neither in the package cache nor in the repository. The upgrade was not started, because a prepared return that does not exist is worse than an upgrade postponed.",
		Action:  "Put the named version back into the repository the host uses, or order the upgrade without a version to go back to and accept that a return would then depend on the repository.", CountsAsFailure: true},

	// The phases of a directory change (security remediation, chapter
	// 14.3). None of them sits on a job of a host, so none counts against a
	// campaign; they are in the guide because the change screen shows them
	// and an operator looks them up here. A plan the directory moved under
	// is reported as stale_plan, the shared code listed above.
	{Code: "directory_moddn_unsupported", Stage: "preflight", Retry: RetryAfterChange,
		Meaning: "The preflight asked the directory what it can do and it proved it cannot preserve an account: the connector's service account may not move an entry, or the container of preserved accounts is not there. Nothing was ordered and the local account was not touched.",
		Action:  "Run the directory provisioning step for preserving accounts: it gives the connector's service account the three rights the move needs - System: Preserve User for the move itself, System: Modify User RDN for the name it carries, and System: Read Preserved Users so the directory can report what it moved - through the privilege Flotestro Preserve Users and the role Flotestro Directory Connector, and nothing else. It is safe to repeat - a second run changes nothing. If the directory refuses the connector that step too, the refusal names the ipa commands a directory administrator runs instead. A directory that merely does not report its rights does not raise this."},
	{Code: "directory_plan_incomplete", Stage: "planning", Retry: RetryAfterReplan,
		Meaning: "The approved change carries no reference to the entry it would move - where it is, which entry it is and when it last changed - so there is nothing to bind the execution to.",
		Action:  "Plan the change again; the new plan records the entry, and the execution refuses if that entry moves between the approval and the change."},
	{Code: "directory_refused", Stage: "directory", Retry: RetryAfterChange,
		Meaning: "The directory refused the change and named its own reason. Nothing was changed locally: the directory goes first exactly so that its refusal does not leave a host denying a user the directory still holds.",
		Action:  "Read the directory's reason in the phase - an ACI, a validation, an entry that is not there - correct it in the directory and order again."},
	{Code: "directory_unreachable", Stage: "directory", Retry: RetryAutomatic,
		Meaning: "The directory did not answer, so nothing is known about what it would have done and nothing was changed anywhere.",
		Action:  "Check the connector on the identity screen - the keytab, the KDC, the directory itself - and order again once it answers."},

	// The built-in monitoring (security remediation, chapters 12 and 16).
	// None of these sits on a job of a host, so none counts against a
	// campaign. They are in the guide because a gap in a chart and a
	// refused start both have to name a reason somebody can look up.
	{Code: "metric_sample_too_old", Stage: "monitoring", Retry: RetryNever,
		Meaning: "A resource sample reached the panel older than the raw samples are kept for, so it was not stored: writing it would put a reading into a window the retention drops in the same pass. The host was told so and dropped its copy, and the chart keeps a gap at that moment rather than a line drawn through it.",
		Action:  "Read how long the host or its relay was cut off: a gap longer than the maximum lateness is the outage, not a fault. Raise the maximum lateness and the raw retention together if such an outage has to be recoverable; the panel refuses a retention shorter than the query window plus the lateness."},
	{Code: "metric_sample_not_kept", Stage: "monitoring", Retry: RetryNever,
		Meaning: "The panel that received the sample keeps no samples at all: this gateway has no monitoring store attached. The host was told terminally rather than left waiting, so its spool holds readings it can still deliver instead of one nobody will take.",
		Action:  "This is a deployment without the built-in monitoring. Attach the monitoring store on the control plane if the fleet is meant to have charts and alerts."},
	{Code: "alert_evaluator_lease_lost", Stage: "monitoring", Retry: RetryAutomatic,
		Meaning: "The control-plane instance evaluating the alert rules lost the lease in the middle of a pass and stopped where it was. Another instance holds the lease and carries on from the open episodes; nothing was written after the loss, because two instances judging one fleet at once is how a panel contradicts itself about an alert.",
		Action:  "Nothing, unless it repeats. A stream of these from one instance means it cannot renew in time: look at the database latency and at the clock of that instance."},
	{Code: "metrics_retention_too_short", Stage: "startup", Retry: RetryAfterChange,
		Meaning: "The panel refused to start because the raw retention is shorter than the window it offers at full resolution plus the longest a sample may take to arrive. Such a configuration deletes a reading a relay is still carrying, by definition and without anybody ordering it.",
		Action:  "Raise the raw retention to at least the sum, or lower the raw query window or the maximum lateness. The three are named in the configuration reference under the monitoring settings."},

	// The proof of the management channel after a change of the network or
	// the firewall (security remediation, chapter 14.4). Such a change arms a
	// rescue plan before it touches the host, and only a call the host makes
	// with its own identity, acknowledged by the panel, disarms it.
	// The layered network changes (ROADMAPE, gap 8). Every one of these is a
	// refusal about a relation on the host - what owns what, what the panel
	// itself talks over - rather than about a wrong value, so each has a
	// code of its own: an operator told only "malformed" would have no idea
	// which of five relations was in the way.
	{Code: "link_member_taken", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "An interface named as a member of the bond or the bridge is already owned by another layer, or is a VLAN running on one. Taking it would remove it from there and stop whatever runs over that layer, so nothing was written.",
		Action:  "Read the layering of the host. Take the interface out of the layer that owns it first, or build this one from interfaces that are free.", CountsAsFailure: true},
	{Code: "link_member_missing", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The host does not report an interface named as a member of the layer. A layer built on an interface that is not there would come up with fewer members than the operator approved.",
		Action:  "Check the name against the interfaces the host reports; on a fleet this usually means the hosts do not name their cards alike."},
	{Code: "bond_needs_two_members", Stage: "admission", Retry: RetryAfterChange,
		Meaning: "The bond would have fewer than two members. With one it carries the same traffic over the same cable with a driver in between, and none of the redundancy a bond exists for.",
		Action:  "Name at least two members, or set the address on the interface directly instead of bonding it to itself."},
	{Code: "vlan_parent_missing", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The interface the tagged traffic would run on is not on the host. Nothing was written: a VLAN without a parent carries nothing.",
		Action:  "Name a parent the host reports, or build the parent - a bond or a bridge - first and order the VLAN afterwards.", CountsAsFailure: true},
	{Code: "link_swallows_management", Stage: "helper", Retry: RetryNever,
		Meaning: "A member of the layer is the interface the panel talks to this host over. Enslaving it moves its address to the layer above, and the host would be gone before the layer was finished - with the rescue plan still armed and nobody left to disarm it.",
		Action:  "Build the layer from interfaces the panel does not come through. Moving the management channel onto a bond is a job for the machine's build, not for a fleet operation.", CountsAsFailure: true},
	{Code: "link_carries_management", Stage: "helper", Retry: RetryNever,
		Meaning: "The layer being removed is the one the panel talks over; removing it takes the address with it. Nothing was written.",
		Action:  "Move the management channel to another interface on the host first, or do this from the console.", CountsAsFailure: true},
	{Code: "link_kind_mismatch", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The host already has an interface under this name and it is something else - a plain link, or a layer of another kind. The panel does not turn one into the other under the same name.",
		Action:  "Choose a name the host does not use, or remove the existing interface deliberately first."},
	{Code: "link_not_layered", Stage: "helper", Retry: RetryNever,
		Meaning: "The interface named for removal is a plain link, or a layer this panel did not define: under netplan a definition an earlier file made cannot be removed by a later one, so a removal that looked like it worked would leave the interface exactly where it was after the next boot.",
		Action:  "Remove only the layers the panel built. One the distribution defined is removed by editing that definition on the host.", CountsAsFailure: true},
	{Code: "link_in_use", Stage: "helper", Retry: RetryAfterChange,
		Meaning: "The layer carries VLANs, or is itself a member of another layer. Removing it would take them with it, so nothing was written.",
		Action:  "Remove what stands on it first - the VLANs it carries, or its membership of the layer above - and order the removal again."},
	{Code: "link_mechanism_unsupported", Stage: "helper", Retry: RetryNever,
		Meaning: "The host configures its network through a mechanism this module does not write layered interfaces with. A bond is several profiles at once, and half of one on a host the panel then cannot reach is worse than none, so nothing was written.",
		Action:  "Build the layer on the host itself, or move that host to nmstate or netplan. The panel keeps reading and changing addresses there either way.", CountsAsFailure: true},
	{Code: "ipv6_disabled_on_host", Stage: "helper", Retry: RetryNever,
		Meaning: "The order carries an IPv6 address, route or router advertisement setting and the host has the second family switched off. The write would go into the void and the verifier would never find it, so nothing was written.",
		Action:  "Switch IPv6 on for the host or the interface first - that is a kernel setting, not a profile one - and order the change again.", CountsAsFailure: true},

	{Code: "management_channel_unproved", Stage: "agent", Retry: RetryReadState,
		Meaning: "After the change the host could not prove it still talks to the panel: the call it made with its own identity was not acknowledged. The rescue plan was not disarmed, so the host returns on its own to the state from before the change. A connection that merely opens is not the proof - a rule can admit the handshake and still end every management session.",
		Action:  "Wait for the rollback, read the state of the host, and order the change again only with a rule that leaves the management channel working - or, deliberately, with break-glass consent.", CountsAsFailure: true},
}

// RefusalError is a validation refusal with a code of its own. Validate
// returns plain errors for a malformed payload - the interface shows the
// message and that is enough - but a refusal on grounds other than shape
// needs a code the interface can act on: a protocol the panel does not
// speak is a fact about the release, not a typo in the order.
type RefusalError struct {
	Code string
	Err  error
}

// RefusalProtocolIncompatible refuses an agent release whose protocol this
// panel does not speak.
const RefusalProtocolIncompatible = "protocol_incompatible"

func (e *RefusalError) Error() string { return e.Code + ": " + e.Err.Error() }

func (e *RefusalError) Unwrap() error { return e.Err }

// RefusalCode returns the code of a validation error: the refusal's own
// one, or invalid_payload for a plain validation error. The handlers that
// call Validate answer with it, so the interface tells a wrong shape from
// a refused release.
func RefusalCode(err error) string {
	var refusal *RefusalError
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return "invalid_payload"
}
