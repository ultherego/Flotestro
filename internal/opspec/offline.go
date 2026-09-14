package opspec

import (
	"errors"
	"fmt"
)

// OfflinePolicy says what a campaign does with a host that is not connected
// when its turn comes.
//
// Offline is a normal state of a fleet, not an exception, and every
// operation declares the policy itself: the effect of a command carried out
// an hour later can be entirely different from the effect of carrying it out
// now. A route change or a signal to a process concerns the state the
// operator saw; a package upgrade concerns a target state that still holds
// tomorrow.
type OfflinePolicy string

const (
	// OfflineRequireOnline ends the host's participation the moment it is
	// found offline: the order is reactive or contextual, and the state it
	// was given for will not be there when the host comes back.
	OfflineRequireOnline OfflinePolicy = "require_online"
	// OfflineSkip leaves the host out without calling that a failure: a
	// read or a refresh that did not happen is a gap in knowledge, not a
	// broken change.
	OfflineSkip OfflinePolicy = "skip_if_offline"
	// OfflineWait keeps the host in the queue without a slot and starts it
	// when it comes back, up to the campaign's deadline.
	OfflineWait OfflinePolicy = "wait_until_deadline"
	// OfflineReplan waits like OfflineWait, but computes the host's plan
	// again after the reconnect and runs the change only when the plan is
	// the one that was approved. The consent covered a diff against the
	// state the host had before it disappeared.
	OfflineReplan OfflinePolicy = "replan_on_reconnect"
)

var (
	// ErrUnknownOfflinePolicy means a policy outside the four the registry knows.
	ErrUnknownOfflinePolicy = errors.New("unknown offline policy")
	// ErrOfflinePolicyLoosened means a campaign asked for a policy weaker
	// than the operation declares.
	ErrOfflinePolicyLoosened = errors.New("a campaign may only tighten the offline policy of an operation")
	// ErrNothingToReplan means replan_on_reconnect asked for an operation
	// that has no planner, so there is nothing to compute again.
	ErrNothingToReplan = errors.New("replan_on_reconnect needs an operation with a per-host plan")
)

// KnownOfflinePolicy checks that the policy is one of the registry's.
func KnownOfflinePolicy(policy OfflinePolicy) bool {
	switch policy {
	case OfflineRequireOnline, OfflineSkip, OfflineWait, OfflineReplan:
		return true
	default:
		return false
	}
}

// strictness orders the policies by how little they do with an offline
// host. Waiting runs the approved plan later; replanning runs it only when
// it still matches; skipping never runs it; requiring the host online
// never runs it and calls the absence a refusal. A campaign may move up
// this ladder and never down: a stricter policy does at most what the
// operation's own policy would have done.
func (p OfflinePolicy) strictness() int {
	switch p {
	case OfflineWait:
		return 1
	case OfflineReplan:
		return 2
	case OfflineSkip:
		return 3
	case OfflineRequireOnline:
		return 4
	}
	return 0
}

// Waits says whether the policy keeps an offline host in the queue.
func (p OfflinePolicy) Waits() bool {
	return p == OfflineWait || p == OfflineReplan
}

// offlinePolicies is the registry of explicit offline policies.
//
// The map lists the operations whose policy does not follow from their
// shape. The rest is derived: a read is skipped, a change with a per-host
// plan is planned again after the reconnect, and a change nobody described
// requires the host online - missing metadata must not mean "run it
// whenever the host shows up".
var offlinePolicies = map[ActionType]OfflinePolicy{
	// Reactive and contextual orders. A signal, a route, a firewall rule or
	// a reboot carried out hours later may concern a different state than
	// the one the operator approved; the anti-pattern the document warns
	// about is a long TTL on exactly these.
	ActionProcessSignal:          OfflineRequireOnline,
	ActionNetworkProfileApply:    OfflineRequireOnline,
	ActionNetworkRouteEnsure:     OfflineRequireOnline,
	ActionNetworkMTUSet:          OfflineRequireOnline,
	ActionNetworkRollback:        OfflineRequireOnline,
	ActionDNSHostApply:           OfflineRequireOnline,
	ActionFirewallRuleEnsure:     OfflineRequireOnline,
	ActionFirewallRuleRemove:     OfflineRequireOnline,
	ActionFirewallZonePort:       OfflineRequireOnline,
	ActionFirewallZoneService:    OfflineRequireOnline,
	ActionFirewallRulesetRestore: OfflineRequireOnline,
	ActionSSHConfigApply:         OfflineRequireOnline,
	ActionSSHHostKeyRotate:       OfflineRequireOnline,
	ActionSystemReboot:           OfflineRequireOnline,
	ActionSystemShutdown:         OfflineRequireOnline,
	// A rename lands on a host whose neighbours were checked at ordering
	// time; hours later the name may be taken.
	ActionSystemHostnameSet: OfflineRequireOnline,
	// Deleting an account frees a name the operator saw at that moment.
	ActionLocalUserDelete: OfflineRequireOnline,
	// Destructive storage: a disk that was empty when the operator looked
	// may hold somebody's data by the time the host comes back.
	ActionDiskWipe:         OfflineRequireOnline,
	ActionFilesystemCreate: OfflineRequireOnline,
	// Removing a container or pruning images frees what the operator saw
	// as unused at that moment.
	ActionDockerRemove: OfflineRequireOnline,
	ActionDockerPrune:  OfflineRequireOnline,

	// Reads, scans and refreshes: a missing observation is a gap, not a
	// failure, and the next refresh fills it.
	ActionInventoryRefresh: OfflineSkip,
	ActionSecurityScan:     OfflineSkip,
	ActionCertificateScan:  OfflineSkip,
	ActionMonitoringProbe:  OfflineSkip,
	ActionDNSResolveTest:   OfflineSkip,
	ActionTimeSyncTest:     OfflineSkip,

	// Declarations of a target state: the same order means the same thing
	// tomorrow, so the host gets it when it comes back, within the
	// campaign's deadline.
	ActionUnitStart:        OfflineWait,
	ActionUnitStop:         OfflineWait,
	ActionUnitRestart:      OfflineWait,
	ActionUnitReload:       OfflineWait,
	ActionUnitEnableSet:    OfflineWait,
	ActionUnitMaskSet:      OfflineWait,
	ActionScheduleEnsure:   OfflineWait,
	ActionScheduleDisable:  OfflineWait,
	ActionScheduleRemove:   OfflineWait,
	ActionScheduleRunNow:   OfflineWait,
	ActionPackageHoldSet:   OfflineWait,
	ActionPackageRemove:    OfflineWait,
	ActionPackageRepair:    OfflineWait,
	ActionRepositorySet:    OfflineWait,
	ActionAgentUpgrade:     OfflineWait,
	ActionLocalUserCreate:  OfflineWait,
	ActionLocalUserLock:    OfflineWait,
	ActionLocalUserUnlock:  OfflineWait,
	ActionLocalSSHKeysSet:  OfflineWait,
	ActionDomainEnroll:     OfflineWait,
	ActionKernelModuleLoad: OfflineWait,
	ActionSysctlEnsure:     OfflineWait,
	ActionSELinuxModeSet:   OfflineWait,
	ActionAuditRulesReload: OfflineWait,
	ActionTimezoneSet:      OfflineWait,
	ActionBackupRestore:    OfflineWait,
	ActionDockerStart:      OfflineWait,
	ActionDockerStop:       OfflineWait,
	ActionDockerRestart:    OfflineWait,
	ActionDockerPull:       OfflineWait,
	// A group list and an expiry date are declarations about a name.
	ActionLocalUserGroupsSet: OfflineWait,
	ActionLocalUserExpirySet: OfflineWait,
}

// OfflinePolicy returns the policy an operation declares for a host that is
// not connected.
//
// An operation that computes its plan on the host is planned again after
// the reconnect: the diff the operator approved was computed against a
// state the host no longer necessarily has. A read is skipped. Anything
// else without a declaration requires the host online - the strictest
// answer, because an undescribed change must not be carried onto a host at
// an unknown later time.
func (a ActionType) OfflinePolicy() OfflinePolicy {
	if policy, ok := offlinePolicies[a]; ok {
		return policy
	}
	if PlanningAction(a) != "" {
		return OfflineReplan
	}
	if a.Known() && !a.Mutating() {
		return OfflineSkip
	}
	return OfflineRequireOnline
}

// ResolveOfflinePolicy returns the policy a campaign runs under.
//
// An empty request means the operation's own policy. A request may only
// tighten it: wait_until_deadline may become skip_if_offline or
// require_online, and require_online may become nothing else. Loosening is
// refused, because the operation's policy is the boundary the module drew
// - a route change waiting a day for a host is exactly the order the
// registry says must not exist.
func ResolveOfflinePolicy(action ActionType, requested OfflinePolicy) (OfflinePolicy, error) {
	declared := action.OfflinePolicy()
	if requested == "" {
		return declared, nil
	}
	if !KnownOfflinePolicy(requested) {
		return "", fmt.Errorf("%w: %q", ErrUnknownOfflinePolicy, requested)
	}
	if requested == OfflineReplan && PlanningAction(action) == "" {
		return "", fmt.Errorf("%w: %s has none", ErrNothingToReplan, action)
	}
	if requested.strictness() < declared.strictness() {
		return "", fmt.Errorf("%w: %s declares %s, the request asked for %s",
			ErrOfflinePolicyLoosened, action, declared, requested)
	}
	return requested, nil
}
