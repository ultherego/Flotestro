package adminapi

import (
	"net/http"
	"strings"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// What one host lets one operator do, action by action.
//
// The screens used to draw every button and let the order find out, from
// the 403 or the 409 that came back, that the operator had no right to it
// or that the host had no adapter for it. The answer here is the same
// judgement handleCreateOperation makes at the door of an order - the
// permission in the host's scope, the lifecycle state, the adapter
// registry - given ahead of the click, for every operation at once, so a
// viewer sees no restart button and a host without Docker shows no image
// pull. It is a preview and nothing else: the order itself is judged again,
// by the same code, when it is placed. Nothing here grants anything.
//
// The judgement is cheap on purpose: the host row carries its registry,
// the principal carries its bindings, and every action of the catalogue is
// decided from those two without another read.

// Reason codes of a refused action. Each names what the operator would
// change to get the action, so the screen can say it in one line.
const (
	// ReasonPermissionDenied: the operator lacks the permission of the
	// action, or the right to order anything, in the scope of the host.
	ReasonPermissionDenied = "permission_denied"
	// ReasonHostQuarantined: the host is cut off until somebody releases it.
	ReasonHostQuarantined = "host_quarantined"
	// ReasonHostRecovery: the host waits for its new certificate; it takes
	// orders again once the new key connects.
	ReasonHostRecovery = "host_recovery"
	// ReasonHostRetired: the host is leaving or has left the fleet.
	ReasonHostRetired = "host_retired"
	// ReasonReadOnlyHost: the adapter is there, but the host said it can
	// only read with it - no mechanism that persists a network change, no
	// resolver the panel may write - so the write the action needs is not
	// among its features.
	ReasonReadOnlyHost = "read_only_host"
	// ReasonHelperUnavailable: the agent reported that its root helper did
	// not answer, and the action needs the helper to change anything.
	ReasonHelperUnavailable = "helper_unavailable"
	// ReasonHostOffline: a read needs the host on the line now; there is
	// no state to read from a host that is not connected.
	ReasonHostOffline = "host_offline"
	// ReasonPackageDatabaseBroken: the host's package database needs a
	// repair before any other package operation.
	ReasonPackageDatabaseBroken = "package_database_broken"
	// ReasonLifecycleStateMismatch: a lifecycle order that does not apply
	// to the state the host is in - a release of a host not in quarantine.
	ReasonLifecycleStateMismatch = "lifecycle_state_mismatch"
)

// hostAction is the verdict on one action of the catalogue for one host
// and one operator.
type hostAction struct {
	Action     string `json:"action"`
	Permission string `json:"permission"`
	Mutating   bool   `json:"mutating"`
	Risk       string `json:"risk"`
	Allowed    bool   `json:"allowed"`
	// ReasonCode and Reason say why the action is refused; both are empty
	// when it is allowed.
	ReasonCode string `json:"reason_code,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// MissingPermission names the permission a permission_denied verdict
	// is about: the action's own, or job.create when the operator holds
	// the action's permission but not the right to order anything.
	MissingPermission string `json:"missing_permission,omitempty"`
	// Note is a fact about an allowed action the operator wants before
	// the click: the order will wait in the queue for an offline host, or
	// it will ask for fresh authentication. It never refuses anything.
	Note string `json:"note,omitempty"`
}

// handleListHostActions answers GET /api/v1/hosts/{id}/actions: every
// action of the catalogue with whether this operator may order it on this
// host now, and why not otherwise. Reading the host is enough to ask; the
// answer for an operator who may order nothing is a list of refusals, which
// is exactly what their screen needs.
func (s *Server) handleListHostActions(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostRead, scope, "host", hostID)
	if !ok {
		return
	}
	// The verdict depends on who asks and changes with every binding, every
	// reconnect and every lifecycle change; a shared cache would serve one
	// operator's rights to another.
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"items":   hostActions(principal, host, scope),
		"version": opspec.ActionVersion,
	})
}

// hostActions judges every action of the catalogue for one operator on one
// host, and the three lifecycle orders after them. The checks run in the
// order handleCreateOperation runs them, so the reason named here is the
// one the order would be refused with.
func hostActions(principal authz.Principal, host *hosts.Host, scope authz.Scope) []hostAction {
	actions := opspec.AllActions()
	items := make([]hostAction, 0, len(actions)+len(hostLifecycleActions))
	for _, action := range actions {
		items = append(items, judgeHostAction(principal, host, scope, action))
	}
	for _, transition := range hostLifecycleActions {
		items = append(items, judgeLifecycleAction(principal, host, scope, transition))
	}
	return items
}

// lifecycleAction is one of the orders that change what the panel thinks
// of a host rather than the host itself: they are not in the operation
// catalogue, have no adapter and no job, and take a host in some states
// only. The screen draws their buttons from the same preview.
type lifecycleAction struct {
	// Action is the name the audit trail records the order under, which is
	// also its permission.
	Action     string
	Permission authz.Permission
	FromStates []string
}

// lifecycleActions mirrors the transitions of lifecycle.go: quarantine
// from a live state or again from quarantine, release from quarantine,
// decommission from everything but retired.
var hostLifecycleActions = []lifecycleAction{
	{Action: "host.quarantine", Permission: authz.PermHostQuarantine,
		FromStates: []string{hosts.StateActive, hosts.StateRecovery, hosts.StateQuarantined}},
	{Action: "host.quarantine.release", Permission: authz.PermHostQuarantineRelease,
		FromStates: []string{hosts.StateQuarantined}},
	{Action: "host.decommission", Permission: authz.PermHostDecommission,
		FromStates: []string{hosts.StateActive, hosts.StateQuarantined, hosts.StateRecovery, hosts.StateRetiring}},
}

// judgeLifecycleAction is the verdict on one lifecycle order: the
// permission in the host's scope, then the state the host is in.
func judgeLifecycleAction(principal authz.Principal, host *hosts.Host, scope authz.Scope, transition lifecycleAction) hostAction {
	verdict := hostAction{
		Action:     transition.Action,
		Permission: string(transition.Permission),
		Mutating:   true,
		Risk:       string(opspec.RiskCritical),
	}
	if !principal.Can(transition.Permission, scope) {
		verdict.ReasonCode = ReasonPermissionDenied
		verdict.MissingPermission = string(transition.Permission)
		verdict.Reason = "ordering " + transition.Action + " needs the permission " + string(transition.Permission) + " in scope " + scope.String()
		return verdict
	}
	for _, state := range transition.FromStates {
		if host.LifecycleState == state {
			verdict.Allowed = true
			verdict.Note = "asks for fresh authentication and a reason"
			return verdict
		}
	}
	verdict.ReasonCode = ReasonLifecycleStateMismatch
	verdict.Reason = "the host is " + host.LifecycleState + "; " + transition.Action + " does not apply to it"
	return verdict
}

// judgeHostAction is the verdict on one action.
func judgeHostAction(principal authz.Principal, host *hosts.Host, scope authz.Scope, action opspec.ActionType) hostAction {
	verdict := hostAction{
		Action:     string(action),
		Permission: action.Permission(),
		Mutating:   action.Mutating(),
		Risk:       string(action.Risk()),
	}
	refuse := func(code, reason string) hostAction {
		verdict.Allowed = false
		verdict.ReasonCode = code
		verdict.Reason = reason
		return verdict
	}

	// Ordering anything at all is one permission; this operation is a
	// second one. The order checks the general right first; the preview
	// names the action's own permission first, because that is the one a
	// screen tells the operator they lack - job.create is named only when
	// it is the sole thing missing.
	for _, permission := range []authz.Permission{authz.Permission(action.Permission()), authz.PermJobCreate} {
		if !principal.Can(permission, scope) {
			verdict.MissingPermission = string(permission)
			return refuse(ReasonPermissionDenied,
				"ordering "+string(action)+" needs the permission "+string(permission)+" in scope "+scope.String())
		}
	}

	if host.PackageDatabaseBroken && blockedByBrokenDatabase(action) {
		return refuse(ReasonPackageDatabaseBroken,
			"the host's package database needs repair; run packages.repair first")
	}

	// The states other than active are different kinds of "no", and the
	// code says which; the sentence is the one the order gets.
	if !hosts.Active(host.LifecycleState) {
		return refuse(lifecycleReasonCode(host.LifecycleState), lifecycleRefusal(host.LifecycleState))
	}

	// The registry decides, as it does for the order. The host's own words
	// on the adapter - "this host does not run systemd" - are better than
	// the requirement name alone, so they go into the sentence when it
	// recorded any. An adapter that is there in read mode is a refusal of
	// its own kind: the host has the module and said it can only read with
	// it, and why - no write mechanism for the network, no include for
	// sshd - so the operator learns what the host lacks, not that the
	// module is gone.
	capability := action.RequiredCapability()
	if !hostHasCapability(host, capability) {
		adapter := adapterOf(host.Capabilities, capability)
		said := host.Capabilities.Reason(adapter)
		if action.Mutating() && adapterReadOnly(host.Capabilities, adapter) {
			reason := "the host can only read with its " + adapter + " adapter"
			if said != "" {
				reason += ": " + said
			}
			return refuse(ReasonReadOnlyHost, reason)
		}
		reason := "the host lacks capability " + capability
		if said != "" {
			reason += ": " + said
		}
		return refuse(ReasonCapabilityMissing, reason)
	}

	if action.Mutating() {
		// Every change on the host goes through the root helper. An agent
		// that named the helper adapter and reported no mode is one whose
		// helper did not answer; an agent from before the adapter says
		// nothing, and nothing is not a refusal.
		if helperReportedUnreachable(host.Capabilities) {
			reason := "the root helper of this host did not answer the agent; a change would be refused on the host"
			if said := host.Capabilities.Reason(helperAdapter); said != "" {
				reason += " (" + said + ")"
			}
			return refuse(ReasonHelperUnavailable, reason)
		}
	} else if host.ConnectionState != connectionOnline {
		// A read is the host's answer now; there is none to have from a
		// host that is not on the line. A change is a target state and may
		// wait in the queue, which the note below says.
		return refuse(ReasonHostOffline, "the host is not connected; a read needs it on the line")
	}

	verdict.Allowed = true
	verdict.Note = actionNote(host, action)
	return verdict
}

// connectionOnline is the connection state of a host with a live session,
// as the hosts table spells it.
const connectionOnline = "online"

// lifecycleReasonCode maps a state that takes no order to its reason code.
// Retiring and retired are one code: in both the host is on its way out,
// and there is nothing the operator does to get it back.
func lifecycleReasonCode(state string) string {
	switch state {
	case hosts.StateQuarantined:
		return ReasonHostQuarantined
	case hosts.StateRecovery:
		return ReasonHostRecovery
	case hosts.StateRetiring, hosts.StateRetired:
		return ReasonHostRetired
	}
	return "host_" + state
}

// actionNote is what an operator wants to know before ordering an allowed
// action: that the order waits for the host, or that it asks for more than
// a click. The notes are facts about the road ahead, not refusals.
func actionNote(host *hosts.Host, action opspec.ActionType) string {
	var notes []string
	if action.Mutating() && host.ConnectionState != connectionOnline {
		notes = append(notes, "the host is not connected; the order waits in the queue until it is")
	}
	if action.RequiresPlan() {
		notes = append(notes, "needs an approved plan")
	}
	if action.RequiresFreshAuth() {
		notes = append(notes, "asks for fresh authentication and a reason")
	}
	if action.RequiresTargetConfirmation() {
		notes = append(notes, "asks for the target name typed in")
	}
	return strings.Join(notes, "; ")
}

// adapterOf names the adapter of the registry an operation requirement
// resolves to, or nothing when the host has none for it. A logical
// requirement - packages - maps to whichever package adapter the host has;
// a feature requirement - network.write - maps to the adapter that carries
// the feature; anything else is an adapter name already.
func adapterOf(registry hosts.Capabilities, requirement string) string {
	switch requirement {
	case "":
		return ""
	case hosts.NeedPackages, hosts.NeedPackageRepair:
		for _, adapter := range []string{hosts.CapAPT, hosts.CapDNF, hosts.CapPacman} {
			if registry.Available(adapter) {
				return adapter
			}
		}
		return ""
	case hosts.NeedNetworkWrite:
		return hosts.CapNetwork
	case hosts.NeedDNSWrite:
		return hosts.CapDNS
	case hosts.NeedFirewallWrite, hosts.NeedFirewallZones:
		return hosts.CapFirewall
	case hosts.NeedLVM:
		return hosts.CapStorage
	}
	return requirement
}

// adapterReadOnly says whether the host has the adapter and marked it as
// one it can only read with. It is consulted once the requirement of an
// action has failed, to tell "the module is not there" from "the module
// is there and cannot write"; the flag alone refuses nothing, because the
// helper, not the flag, decides what a change through a present adapter
// does.
func adapterReadOnly(registry hosts.Capabilities, adapter string) bool {
	for _, capability := range registry {
		if capability.Name == adapter {
			return capability.Available && capability.ReadOnly
		}
	}
	return false
}

// helperAdapter is the registry entry through which the agent reports the
// mode of its root helper; its features name the mode, and one of them is
// true once the helper has answered.
const helperAdapter = "helper.capability"

// helperReportedUnreachable says whether the agent named the helper
// adapter and reported no mode for it - the helper did not answer when the
// agent asked. An agent that does not name the adapter at all is from
// before it, and says nothing about the helper.
func helperReportedUnreachable(registry hosts.Capabilities) bool {
	for _, capability := range registry {
		if capability.Name != helperAdapter || !capability.Available {
			continue
		}
		for _, mode := range []string{"observe", "prefer", "enforce"} {
			if capability.Features[mode] {
				return false
			}
		}
		return true
	}
	return false
}
