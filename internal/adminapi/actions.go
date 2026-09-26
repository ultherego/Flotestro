package adminapi

import (
	"net/http"
	"strings"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/contract"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// What one host lets one operator do, action by action.

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
	// ReasonReadOnlyHost: the adapter is there, but the host said it can only
	// read with it - no mechanism that persists a network change, no resolver the
	// panel may write - so the write the action needs is not among its features.
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
	// MissingPermission names the permission a permission_denied verdict is
	// about: the action's own, or job.
	MissingPermission string `json:"missing_permission,omitempty"`
	// Note is a fact about an allowed action the operator wants before the click:
	// the order will wait in the queue for an offline host, or it will ask for
	// fresh authentication.
	Note string `json:"note,omitempty"`
}

// handleListHostActions answers GET /api/v1/hosts/{id}/actions: every action
// of the catalogue with whether this operator may order it on this host now,
// and why not otherwise.
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
// host, and the three lifecycle orders after them.
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

// lifecycleAction and the table of transitions live in internal/contract: the
// generator that writes the interface's copy of the catalogue reads them from
// there, so the two cannot drift.
type lifecycleAction = contract.LifecycleAction

var hostLifecycleActions = contract.HostLifecycleActions

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

	// Ordering anything at all is one permission; this operation is a second one.
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

	// The registry decides, as it does for the order.
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
		// Every change on the host goes through the root helper.
		if helperReportedUnreachable(host.Capabilities) {
			reason := "the root helper of this host did not answer the agent; a change would be refused on the host"
			if said := host.Capabilities.Reason(helperAdapter); said != "" {
				reason += " (" + said + ")"
			}
			return refuse(ReasonHelperUnavailable, reason)
		}
	} else if host.ConnectionState != connectionOnline {
		// A read is the host's answer now; there is none to have from a host that is
		// not on the line.
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
// action: that the order waits for the host, or that it asks for more than a
// click.
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
// resolves to, or nothing when the host has none for it.
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

// adapterReadOnly says whether the host has the adapter and marked it as one
// it can only read with.
func adapterReadOnly(registry hosts.Capabilities, adapter string) bool {
	for _, capability := range registry {
		if capability.Name == adapter {
			return capability.Available && capability.ReadOnly
		}
	}
	return false
}

// helperAdapter is the registry entry through which the agent reports the mode
// of its root helper; its features name the mode, and one of them is true once
// the helper has answered.
const helperAdapter = "helper.capability"

// helperReportedUnreachable says whether the agent named the helper adapter
// and reported no mode for it - the helper did not answer when the agent
// asked.
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
