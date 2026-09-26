// Package contract holds what the panel, the agent and the interface have to
// agree about: the orders that exist, who may give them and when. It is here
// rather than inside the panel's HTTP layer because the generator that writes
// the interface's copy of the catalogue reads it too, and a catalogue kept in
// two places by hand is a catalogue that disagrees with itself.
package contract

import (
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// LifecycleAction is one of the orders that change what the panel thinks of a
// host rather than the host itself: they are not in the operation catalogue,
// have no adapter and no job, and take a host in some states only.
type LifecycleAction struct {
	// Action is the name the audit trail records the order under, which is
	// also its permission.
	Action     string
	Permission authz.Permission
	FromStates []string
}

// HostLifecycleActions mirrors the transitions of lifecycle.
var HostLifecycleActions = []LifecycleAction{
	{Action: "host.quarantine", Permission: authz.PermHostQuarantine,
		FromStates: []string{hosts.StateActive, hosts.StateRecovery, hosts.StateQuarantined}},
	{Action: "host.quarantine.release", Permission: authz.PermHostQuarantineRelease,
		FromStates: []string{hosts.StateQuarantined}},
	{Action: "host.decommission", Permission: authz.PermHostDecommission,
		FromStates: []string{hosts.StateActive, hosts.StateQuarantined, hosts.StateRecovery, hosts.StateRetiring}},
}
