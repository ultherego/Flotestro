package adminapi

import (
	"net/http"
	"sort"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The fleet answers "who can carry out this operation" one operation at a time:
// the campaign preview asks it, and the qualification behind it already groups
// the hosts into ready and ineligible with the reason. What nothing answered is
// the transpose - "what cannot be carried out on this fleet, and why" - and
// that is the question an operator starts the day with.
//
// Nothing new is measured here. Every agent reports its adapter registry with a
// reason for each adapter it does not offer, and every operation says which
// adapter it needs. This puts the two together and groups by the cause rather
// than by the host, because "three hosts have no Docker Compose plugin" is one
// thing to fix and not three.

// ReadinessGap is one adapter requirement the fleet does not meet everywhere,
// and what it costs.
type ReadinessGap struct {
	// Requirement is the name an operation asks for - an adapter, a family of
	// them, or an adapter and a feature.
	Requirement string `json:"requirement"`
	// Operations are the operations that cannot be ordered without it, by name,
	// so the cost is read in work and not in packages.
	Operations []string `json:"operations"`
	// Hosts are the hosts that do not meet it, each with what it said about why.
	Hosts []ReadinessHost `json:"hosts"`
	// Satisfied counts the hosts that do meet it. A requirement no host meets is
	// a property of the installation; one that most hosts meet is a property of
	// the few that do not.
	Satisfied int `json:"satisfied"`
	// Nowhere says no visible host meets it at all.
	Nowhere bool `json:"nowhere"`
}

// ReadinessHost is one host against one requirement.
type ReadinessHost struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	// Reason is what the agent said about the adapter. Empty when the host has
	// never reported it, which is a different thing from reporting that it is
	// missing: the first is unknown, the second is a no.
	Reason string `json:"reason,omitempty"`
	// Silent says the host has reported no adapter registry at all, so nothing
	// here is known about it rather than known to be absent.
	Silent bool `json:"silent,omitempty"`
}

// FleetReadiness is what stands between this fleet and being managed.
type FleetReadiness struct {
	// Hosts is how many were looked at, and Silent how many have reported no
	// registry. A fleet whose hosts are silent is not a fleet with no gaps.
	Hosts  int `json:"hosts"`
	Silent int `json:"silent"`
	// Operations is how many of the product's operations name an adapter at all.
	Operations int `json:"operations"`
	// Unorderable counts the operations no visible host can be sent. This is the
	// one number worth putting on a screen: it is the work this installation
	// cannot do anywhere.
	Unorderable int            `json:"unorderable"`
	Gaps        []ReadinessGap `json:"gaps"`
}

func (s *Server) handleFleetReadiness(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "fleet")
	if !ok {
		return
	}
	list, err := s.hosts.List(r.Context(), hosts.ListFilter{
		Scopes: principal.ScopesFor(authz.PermHostRead),
	})
	if err != nil {
		s.fail(w, err)
		return
	}

	// Only the hosts an operation could be sent to. A retired host that cannot
	// do something is not a gap, and counting it as one is how a screen like
	// this fills with things nobody will act on.
	active := make([]hosts.Host, 0, len(list))
	silent := 0
	for _, host := range list {
		if !hosts.Active(host.LifecycleState) {
			continue
		}
		active = append(active, host)
		if len(host.Capabilities) == 0 {
			silent++
		}
	}

	// What each requirement costs, in operations, from the product's own table.
	cost := map[string][]string{}
	for _, action := range opspec.AllActions() {
		if requirement := action.RequiredCapability(); requirement != "" {
			cost[requirement] = append(cost[requirement], string(action))
		}
	}

	readiness := FleetReadiness{Hosts: len(active), Silent: silent}
	for _, operations := range cost {
		readiness.Operations += len(operations)
	}
	for requirement, operations := range cost {
		gap := ReadinessGap{Requirement: requirement}
		for _, host := range active {
			// Satisfies is the product's own rule, which knows that "packages"
			// is apt or dnf or pacman and that an adapter silent about its
			// features leaves the decision to execution time. Asking anything
			// simpler here would answer a different question than the one the
			// panel answers when the operation is ordered.
			if host.Capabilities.Satisfies(requirement) {
				gap.Satisfied++
				continue
			}
			entry := ReadinessHost{ID: host.ID, Hostname: host.Hostname}
			if len(host.Capabilities) == 0 {
				entry.Silent = true
			} else {
				entry.Reason = capabilityReason(host.Capabilities, requirement)
			}
			gap.Hosts = append(gap.Hosts, entry)
		}
		if len(gap.Hosts) == 0 {
			continue
		}
		sort.Strings(operations)
		gap.Operations = operations
		gap.Nowhere = gap.Satisfied == 0
		if gap.Nowhere {
			readiness.Unorderable += len(operations)
		}
		sort.Slice(gap.Hosts, func(i, j int) bool { return gap.Hosts[i].Hostname < gap.Hosts[j].Hostname })
		readiness.Gaps = append(readiness.Gaps, gap)
	}
	// The costliest first, and the ties by name so two readings of one fleet
	// come out in the same order.
	sort.Slice(readiness.Gaps, func(i, j int) bool {
		left, right := readiness.Gaps[i], readiness.Gaps[j]
		if left.Nowhere != right.Nowhere {
			return left.Nowhere
		}
		if len(left.Operations) != len(right.Operations) {
			return len(left.Operations) > len(right.Operations)
		}
		return left.Requirement < right.Requirement
	})
	if readiness.Gaps == nil {
		readiness.Gaps = []ReadinessGap{}
	}
	writeJSON(w, http.StatusOK, readiness)
}

// capabilityReason is the sentence that explains this host's gap.
//
// The first version took the first adapter behind the requirement that was
// unavailable and had something to say. On a family that is wrong in a way
// that reads as a lie: agent-fedora was told "apt-get is not installed on this
// host" about packages.repair, when the host uses dnf and dnf simply offers no
// repair. And where the adapter is present and only the feature is missing -
// firewalld without zones - no adapter was unavailable at all, so the column
// said "gave no reason" about a host that had been perfectly clear.
//
// So the adapter the host actually has is asked first.
func capabilityReason(registry hosts.Capabilities, requirement string) string {
	feature := hosts.FeatureBehind(requirement)
	adapters := hosts.AdaptersBehind(requirement)

	// The adapter this host holds, which is the one the requirement is really
	// about here. It is present and does not do the thing asked of it.
	if feature != "" {
		for _, adapter := range adapters {
			if !registry.Available(adapter) {
				continue
			}
			if value, known := registry.FeatureState(adapter, feature); known && !value {
				return adapter + " is here and offers no " + feature
			}
			return adapter + " says nothing about " + feature
		}
	}

	// Otherwise the adapters that are absent, and what the host said about
	// them. Only the ones it could plausibly use: a Debian host explaining that
	// pacman is missing is noise.
	for _, adapter := range adapters {
		for _, entry := range registry {
			if entry.Name == adapter && !entry.Available && entry.Reason != "" {
				return entry.Reason
			}
		}
	}
	return ""
}
