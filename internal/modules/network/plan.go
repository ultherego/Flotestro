package network

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Plan describes the difference between the network profile found and the
// one requested on a single host.
//
// "Set MTU 9000 on eth1" or "a static address on eth1" means something
// different on every host: a different NetworkManager profile, different
// routes and DNS that are to stay, one host already has it. The operator's
// approval is meant to cover those differences, not the intent alone - and
// that is why the plan is made on the host.
type Plan struct {
	Interface string `json:"interface"`
	// Connection is the NetworkManager profile the host has on this
	// interface. The panel does not create new profiles: no profile is a
	// refusal.
	Connection string `json:"connection,omitempty"`
	// Operation names which change was planned: mtu, routes or profile.
	Operation string `json:"operation"`
	// Action names what would happen: update or no_change.
	Action string `json:"action"`

	Current *Profile `json:"current,omitempty"`
	Desired *Profile `json:"desired,omitempty"`
	// Changes lists in human terms what will change.
	Changes []string `json:"changes,omitempty"`

	// Refusal names the reason the change will not land on this host: no
	// NetworkManager, no profile on the interface, a configuration the host
	// will not accept. A plan with a refusal is an answer the operator is
	// meant to see before approving.
	Refusal string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Plan operation and action names.
const (
	PlanMTU     = "mtu"
	PlanRoutes  = "routes"
	PlanProfile = "profile"
	PlanDNS     = "dns"

	PlanUpdate   = "update"
	PlanNoChange = "no_change"
)

// ComputeMTU computes the difference for an MTU change of a profile.
func ComputeMTU(iface string, current Profile, mtu string) Plan {
	plan := newPlan(iface, current, PlanMTU)
	if _, err := MTUArguments(current.Connection, mtu); err != nil {
		return plan.withRefusal(err.Error())
	}
	desired := current
	desired.MTU = mtu
	return plan.withDesired(desired)
}

// ComputeRoutes computes the difference for the full route list of a
// profile.
func ComputeRoutes(iface string, current Profile, routes []string) Plan {
	plan := newPlan(iface, current, PlanRoutes)
	if _, err := RouteArguments(current.Connection, routes); err != nil {
		return plan.withRefusal(err.Error())
	}
	desired := current
	desired.Routes = append([]string(nil), routes...)
	return plan.withDesired(desired)
}

// ComputeProfile computes the difference for the address profile.
//
// The routes and the MTU stay as the host has them: the address profile is
// a separate operation and must not silently wipe settings the operator was
// not asked about. That is why they are in Desired but not in Changes.
func ComputeProfile(iface string, current Profile, method string, addresses []string,
	gateway string, dns []string) Plan {
	plan := newPlan(iface, current, PlanProfile)
	desired := Profile{
		Connection: current.Connection, Interface: current.Interface,
		Method: method, Addresses: append([]string(nil), addresses...),
		Gateway: gateway, DNS: append([]string(nil), dns...),
		DNSSearch: current.DNSSearch, IgnoreAutoDNS: current.IgnoreAutoDNS,
		Routes: current.Routes, MTU: current.MTU,
	}
	if _, err := ProfileArguments(desired); err != nil {
		return plan.withRefusal(err.Error())
	}
	return plan.withDesired(desired)
}

// ComputeDNS computes the difference for the resolver alone: the servers,
// the search domains and whether the DHCP servers are rejected. The rest of
// the profile stays as the host has it.
func ComputeDNS(iface string, current Profile, servers, domains []string,
	ignoreAuto bool) Plan {
	plan := newPlan(iface, current, PlanDNS)
	if _, err := DNSArguments(current.Connection, servers, domains, ignoreAuto); err != nil {
		return plan.withRefusal(err.Error())
	}
	desired := current
	desired.DNS = append([]string(nil), servers...)
	desired.DNSSearch = append([]string(nil), domains...)
	desired.IgnoreAutoDNS = ignoreAuto
	return plan.withDesired(desired)
}

// RefusedPlan builds a plan for a host on which there is nothing to
// compare: without NetworkManager or without a profile on the interface.
func RefusedPlan(iface, operation, reason string) Plan {
	plan := Plan{Interface: iface, Operation: operation}
	return plan.withRefusal(reason)
}

// Refuse records a refusal reason learned after the differences were
// computed and recomputes the fingerprint: a plan with a refusal is a
// different answer than a plan without one.
func (p *Plan) Refuse(reason string) {
	p.Refusal = reason
	p.PlanHash = planFingerprint(*p)
}

func newPlan(iface string, current Profile, operation string) Plan {
	found := current
	return Plan{
		Interface: iface, Connection: current.Connection,
		Operation: operation, Current: &found,
	}
}

func (p Plan) withRefusal(reason string) Plan {
	p.Refusal = reason
	p.PlanHash = planFingerprint(p)
	return p
}

func (p Plan) withDesired(desired Profile) Plan {
	p.Desired = &desired
	p.Changes = differences(*p.Current, desired)
	p.Action = PlanUpdate
	if len(p.Changes) == 0 {
		p.Action = PlanNoChange
	}
	p.PlanHash = planFingerprint(p)
	return p
}

// differences lists the changes visible to a human.
func differences(current, desired Profile) []string {
	var changes []string
	if current.Method != desired.Method {
		changes = append(changes, fmt.Sprintf("method from %s to %s",
			orNone(current.Method), orNone(desired.Method)))
	}
	if !sameSet(current.Addresses, desired.Addresses) {
		changes = append(changes, "addresses from "+list(current.Addresses)+" to "+list(desired.Addresses))
	}
	if current.Gateway != desired.Gateway {
		changes = append(changes, "gateway from "+orNone(current.Gateway)+" to "+orNone(desired.Gateway))
	}
	if !sameSet(current.DNS, desired.DNS) {
		changes = append(changes, "DNS from "+list(current.DNS)+" to "+list(desired.DNS))
	}
	if !sameSet(current.DNSSearch, desired.DNSSearch) {
		changes = append(changes, "search domains from "+list(current.DNSSearch)+
			" to "+list(desired.DNSSearch))
	}
	if current.IgnoreAutoDNS != desired.IgnoreAutoDNS {
		if desired.IgnoreAutoDNS {
			changes = append(changes, "DHCP servers will be rejected")
		} else {
			changes = append(changes, "DHCP servers will be accepted")
		}
	}
	if !sameSet(current.Routes, desired.Routes) {
		changes = append(changes, "routes from "+list(current.Routes)+" to "+list(desired.Routes))
	}
	if current.MTU != desired.MTU {
		changes = append(changes, "MTU from "+orNone(current.MTU)+" to "+orNone(desired.MTU))
	}
	return changes
}

// sameSet compares lists as sets: the order of addresses or routes is not
// the operator's decision.
func sameSet(a, b []string) bool {
	return reflect.DeepEqual(sorted(a), sorted(b))
}

func sorted(items []string) []string {
	copied := []string{}
	for _, element := range items {
		if element = strings.TrimSpace(element); element != "" {
			copied = append(copied, element)
		}
	}
	sort.Strings(copied)
	return copied
}

func list(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(sorted(items), ",")
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

// planFingerprint computes the plan fingerprint excluding the fingerprint
// itself.
//
// It covers the found and the desired state together: the same diff
// computed against a profile that changed in the meantime is a different
// change.
func planFingerprint(plan Plan) string {
	stripped := plan
	stripped.PlanHash = ""
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
