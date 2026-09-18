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

	// CurrentLink and DesiredLink carry the layering of the interface: a
	// bond, a bridge or a VLAN, what it is made of and what it would be
	// made of. They are set for a layered change and empty for a change of
	// an address, a route or the resolver - those say nothing about what an
	// interface sits on.
	CurrentLink *LinkState `json:"current_link,omitempty"`
	DesiredLink *LinkState `json:"desired_link,omitempty"`

	// Refusal names the reason the change will not land on this host: no
	// NetworkManager, no profile on the interface, a configuration the host
	// will not accept. A plan with a refusal is an answer the operator is
	// meant to see before approving.
	Refusal string `json:"refusal,omitempty"`
	// RefusalCode is the typed code of the refusal where one exists:
	// link_member_taken, vlan_parent_missing, ipv6_disabled_on_host and the
	// rest of the layered codes. A refusal without a code is a plain
	// description of why nothing will happen.
	RefusalCode string `json:"refusal_code,omitempty"`

	// Adapter names the mechanism the change goes through on this host:
	// networkmanager, nmstate or netplan. The same difference written for
	// another mechanism is another change, so it is part of the fingerprint.
	Adapter string `json:"adapter,omitempty"`
	// Document is the text the adapter will apply: the nmstate document of
	// the touched interface or the panel's netplan file after the merge.
	// NetworkManager takes arguments, not a document, so it stays empty
	// there. The operator sees exactly what will land on the host.
	Document string `json:"document,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Plan operation and action names.
const (
	PlanMTU     = "mtu"
	PlanRoutes  = "routes"
	PlanProfile = "profile"
	PlanDNS     = "dns"
	// PlanLink builds or changes a layered interface; PlanLinkRemove takes
	// one away. They are separate kinds because the mechanisms write them
	// differently from an address: one adds an interface to the document,
	// the other takes an entry out of it.
	PlanLink       = "link"
	PlanLinkRemove = "link_remove"

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
//
// The operator types one list and the two families are separated here: the
// mechanisms keep them apart - a v6 route written into the v4 key of a
// profile is silently dropped - and an order that named both has to reach
// both. A list with no entry of one family clears that family, which is the
// same meaning the list has always had.
func ComputeRoutes(iface string, current Profile, routes []string) Plan {
	plan := newPlan(iface, current, PlanRoutes)
	for _, route := range routes {
		if err := ValidateRoute(route); err != nil {
			return plan.withRefusal(err.Error())
		}
	}
	desired := current
	desired.Routes, desired.Routes6 = SplitRouteFamilies(routes)
	if _, err := RouteArguments(current.Connection, desired.Routes, desired.Routes6); err != nil {
		return plan.withRefusal(err.Error())
	}
	return plan.withDesired(desired)
}

// SplitRouteFamilies puts every route in the list of its own family.
//
// The family of a route is the family of its destination: a v4 destination
// reached through a v6 next hop is not a thing the kernel carries. The
// operator types one list, and it is split here rather than at the screen,
// so that the plan and the write split it the same way.
func SplitRouteFamilies(routes []string) (v4 []string, v6 []string) {
	v4, v6 = []string{}, []string{}
	for _, route := range routes {
		fields := strings.Fields(route)
		if len(fields) == 0 {
			continue
		}
		if strings.Contains(fields[0], ":") {
			v6 = append(v6, route)
			continue
		}
		v4 = append(v4, route)
	}
	return v4, v6
}

// ProfileRequest is the address profile the operator ordered, both
// families at once.
//
// IPv4 and IPv6 are two states of one interface, not one state with a
// second spelling: a host can take its v4 address from DHCP and hold a
// static v6 one at the same time, and an order that could name only one of
// them would leave the other to whatever was there before. A family the
// order says nothing about is left alone; that is what an empty method
// means here.
type ProfileRequest struct {
	Method    string
	Addresses []string
	Gateway   string
	DNS       []string

	Method6    string
	Addresses6 []string
	Gateway6   string
	// AcceptRA and Privacy are the router advertisement and the privacy
	// extensions, where the mechanism exposes them. Empty leaves the
	// setting as the host has it.
	AcceptRA string
	Privacy  string
}

// DescribesIPv6 says whether the order carries anything about the second
// family. A plan for such an order on a host with IPv6 switched off is a
// refusal, not a write into the void.
func (r ProfileRequest) DescribesIPv6() bool {
	return r.Method6 != "" || len(r.Addresses6) > 0 || r.Gateway6 != "" ||
		r.AcceptRA != "" || r.Privacy != ""
}

// ComputeProfile computes the difference for the address profile.
//
// The routes and the MTU stay as the host has them: the address profile is
// a separate operation and must not silently wipe settings the operator was
// not asked about. That is why they are in Desired but not in Changes.
//
// The second family is held to the same standard as the first: it is
// planned, written and read back, and where the host has it switched off
// the plan says so rather than writing an address nobody will ever find.
func ComputeProfile(iface string, current Profile, want ProfileRequest, ipv6 IPv6Settings) Plan {
	plan := newPlan(iface, current, PlanProfile)
	if want.DescribesIPv6() && ipv6.Off() {
		return plan.withTypedRefusal(&LinkRefusal{Code: CodeIPv6Disabled,
			Reason: "the host has IPv6 switched off on " + iface +
				"; an address, a route or a router advertisement setting written there would never take effect"})
	}
	// The type travels with the profile: the mechanisms that apply a
	// document name the interface by it, also in the document that goes the
	// other way on rollback.
	// A family the order left out keeps what the host has, down to its
	// routes: the operator asked about one family and gets one family. An
	// order about IPv6 alone must not wipe the IPv4 address on the way
	// past, and the other way round.
	desired := Profile{
		Connection: current.Connection, Interface: current.Interface, Type: current.Type,
		Method: current.Method, Addresses: current.Addresses,
		Gateway: current.Gateway, DNS: current.DNS,
		DNSSearch: current.DNSSearch, IgnoreAutoDNS: current.IgnoreAutoDNS,
		Routes: current.Routes, MTU: current.MTU,
		Method6: current.Method6, Addresses6: current.Addresses6,
		Gateway6: current.Gateway6, Routes6: current.Routes6,
		AcceptRA: current.AcceptRA, Privacy: current.Privacy,
	}
	if want.Method != "" {
		desired.Method = want.Method
		desired.Addresses = append([]string(nil), want.Addresses...)
		desired.Gateway = want.Gateway
		desired.DNS = append([]string(nil), want.DNS...)
	}
	if want.Method6 != "" {
		desired.Method6 = want.Method6
		desired.Addresses6 = append([]string(nil), want.Addresses6...)
		desired.Gateway6 = want.Gateway6
	}
	if want.AcceptRA != "" {
		desired.AcceptRA = want.AcceptRA
	}
	if want.Privacy != "" {
		desired.Privacy = want.Privacy
	}
	// The shape is checked here, without any one mechanism's limits: the
	// plan is computed the same way on every host, and which mechanism can
	// express which setting is that mechanism's own answer, attached to the
	// plan together with the document it would write.
	if err := ValidateProfile(desired); err != nil {
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
	p.RefusalCode = ""
	p.PlanHash = planFingerprint(*p)
}

// RefuseWith records a refusal that has a typed code of its own.
func (p *Plan) RefuseWith(code, reason string) {
	p.Refusal = reason
	p.RefusalCode = code
	p.PlanHash = planFingerprint(*p)
}

// Attach records the adapter and the document the change will go through
// and recomputes the fingerprint: the same difference applied by another
// mechanism, or with another document, is another change.
func (p *Plan) Attach(adapter, document string) {
	p.Adapter = adapter
	p.Document = document
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

func (p Plan) withTypedRefusal(refusal *LinkRefusal) Plan {
	p.Refusal = refusal.Reason
	p.RefusalCode = refusal.Code
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
	// The second family is listed on its own lines. Folding both into one
	// sentence would hide which family an address belongs to, and that is
	// the one thing an operator reading a dual-stack plan has to see.
	if current.Method6 != desired.Method6 {
		changes = append(changes, "IPv6 method from "+orNone(current.Method6)+" to "+orNone(desired.Method6))
	}
	if !sameSet(current.Addresses6, desired.Addresses6) {
		changes = append(changes, "IPv6 addresses from "+list(current.Addresses6)+" to "+list(desired.Addresses6))
	}
	if current.Gateway6 != desired.Gateway6 {
		changes = append(changes, "IPv6 gateway from "+orNone(current.Gateway6)+" to "+orNone(desired.Gateway6))
	}
	if !sameSet(current.Routes6, desired.Routes6) {
		changes = append(changes, "IPv6 routes from "+list(current.Routes6)+" to "+list(desired.Routes6))
	}
	if current.AcceptRA != desired.AcceptRA {
		changes = append(changes, "router advertisements from "+orNone(current.AcceptRA)+" to "+orNone(desired.AcceptRA))
	}
	if current.Privacy != desired.Privacy {
		changes = append(changes, "IPv6 privacy extensions from "+orNone(current.Privacy)+" to "+orNone(desired.Privacy))
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
