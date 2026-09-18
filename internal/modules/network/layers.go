package network

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Refusal codes of a change to a layered interface.
//
// Each one is a typed answer the panel and the operator can act on, and the
// message that travels with it names the particular interface. A layered
// change is the one place in this module where the mistake is not a wrong
// value but a wrong relation - a member somebody else already owns, a VLAN
// on a parent that is not there - and a relation refused as "malformed"
// would tell the operator nothing.
const (
	// CodeLinkMemberTaken: the interface is already a member of another
	// bond or bridge. Taking it would silently remove it from there, and
	// whatever ran over that layer would stop.
	CodeLinkMemberTaken = "link_member_taken"
	// CodeLinkMemberMissing: the host does not have the interface the
	// layer is to be built from.
	CodeLinkMemberMissing = "link_member_missing"
	// CodeBondNeedsMembers: a bond of one member is a slower copy of that
	// member with none of the redundancy it exists for.
	CodeBondNeedsMembers = "bond_needs_two_members"
	// CodeVLANParentMissing: the interface the tagged traffic would run on
	// is not on the host.
	CodeVLANParentMissing = "vlan_parent_missing"
	// CodeLinkSwallowsManagement: a member of the layer is the interface
	// the panel talks to the host over. Enslaving it moves its address to
	// the layer above, and the host is gone before the layer is finished.
	CodeLinkSwallowsManagement = "link_swallows_management"
	// CodeLinkCarriesManagement: the layer being removed is the one the
	// panel talks over.
	CodeLinkCarriesManagement = "link_carries_management"
	// CodeLinkKindMismatch: the host already has an interface of this name
	// and it is something else. The panel does not turn a network card
	// into a bridge under the same name.
	CodeLinkKindMismatch = "link_kind_mismatch"
	// CodeLinkNotLayered: the interface named for removal is a physical
	// link or one the panel did not build.
	CodeLinkNotLayered = "link_not_layered"
	// CodeLinkInUse: the layer carries VLANs or is itself a member of
	// another layer; removing it takes them with it.
	CodeLinkInUse = "link_in_use"
	// CodeLinkMechanismUnsupported: the host configures its network
	// through a mechanism this module does not write layered interfaces
	// with. Half a bond is worse than none.
	CodeLinkMechanismUnsupported = "link_mechanism_unsupported"
	// CodeIPv6Disabled: the order carries an IPv6 setting and the host has
	// the second family switched off. The write would go into the void and
	// the verifier would never find it.
	CodeIPv6Disabled = "ipv6_disabled_on_host"
)

// LinkRefusal is a refusal of a layered change with a typed code. The
// helper answers with the code, the panel shows the reason.
type LinkRefusal struct {
	Code   string
	Reason string
}

func (r *LinkRefusal) Error() string { return r.Reason }

// The bond modes the kernel knows, in the spelling it uses itself.
var bondModes = []string{
	"balance-rr", "active-backup", "balance-xor", "broadcast",
	"802.3ad", "balance-tlb", "balance-alb",
}

// The LACP rates of an 802.3ad bond.
var lacpRates = []string{"slow", "fast"}

// The VLAN protocols. 802.1ad is the outer tag of a stacked VLAN; a host
// whose driver cannot do it will say so, but the panel does not refuse it
// on the operator's behalf.
var vlanProtocols = []string{"802.1Q", "802.1ad"}

// LinkSpec is the layered interface the operator ordered.
//
// It describes the target state of one link, never the commands to reach
// it: the same specification is what the plan compares against, what the
// mechanism writes and what the verifier reads back.
type LinkSpec struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Members are the interfaces the bond or the bridge is built from. A
	// VLAN has none: its one lower interface is the parent.
	Members []string `json:"members,omitempty"`
	// The bond settings. MIIMonMS zero means the monitoring is off, which
	// is a decision; the panel writes it as given rather than filling in a
	// default the operator never saw.
	Mode     string `json:"mode,omitempty"`
	MIIMonMS int    `json:"miimon_ms,omitempty"`
	Primary  string `json:"primary,omitempty"`
	LACPRate string `json:"lacp_rate,omitempty"`
	// The bridge settings.
	STP           bool `json:"stp,omitempty"`
	VLANFiltering bool `json:"vlan_filtering,omitempty"`
	// The VLAN settings.
	Parent   string `json:"parent,omitempty"`
	VLANID   int    `json:"vlan_id,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	// MTU is text, because "auto" is an equal value here, exactly as it is
	// for a plain interface.
	MTU string `json:"mtu,omitempty"`
}

// LinkState is the layering of one interface: what the host has now, or
// what the change would leave behind.
type LinkState struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
	// Present says whether the host has the interface at all. A state that
	// is not present is the way a creation and a removal are written down
	// in the same shape.
	Present bool     `json:"present"`
	Members []string `json:"members,omitempty"`

	Mode     string `json:"mode,omitempty"`
	MIIMonMS int    `json:"miimon_ms,omitempty"`
	Primary  string `json:"primary,omitempty"`
	LACPRate string `json:"lacp_rate,omitempty"`

	STP           bool `json:"stp,omitempty"`
	VLANFiltering bool `json:"vlan_filtering,omitempty"`

	Parent   string `json:"parent,omitempty"`
	VLANID   int    `json:"vlan_id,omitempty"`
	Protocol string `json:"protocol,omitempty"`

	MTU string `json:"mtu,omitempty"`
	// Management marks the layer the panel talks to the host over.
	Management bool `json:"management,omitempty"`
}

// LinkStateOf reads the layering of one interface out of the snapshot. An
// interface the host does not report comes back as a state that is not
// present - which is an answer, not a zero value.
func LinkStateOf(snapshot Snapshot, name string) LinkState {
	state := LinkState{Name: name}
	iface := snapshot.InterfaceByName(name)
	if iface == nil {
		return state
	}
	state.Present = true
	state.Kind = iface.LayerKind()
	state.Management = iface.Management
	if iface.MTU > 0 {
		state.MTU = strconv.Itoa(iface.MTU)
	}
	switch {
	case iface.Bond != nil:
		state.Members = sorted(iface.Bond.Members)
		state.Mode = iface.Bond.Mode
		state.MIIMonMS = iface.Bond.MIIMonMS
		state.Primary = iface.Bond.Primary
		state.LACPRate = iface.Bond.LACPRate
	case iface.Bridge != nil:
		state.Members = sorted(iface.Bridge.Members)
		state.STP = iface.Bridge.STP
		state.VLANFiltering = iface.Bridge.VLANFiltering
		state.Protocol = iface.Bridge.VLANProtocol
	case iface.VLAN != nil:
		state.Parent = iface.VLAN.Parent
		state.VLANID = iface.VLAN.ID
		state.Protocol = iface.VLAN.Protocol
	}
	// The members the layer itself reports and the ones the kernel keeps on
	// the member side have to agree; where the layer said nothing, the
	// member side is the answer.
	if state.Kind == LinkBond || state.Kind == LinkBridge {
		if owned := sorted(snapshot.MembersOf(name)); len(owned) > 0 {
			state.Members = owned
		}
	}
	return state
}

// desiredState turns the order into the state the host would have.
func desiredState(spec LinkSpec, current LinkState) LinkState {
	state := LinkState{
		Name: spec.Name, Kind: spec.Kind, Present: true,
		Members: sorted(spec.Members), MTU: spec.MTU,
		Management: current.Management,
	}
	switch spec.Kind {
	case LinkBond:
		state.Mode = spec.Mode
		state.MIIMonMS = spec.MIIMonMS
		state.Primary = spec.Primary
		state.LACPRate = spec.LACPRate
	case LinkBridge:
		state.STP = spec.STP
		state.VLANFiltering = spec.VLANFiltering
	case LinkVLAN:
		state.Members = nil
		state.Parent = spec.Parent
		state.VLANID = spec.VLANID
		state.Protocol = spec.Protocol
	}
	if state.MTU == "" {
		state.MTU = current.MTU
	}
	return state
}

// ValidateLinkSpec checks the shape of the order: the names the kernel
// would accept, a kind this module knows, and values within the ranges the
// drivers take. It says nothing about the host - that is what the plan is
// for - so the panel can run it before the order is ever sent.
func ValidateLinkSpec(spec LinkSpec) error {
	if err := ValidateInterfaceName(spec.Name); err != nil {
		return err
	}
	switch spec.Kind {
	case LinkBond, LinkBridge, LinkVLAN:
	default:
		return fmt.Errorf("unsupported layer kind %q; the panel builds a bond, a bridge or a VLAN", spec.Kind)
	}
	seen := map[string]bool{}
	for _, member := range spec.Members {
		if err := ValidateInterfaceName(member); err != nil {
			return fmt.Errorf("member: %w", err)
		}
		if member == spec.Name {
			return fmt.Errorf("the interface %s cannot be a member of itself", member)
		}
		if seen[member] {
			return fmt.Errorf("the member %s is named twice", member)
		}
		seen[member] = true
	}
	if spec.MTU != "" {
		if err := ValidateMTU(spec.MTU); err != nil {
			return err
		}
	}
	switch spec.Kind {
	case LinkBond:
		// A bond of one member is the same link with a driver in between:
		// no redundancy, no more traffic, and the member's address moved
		// onto the layer for nothing. This is a property of the order,
		// knowable without asking any host, so it is refused here - with
		// the code the host would have used - instead of being sent out.
		if len(spec.Members) < 2 {
			return &LinkRefusal{Code: CodeBondNeedsMembers,
				Reason: "the bond " + spec.Name + " would have " + strconv.Itoa(len(spec.Members)) +
					" member(s); a bond carries traffic over at least two, and with one it is the same link with a driver in between"}
		}
		if !contains(bondModes, spec.Mode) {
			return fmt.Errorf("unsupported bond mode %q; the kernel knows %s",
				spec.Mode, strings.Join(bondModes, ", "))
		}
		// A monitoring interval the driver would round to nothing is not
		// monitoring; above a minute a dead member keeps taking traffic for
		// longer than any operator would call a failover.
		if spec.MIIMonMS != 0 && (spec.MIIMonMS < 50 || spec.MIIMonMS > 60000) {
			return fmt.Errorf("the link monitoring interval %d ms is outside the range 50-60000; zero switches it off", spec.MIIMonMS)
		}
		if spec.Primary != "" {
			if err := ValidateInterfaceName(spec.Primary); err != nil {
				return fmt.Errorf("primary member: %w", err)
			}
			if !seen[spec.Primary] {
				return fmt.Errorf("the primary member %s is not among the members", spec.Primary)
			}
		}
		if spec.LACPRate != "" {
			if !contains(lacpRates, spec.LACPRate) {
				return fmt.Errorf("unsupported LACP rate %q; the kernel knows %s",
					spec.LACPRate, strings.Join(lacpRates, ", "))
			}
			if spec.Mode != "802.3ad" {
				return fmt.Errorf("the LACP rate belongs to the mode 802.3ad, not to %s", spec.Mode)
			}
		}
		if spec.Parent != "" || spec.VLANID != 0 {
			return fmt.Errorf("a bond has members, not a parent and a VLAN identifier")
		}
	case LinkBridge:
		if spec.Parent != "" || spec.VLANID != 0 {
			return fmt.Errorf("a bridge has members, not a parent and a VLAN identifier")
		}
	case LinkVLAN:
		if len(spec.Members) > 0 {
			return fmt.Errorf("a VLAN runs on one parent interface, not on a list of members")
		}
		if err := ValidateInterfaceName(spec.Parent); err != nil {
			return fmt.Errorf("parent: %w", err)
		}
		if spec.Parent == spec.Name {
			return fmt.Errorf("the VLAN %s cannot run on itself", spec.Name)
		}
		// 0 is "no VLAN" and 4095 is reserved; neither is a tag a host
		// carries traffic on.
		if spec.VLANID < 1 || spec.VLANID > 4094 {
			return fmt.Errorf("the VLAN identifier %d is outside the range 1-4094", spec.VLANID)
		}
		if spec.Protocol != "" && !contains(vlanProtocols, spec.Protocol) {
			return fmt.Errorf("unsupported VLAN protocol %q; the kernel knows %s",
				spec.Protocol, strings.Join(vlanProtocols, ", "))
		}
	}
	return nil
}

// LayerAdapterRefusal says whether the mechanism this host configures its
// network with can express a layered interface at all.
//
// nmstate and netplan describe a whole interface, so a bond is one more
// entry in a document they already own. Plain NetworkManager is driven here
// by changing the profile that exists on an interface, and a bond is not a
// change to a profile: it is several new profiles whose half-written state
// has no way back through the rollback this module arms. Saying so is the
// honest answer; writing half a bond on a host the panel then cannot reach
// is not.
func LayerAdapterRefusal(adapter string) *LinkRefusal {
	switch adapter {
	case AdapterNmstate, AdapterNetplan:
		return nil
	case AdapterNetworkManager:
		return &LinkRefusal{Code: CodeLinkMechanismUnsupported,
			Reason: "this host is configured through NetworkManager alone, which this module drives by changing the profile an interface already has; building a bond, a bridge or a VLAN needs nmstate or netplan"}
	}
	return &LinkRefusal{Code: CodeLinkMechanismUnsupported,
		Reason: "this host has no NetworkManager, nmstate or netplan; its network configuration is read-only here"}
}

// ComputeLink computes the difference between the layering the host has and
// the one ordered.
//
// The whole snapshot goes in, not just the one interface: every refusal
// here is about a relation to something else on the host - a member another
// layer owns, a parent that is not there, the interface the panel itself
// talks over - and a plan computed against one interface could see none of
// them.
func ComputeLink(snapshot Snapshot, adapter string, spec LinkSpec) Plan {
	current := LinkStateOf(snapshot, spec.Name)
	plan := Plan{
		Interface: spec.Name, Connection: spec.Name,
		Operation: PlanLink, CurrentLink: &current,
	}
	if err := ValidateLinkSpec(spec); err != nil {
		// A refusal of the shape that has a code of its own keeps it: the
		// panel and the host name the same fault the same way.
		var refusal *LinkRefusal
		if errors.As(err, &refusal) {
			return plan.withTypedRefusal(refusal)
		}
		return plan.withRefusal(err.Error())
	}
	if refusal := LayerAdapterRefusal(adapter); refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	if refusal := layerConflicts(snapshot, spec, current); refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	desired := desiredState(spec, current)
	plan.DesiredLink = &desired
	plan.Changes = linkDifferences(current, desired)
	plan.Action = PlanUpdate
	if len(plan.Changes) == 0 {
		plan.Action = PlanNoChange
	}
	plan.PlanHash = planFingerprint(plan)
	return plan
}

// layerConflicts names the first relation on the host that forbids the
// change. The order of the checks is the order of the questions: is this
// name already something else, is the lower interface there at all, is the
// layer worth building, and would it take the interface we are speaking
// over.
func layerConflicts(snapshot Snapshot, spec LinkSpec, current LinkState) *LinkRefusal {
	if current.Present && current.Kind != spec.Kind {
		found := current.Kind
		if found == "" {
			found = "a plain interface"
		}
		return &LinkRefusal{Code: CodeLinkKindMismatch,
			Reason: "the host already has " + spec.Name + " as " + found +
				"; the panel does not turn it into a " + spec.Kind + " under the same name"}
	}
	if spec.Kind == LinkVLAN {
		parent := snapshot.InterfaceByName(spec.Parent)
		if parent == nil {
			return &LinkRefusal{Code: CodeVLANParentMissing,
				Reason: "the VLAN " + spec.Name + " would run on " + spec.Parent +
					", and the host does not report that interface"}
		}
		if parent.Master != "" && parent.Master != spec.Name {
			return &LinkRefusal{Code: CodeLinkMemberTaken,
				Reason: "the parent " + spec.Parent + " is a member of " + parent.Master +
					"; a VLAN belongs on the layer above, not on an interface somebody else owns"}
		}
		return nil
	}
	for _, member := range spec.Members {
		link := snapshot.InterfaceByName(member)
		if link == nil {
			return &LinkRefusal{Code: CodeLinkMemberMissing,
				Reason: "the host does not report the interface " + member +
					", and the panel does not build a layer on an interface that is not there"}
		}
		// Enslaving a link moves its address to the layer above. On the
		// interface the panel talks over that happens before the layer is
		// finished, and the host is gone with the rescue plan still armed.
		if link.Management || member == snapshot.ManagementInterface {
			return &LinkRefusal{Code: CodeLinkSwallowsManagement,
				Reason: "the interface " + member + " is the one the panel talks to this host over; a " +
					spec.Kind + " would take its address and the host would be unreachable before the change finished"}
		}
		if link.Master != "" && link.Master != spec.Name {
			return &LinkRefusal{Code: CodeLinkMemberTaken,
				Reason: "the interface " + member + " is already a member of " + link.Master +
					"; taking it would remove it from there and stop whatever runs over that layer"}
		}
		if kind := link.LayerKind(); kind == LinkVLAN && spec.Kind == LinkBond {
			return &LinkRefusal{Code: CodeLinkMemberTaken,
				Reason: "the interface " + member + " is a VLAN on " + link.VLAN.Parent +
					"; a bond is built from links, not from the tagged traffic running over one"}
		}
	}
	return nil
}

// ComputeLinkRemoval computes the removal of a layered interface.
//
// A removal is refused for the reverse of the reasons a creation is: the
// interface is not one the panel built, it carries the management channel,
// or something stands on it. An interface that is already gone is not a
// refusal - it is a change with nothing left to do.
func ComputeLinkRemoval(snapshot Snapshot, adapter, name string) Plan {
	current := LinkStateOf(snapshot, name)
	plan := Plan{
		Interface: name, Connection: name,
		Operation: PlanLinkRemove, CurrentLink: &current,
	}
	if err := ValidateInterfaceName(name); err != nil {
		return plan.withRefusal(err.Error())
	}
	if refusal := LayerAdapterRefusal(adapter); refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	gone := LinkState{Name: name}
	plan.DesiredLink = &gone
	if !current.Present {
		plan.Action = PlanNoChange
		plan.PlanHash = planFingerprint(plan)
		return plan
	}
	if refusal := removalConflicts(snapshot, current); refusal != nil {
		// A refused plan carries no desired state: what the panel shows
		// beside the refusal must be what the host has, and a target state
		// under a refusal reads as though something were about to happen.
		plan.DesiredLink = nil
		return plan.withTypedRefusal(refusal)
	}
	plan.Changes = []string{"the " + current.Kind + " " + name + " is removed" + freedMembers(current)}
	plan.Action = PlanUpdate
	plan.PlanHash = planFingerprint(plan)
	return plan
}

func removalConflicts(snapshot Snapshot, current LinkState) *LinkRefusal {
	if current.Kind == "" {
		return &LinkRefusal{Code: CodeLinkNotLayered,
			Reason: "the interface " + current.Name +
				" is a plain link, not a bond, a bridge or a VLAN; the panel removes only the layers it can build"}
	}
	if current.Management {
		return &LinkRefusal{Code: CodeLinkCarriesManagement,
			Reason: "the interface " + current.Name +
				" is the one the panel talks to this host over; removing it takes the address with it"}
	}
	if vlans := snapshot.VLANsOn(current.Name); len(vlans) > 0 {
		return &LinkRefusal{Code: CodeLinkInUse,
			Reason: "the interface " + current.Name + " carries the VLAN(s) " + strings.Join(vlans, ", ") +
				"; remove them first or they go with it"}
	}
	if link := snapshot.InterfaceByName(current.Name); link != nil && link.Master != "" {
		return &LinkRefusal{Code: CodeLinkInUse,
			Reason: "the interface " + current.Name + " is a member of " + link.Master +
				"; take it out of that layer first"}
	}
	return nil
}

func freedMembers(current LinkState) string {
	if len(current.Members) == 0 {
		return ""
	}
	return " and " + list(current.Members) + " go back to carrying their own traffic"
}

// linkDifferences lists in human terms what the layered change does.
func linkDifferences(current, desired LinkState) []string {
	if !current.Present {
		return []string{"the " + desired.Kind + " " + desired.Name + " is created" + builtFrom(desired)}
	}
	var changes []string
	if !sameSet(current.Members, desired.Members) {
		changes = append(changes, "members from "+list(current.Members)+" to "+list(desired.Members))
	}
	if desired.Kind == LinkBond {
		if current.Mode != desired.Mode {
			changes = append(changes, "mode from "+orNone(current.Mode)+" to "+orNone(desired.Mode))
		}
		if current.MIIMonMS != desired.MIIMonMS {
			changes = append(changes, "link monitoring from "+milliseconds(current.MIIMonMS)+
				" to "+milliseconds(desired.MIIMonMS))
		}
		if current.Primary != desired.Primary {
			changes = append(changes, "primary member from "+orNone(current.Primary)+" to "+orNone(desired.Primary))
		}
		if current.LACPRate != desired.LACPRate {
			changes = append(changes, "LACP rate from "+orNone(current.LACPRate)+" to "+orNone(desired.LACPRate))
		}
	}
	if desired.Kind == LinkBridge {
		if current.STP != desired.STP {
			changes = append(changes, "spanning tree "+onOff(desired.STP))
		}
		if current.VLANFiltering != desired.VLANFiltering {
			changes = append(changes, "VLAN filtering "+onOff(desired.VLANFiltering))
		}
	}
	if desired.Kind == LinkVLAN {
		if current.Parent != desired.Parent {
			changes = append(changes, "parent from "+orNone(current.Parent)+" to "+orNone(desired.Parent))
		}
		if current.VLANID != desired.VLANID {
			changes = append(changes, "VLAN identifier from "+strconv.Itoa(current.VLANID)+
				" to "+strconv.Itoa(desired.VLANID))
		}
		if desired.Protocol != "" && current.Protocol != desired.Protocol {
			changes = append(changes, "VLAN protocol from "+orNone(current.Protocol)+" to "+orNone(desired.Protocol))
		}
	}
	if desired.MTU != "" && current.MTU != desired.MTU {
		changes = append(changes, "MTU from "+orNone(current.MTU)+" to "+orNone(desired.MTU))
	}
	return changes
}

func builtFrom(desired LinkState) string {
	switch desired.Kind {
	case LinkVLAN:
		return " with the tag " + strconv.Itoa(desired.VLANID) + " on " + desired.Parent
	case LinkBond:
		return " in the mode " + orNone(desired.Mode) + " from " + list(desired.Members)
	}
	if len(desired.Members) == 0 {
		// A bridge with no member is a legitimate thing to build: virtual
		// machines are attached to it afterwards. The plan says so, so that
		// nobody reads an empty list as a mistake.
		return " with no members yet"
	}
	return " from " + list(desired.Members)
}

func milliseconds(value int) string {
	if value == 0 {
		return "off"
	}
	return strconv.Itoa(value) + " ms"
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

// contains says whether the list holds the value. The lists it is asked
// about are the kernel's own vocabularies - a handful of entries each - so
// a walk is the whole of it.
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
