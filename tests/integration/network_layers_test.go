//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

/*
The layered part of the network module: bonds, bridges and VLANs.

Everything in this file is deliberately one of two kinds of test.

The first kind is plan-only. A bond or a bridge takes the addressing of
every member the moment it is built, so applying one in the lab would be a
coin toss with the host's reachability - and a lab host that goes away takes
the rest of the suite with it. The plan is where the interesting answers
live anyway: the refusals are computed against the host and returned without
anything being written, which is exactly what these tests are about.

The second kind applies one change and undoes it: a VLAN on an interface
that carries nothing. A VLAN adds an interface and takes nothing away from
its parent - the parent keeps its address, its routes and its traffic - so
the host stays reachable whatever the VLAN does. The test picks a parent
only if the host reports it as free: not the management interface, with no
address of its own, owned by no layer and carrying no VLAN already. If there
is no such interface it skips rather than improvising, and it removes the
VLAN in t.Cleanup whether it passed or not.
*/

type layeredBondView struct {
	Mode         string            `json:"mode"`
	Members      []string          `json:"members"`
	MIIMonMS     int               `json:"miimon_ms"`
	Primary      string            `json:"primary"`
	ActiveMember string            `json:"active_member"`
	MemberStates map[string]string `json:"member_states"`
}

type layeredBridgeView struct {
	Members       []string `json:"members"`
	STP           bool     `json:"stp"`
	VLANFiltering bool     `json:"vlan_filtering"`
}

type layeredVLANView struct {
	Parent   string `json:"parent"`
	ID       int    `json:"id"`
	Protocol string `json:"protocol"`
}

type layeredIPv6View struct {
	Disabled *bool `json:"disabled"`
	AcceptRA *int  `json:"accept_ra"`
	Privacy  *int  `json:"privacy"`
}

type layeredInterfaceView struct {
	Name       string             `json:"name"`
	Kind       string             `json:"kind"`
	OperState  string             `json:"oper_state"`
	Master     string             `json:"master"`
	Addresses  []addressView      `json:"addresses"`
	Bond       *layeredBondView   `json:"bond"`
	Bridge     *layeredBridgeView `json:"bridge"`
	VLAN       *layeredVLANView   `json:"vlan"`
	IPv6       *layeredIPv6View   `json:"ipv6"`
	Management bool               `json:"management"`
}

type layeredNetworkView struct {
	Interfaces                []layeredInterfaceView `json:"interfaces"`
	ManagementInterface       string                 `json:"management_interface"`
	WriteAdapter              string                 `json:"write_adapter"`
	IPv6Disabled              *bool                  `json:"ipv6_disabled"`
	LayeringUnavailableReason string                 `json:"layering_unavailable_reason"`
	UnavailableReason         string                 `json:"unavailable_reason"`
}

func hostLayeredNetwork(t *testing.T, h *harness, hostID string) layeredNetworkView {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/network",
		nil, &fragment, http.StatusOK)
	var state layeredNetworkView
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("network snapshot: %v", err)
	}
	return state
}

// hostThatBuildsLayers finds a host whose write mechanism can build a
// bond, a bridge or a VLAN. NetworkManager on its own cannot: this module
// drives it by changing the profile an interface already has, and a
// half-built bond there has no way back through the rescue plan.
func hostThatBuildsLayers(t *testing.T, h *harness) (hostView, layeredNetworkView) {
	t.Helper()
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		state := hostLayeredNetwork(t, h, host.ID)
		switch state.WriteAdapter {
		case "nmstate", "netplan":
			if state.ManagementInterface == "" {
				continue
			}
			return host, state
		}
	}
	t.Skip("no connected host of the laboratory configures its network through nmstate or netplan")
	return hostView{}, layeredNetworkView{}
}

// TestALayerOnAHostThatCannotBuildOneIsRefusedByMechanism is the other
// side of the same question: a host driven by NetworkManager alone says so
// by name instead of leaving the operator with a half-built bond.
func TestALayerOnAHostThatCannotBuildOneIsRefusedByMechanism(t *testing.T) {
	h := newHarness(t)
	var chosen *hostView
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		if hostLayeredNetwork(t, h, host.ID).WriteAdapter == "networkmanager" {
			candidate := host
			chosen = &candidate
			break
		}
	}
	if chosen == nil {
		t.Skip("no connected host of the laboratory is driven by NetworkManager alone")
	}
	plan := networkPlanOf(t, h, chosen.ID, map[string]any{
		"interface": "flotestbond",
		"link": map[string]any{
			"name": "flotestbond", "kind": "bond", "mode": "active-backup",
			"miimon_ms": 100, "members": []string{"lo", "dummy0"},
		},
	})
	code, reason := planRefusal(plan)
	if code != "link_mechanism_unsupported" {
		t.Errorf("refusal code = %q (%s), wanted link_mechanism_unsupported", code, reason)
	}
	if !strings.Contains(reason, "nmstate") && !strings.Contains(reason, "netplan") {
		t.Errorf("the refusal does not say what such a host would need: %s", reason)
	}
}

// networkPlanOf orders a plan and returns the plan the host computed. The
// plan is a read: it walks the host, works out the difference and writes
// nothing, so it is safe to ask about a change that must never be applied.
func networkPlanOf(t *testing.T, h *harness, hostID string, change map[string]any) map[string]any {
	t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action": "network.plan", "reason": "integration test of the layered network",
		"payload": map[string]any{"network": change},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the plan did not finish: state = %s, %s", job.State, lastMessage(attempts))
	}
	var response struct {
		Items []struct {
			Detail struct {
				Kind string          `json:"kind"`
				Plan json.RawMessage `json:"plan"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+job.ID+"/attempts", &response)
	for i := len(response.Items) - 1; i >= 0; i-- {
		if response.Items[i].Detail.Kind != "network_plan" {
			continue
		}
		var plan map[string]any
		if err := json.Unmarshal(response.Items[i].Detail.Plan, &plan); err != nil {
			t.Fatalf("the plan body: %v", err)
		}
		return plan
	}
	t.Fatalf("the job %s carries no network plan", job.ID)
	return nil
}

func planRefusal(plan map[string]any) (string, string) {
	code, _ := plan["refusal_code"].(string)
	reason, _ := plan["refusal"].(string)
	return code, reason
}

// TestLayeringIsReportedFromTheHost checks that the inventory says what the
// host is made of and not only what it carries. A snapshot that reported no
// layering and no reason would read as a host with none - and every refusal
// about a relation would then be silence.
func TestLayeringIsReportedFromTheHost(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostLayeredNetwork(t, h, host.ID)
			if state.UnavailableReason != "" {
				t.Fatalf("the network state was not read: %s", state.UnavailableReason)
			}
			// Either the layering was read, or the host says why. Silence
			// is the one answer that is not allowed here.
			if state.LayeringUnavailableReason != "" {
				t.Skipf("the host cannot read its layering: %s", state.LayeringUnavailableReason)
			}
			for _, iface := range state.Interfaces {
				// A member names the layer that owns it, and that layer has
				// to be an interface the host also reports: a dangling
				// owner would make every membership refusal unresolvable.
				if iface.Master == "" {
					continue
				}
				var owner *layeredInterfaceView
				for i := range state.Interfaces {
					if state.Interfaces[i].Name == iface.Master {
						owner = &state.Interfaces[i]
					}
				}
				if owner == nil {
					t.Errorf("%s names the owner %s, which the host does not report", iface.Name, iface.Master)
					continue
				}
				if owner.Bond == nil && owner.Bridge == nil {
					t.Errorf("%s is owned by %s, which is neither a bond nor a bridge", iface.Name, iface.Master)
				}
			}
			// The second family is read as a fact, not guessed: either the
			// host says it is off, or it reports the sysctls per interface.
			if state.IPv6Disabled == nil {
				t.Errorf("the host says nothing about whether it has IPv6 at all")
			}
		})
	}
}

// TestLayeredRefusalsComeBackNamedFromTheHost walks the refusals that only
// the host can give, because every one of them is about a relation on that
// host. None of these plans writes anything: they are the panel asking what
// would happen, and the answer is the point.
func TestLayeredRefusalsComeBackNamedFromTheHost(t *testing.T) {
	h := newHarness(t)
	// The host has to have a mechanism that builds layers at all: on a
	// machine driven by NetworkManager alone every one of these orders is
	// refused for the mechanism before any relation is looked at, which is
	// its own test below.
	host, state := hostThatBuildsLayers(t, h)
	management := state.ManagementInterface
	if management == "" {
		t.Skip("the host did not point at the management interface")
	}

	cases := []struct {
		why    string
		change map[string]any
		code   string
	}{
		{
			// The one refusal that matters most: a bond over the interface
			// the panel comes through would take its address before the
			// bond was finished, and the host would be gone with the rescue
			// plan still armed.
			why: "a bond over the management interface",
			change: map[string]any{
				"interface": "flotestbond",
				"link": map[string]any{
					"name": "flotestbond", "kind": "bond", "mode": "active-backup",
					"miimon_ms": 100, "members": []string{management, "lo"},
				},
			},
			code: "link_swallows_management",
		},
		{
			why: "a bridge over the management interface",
			change: map[string]any{
				"interface": "flotestbr",
				"link": map[string]any{
					"name": "flotestbr", "kind": "bridge", "members": []string{management},
				},
			},
			code: "link_swallows_management",
		},
		{
			why: "a bond built from an interface the host does not have",
			change: map[string]any{
				"interface": "flotestbond",
				"link": map[string]any{
					"name": "flotestbond", "kind": "bond", "mode": "active-backup",
					"miimon_ms": 100, "members": []string{"nosuch0", "nosuch1"},
				},
			},
			code: "link_member_missing",
		},
		{
			why: "a VLAN on a parent that is not there",
			change: map[string]any{
				"interface": "flotestvlan",
				"link": map[string]any{
					"name": "flotestvlan", "kind": "vlan", "parent": "nosuch0", "vlan_id": 4000,
				},
			},
			code: "vlan_parent_missing",
		},
		{
			// A plain network card is not a layer this panel built, and a
			// removal that looked like it worked would leave it where it
			// was after the next boot.
			why:    "removing an interface that is not a layer",
			change: map[string]any{"interface": management, "link_remove": true},
			code:   "link_not_layered",
		},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			plan := networkPlanOf(t, h, host.ID, tc.change)
			code, reason := planRefusal(plan)
			if code != tc.code {
				t.Fatalf("refusal code = %q (%s), wanted %q", code, reason, tc.code)
			}
			// A code without a reason leaves the operator guessing which of
			// several interfaces was in the way.
			if !strings.Contains(reason, tc.change["interface"].(string)) &&
				!strings.Contains(reason, management) {
				t.Errorf("the refusal names nothing concrete: %s", reason)
			}
			// Nothing was written: a refused plan carries no desired state.
			if plan["desired_link"] != nil {
				t.Errorf("a refused plan carries a desired state: %v", plan["desired_link"])
			}
		})
	}
}

// TestBondOfOneMemberIsRefusedBeforeItLeavesThePanel checks the refusal the
// panel can give on its own: a bond of one member is a slower copy of that
// member and the order never reaches a host.
func TestBondOfOneMemberIsRefusedBeforeItLeavesThePanel(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	cases := []struct {
		why  string
		link map[string]any
	}{
		{"a bond of one member", map[string]any{
			"name": "flotestbond", "kind": "bond", "mode": "active-backup", "members": []string{"lo"}}},
		{"a VLAN identifier outside the space", map[string]any{
			"name": "flotestvlan", "kind": "vlan", "parent": "lo", "vlan_id": 5000}},
		{"a bond mode the kernel does not know", map[string]any{
			"name": "flotestbond", "kind": "bond", "mode": "round-robin",
			"members": []string{"lo", "dummy0"}}},
		{"an LACP rate on a mode that has none", map[string]any{
			"name": "flotestbond", "kind": "bond", "mode": "active-backup",
			"members": []string{"lo", "dummy0"}, "lacp_rate": "fast"}},
		{"a kind the panel does not build", map[string]any{
			"name": "flotesttun", "kind": "tunnel"}},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "network.link.apply",
					"reason": "integration test of the layered network",
					"payload": map[string]any{"network": map[string]any{
						"interface": tc.link["name"], "link": tc.link}}},
				nil, http.StatusBadRequest)
		})
	}
}

// TestIPv6OrderIsRefusedOnAHostWithoutTheFamily checks that an IPv6 address
// ordered onto a host that has the second family switched off comes back as
// a named refusal rather than as a change that seemed to work. The plan
// writes nothing, so the check is safe on any host.
func TestIPv6OrderIsRefusedOnAHostWithoutTheFamily(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostLayeredNetwork(t, h, host.ID)
	if state.WriteAdapter == "" {
		t.Skip("the host has no mechanism to write the network configuration")
	}
	if state.ManagementInterface == "" {
		t.Skip("the host did not point at the management interface")
	}
	off := state.IPv6Disabled != nil && *state.IPv6Disabled
	for _, iface := range state.Interfaces {
		if iface.Name == state.ManagementInterface && iface.IPv6 != nil &&
			iface.IPv6.Disabled != nil && *iface.IPv6.Disabled {
			off = true
		}
	}

	plan := networkPlanOf(t, h, host.ID, map[string]any{
		"interface": state.ManagementInterface,
		"method6":   "manual", "addresses6": []string{"2001:db8:dead::5/64"},
	})
	code, reason := planRefusal(plan)
	if off {
		if code != "ipv6_disabled_on_host" {
			t.Fatalf("a host with IPv6 off answered %q (%s)", code, reason)
		}
		return
	}
	// A host that has the family plans the change instead, and the plan
	// says what it would do with the second family. The change itself is
	// not applied here: this test is not the place to rewrite the
	// addressing of the interface the suite talks over.
	if code != "" {
		t.Fatalf("a host with IPv6 refused the plan: %q (%s)", code, reason)
	}
	changes, _ := plan["changes"].([]any)
	var sixth bool
	for _, change := range changes {
		if text, ok := change.(string); ok && strings.HasPrefix(text, "IPv6") {
			sixth = true
		}
	}
	if !sixth {
		t.Errorf("the plan says nothing about the second family: %v", changes)
	}
}

// TestVLANOnAFreeInterfaceIsBuiltAndRemoved is the one layered change this
// suite applies.
//
// It is safe because a VLAN adds an interface and takes nothing away: the
// parent keeps its address, its routes and its traffic, so the host stays
// reachable whatever the VLAN does. The parent is chosen only if the host
// reports it as free - not the management interface, with no address, owned
// by no layer, carrying no VLAN already - and the VLAN is removed in
// t.Cleanup whether the test passes or fails.
func TestVLANOnAFreeInterfaceIsBuiltAndRemoved(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	state := hostLayeredNetwork(t, h, host.ID)
	if state.WriteAdapter == "" {
		t.Skip("the host has no mechanism to write the network configuration")
	}

	carrying := map[string]bool{}
	for _, iface := range state.Interfaces {
		if iface.VLAN != nil {
			carrying[iface.VLAN.Parent] = true
		}
	}
	parent := ""
	for _, iface := range state.Interfaces {
		switch {
		case iface.Management || iface.Name == state.ManagementInterface:
		case iface.Kind != "ethernet":
		case iface.Master != "" || carrying[iface.Name]:
		case len(iface.Addresses) > 0:
		default:
			parent = iface.Name
		}
		if parent != "" {
			break
		}
	}
	if parent == "" {
		t.Skip("the host has no free interface to hang a VLAN on")
	}

	const name = "flotest4094"
	const reason = "integration test of the layered network"
	remove := func() {
		h.runOperation(host.ID, map[string]any{
			"action": "network.link.remove", "reason": reason,
			"payload": map[string]any{"network": map[string]any{
				"interface": name, "rollback_seconds": 60}},
		}, 3*time.Minute)
	}
	t.Cleanup(remove)

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "network.link.apply", "reason": reason,
		"payload": map[string]any{"network": map[string]any{
			"interface": name, "rollback_seconds": 60,
			"link": map[string]any{
				"name": name, "kind": "vlan", "parent": parent, "vlan_id": 4094,
			},
		}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("building the VLAN: state = %s, %s", job.State, lastMessage(attempts))
	}
	// A layered change goes under the same rescue plan as an address
	// change: armed before anything is written and disarmed only after the
	// host proved it still talks to the panel. A quiet success would be
	// indistinguishable from a change that had no rescue plan at all.
	if !strings.Contains(lastMessage(attempts), "the rollback was disarmed") {
		t.Errorf("a layered change without a connectivity confirmation: %s", lastMessage(attempts))
	}

	// The verifier is what decides the job succeeded, so the host really
	// has the VLAN by now; the inventory is waited for as well, because the
	// panel is what an operator looks at, and it learns on the host's own
	// cycle rather than at the moment the job ends.
	deadline := time.Now().Add(3 * time.Minute)
	for {
		after := hostLayeredNetwork(t, h, host.ID)
		for _, iface := range after.Interfaces {
			if iface.Name != name {
				continue
			}
			if iface.VLAN == nil || iface.VLAN.Parent != parent || iface.VLAN.ID != 4094 {
				t.Fatalf("the VLAN came back as %+v", iface)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the panel never reported the VLAN %s on %s", name, parent)
		}
		time.Sleep(5 * time.Second)
	}
}
