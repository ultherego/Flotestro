//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type addressView struct {
	Family    string `json:"family"`
	Address   string `json:"address"`
	Permanent bool   `json:"permanent"`
}

type interfaceView struct {
	Name       string        `json:"name"`
	Kind       string        `json:"kind"`
	MTU        int           `json:"mtu"`
	OperState  string        `json:"oper_state"`
	Carrier    *bool         `json:"carrier"`
	SpeedMbps  *int          `json:"speed_mbps"`
	Addresses  []addressView `json:"addresses"`
	Management bool          `json:"management"`
}

type networkSnapshot struct {
	Interfaces []interfaceView `json:"interfaces"`
	Routes     []struct {
		Destination string `json:"destination"`
		Family      string `json:"family"`
	} `json:"routes"`
	ManagementInterface string `json:"management_interface"`
	ManagementAddress   string `json:"management_address"`
	WriteAdapter        string `json:"write_adapter"`
	UnavailableReason   string `json:"unavailable_reason"`
}

// TestNetworkPointsAtTheManagementChannel checks the thing that decides the
// safety of every network change: the host is to say itself which interface it
// talks to the panel through.
func TestNetworkPointsAtTheManagementChannel(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostNetworkSnapshot(t, h, host.ID)
			if state.UnavailableReason != "" {
				t.Fatalf("the network state was not read: %s", state.UnavailableReason)
			}
			if state.ManagementInterface == "" || state.ManagementAddress == "" {
				t.Fatalf("the host did not point at the management channel: %+v", state)
			}
			var marked int
			for _, iface := range state.Interfaces {
				if iface.Management {
					marked++
					if iface.Name != state.ManagementInterface {
						t.Errorf("marked interface %q, channel %q", iface.Name, state.ManagementInterface)
					}
				}
			}
			if marked != 1 {
				t.Errorf("interfaces marked as management = %d", marked)
			}
		})
	}
}

// TestNetworkTellsInterfaceKindsApart guards that a container bridge does not
// pose as a network card.
func TestNetworkTellsInterfaceKindsApart(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostNetworkSnapshot(t, h, host.ID)

	kinds := map[string]string{}
	for _, iface := range state.Interfaces {
		kinds[iface.Name] = iface.Kind
		// An address without a mask does not say which network the host
		// considers local.
		for _, address := range iface.Addresses {
			if !hasPrefixMask(address.Address) {
				t.Errorf("address %q without a mask on %s", address.Address, iface.Name)
			}
		}
	}
	if kinds["lo"] != "loopback" {
		t.Errorf("kind of lo = %q", kinds["lo"])
	}
	if kind, ok := kinds["docker0"]; ok && kind != "bridge" {
		t.Errorf("kind of docker0 = %q", kind)
	}
	if len(state.Routes) == 0 {
		t.Error("the host reported no route at all")
	}
}

// TestMissingNetworkWriteHasAReason checks the boundary between an unavailable
// module and a read-only one.
func TestMissingNetworkWriteHasAReason(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var capability *hostCapability
	for i := range host.Capabilities {
		if host.Capabilities[i].Name == "network" {
			capability = &host.Capabilities[i]
		}
	}
	if capability == nil {
		t.Fatal("the host did not report the network module")
	}
	if !capability.Available {
		t.Fatalf("the network module is unavailable: %s", capability.Reason)
	}
	state := hostNetworkSnapshot(t, h, host.ID)
	if state.WriteAdapter == "" && capability.Reason == "" {
		t.Error("a host without a write adapter does not explain why the panel will change nothing")
	}
	if state.WriteAdapter != "" && capability.Reason != "" {
		t.Errorf("a host with the adapter %q gives an unavailability reason: %s",
			state.WriteAdapter, capability.Reason)
	}
}

func hostNetworkSnapshot(t *testing.T, h *harness, hostID string) networkSnapshot {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/network",
		nil, &fragment, http.StatusOK)
	var state networkSnapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("network snapshot: %v", err)
	}
	return state
}

func hasPrefixMask(address string) bool {
	for i := len(address) - 1; i >= 0; i-- {
		if address[i] == '/' {
			return i < len(address)-1
		}
	}
	return false
}

// TestBadNetworkConfigurationDoesNotReachTheHost checks that a value the host
// would not accept, or that would cut it off from the panel, is rejected when
// ordered.
func TestBadNetworkConfigurationDoesNotReachTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	const reason = "integration test of the network module"

	cases := []struct {
		action string
		change map[string]any
		why    string
	}{
		{"network.mtu.set", map[string]any{"interface": "enp0s8", "mtu": "900"},
			"MTU below the IPv6 threshold"},
		{"network.mtu.set", map[string]any{"interface": "enp0s8", "mtu": "lots"},
			"MTU that is not a number"},
		{"network.mtu.set", map[string]any{"interface": "../etc", "mtu": "1500"},
			"interface name with a path"},
		{"network.route.ensure", map[string]any{"interface": "enp0s8",
			"routes": []string{"192.168.9.0 192.168.56.1"}}, "route destination without a mask"},
		{"network.profile.apply", map[string]any{"interface": "enp0s8", "method": "manual"},
			"manual method without an address"},
		{"network.profile.apply", map[string]any{"interface": "enp0s8", "method": "manual",
			"addresses": []string{"192.168.56.40"}}, "address without a mask"},
		{"network.profile.apply", map[string]any{"interface": "enp0s8", "method": "custom"},
			"unknown method"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": tc.action, "reason": reason,
					"payload": map[string]any{"network": tc.change}},
				nil, http.StatusBadRequest)
		})
	}
}

// TestHostWithoutAWriteMechanismRefusesWhenOrdered checks the boundary the
// capability registry is to guard: a host that will not keep the change across
// a reboot is not to get it at all.
func TestHostWithoutAWriteMechanismRefusesWhenOrdered(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostNetworkSnapshot(t, h, host.ID)
	if state.WriteAdapter != "" {
		t.Skipf("the host has the write adapter %s", state.WriteAdapter)
	}

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "network.mtu.set", "reason": "integration test of the network module",
			"payload": map[string]any{"network": map[string]any{
				"interface": "eth1", "mtu": "1400"}}},
		nil, http.StatusConflict)

	// Reading the network state works on the same host: a read-only module
	// is not an unavailable module.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "network.plan",
			"payload": map[string]any{"network": map[string]any{"interface": "eth1"}}},
		nil, http.StatusCreated)
}

// TestNetworkChangeIsConfirmedByConnectivity walks the full path of a change:
// the host arms the rollback, changes the MTU, checks the path to the panel
// and only then disarms the timer.
func TestNetworkChangeIsConfirmedByConnectivity(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	state := hostNetworkSnapshot(t, h, host.ID)
	if state.WriteAdapter == "" {
		t.Skip("the host has no mechanism to write the network configuration")
	}
	iface := state.ManagementInterface
	if iface == "" {
		t.Skip("the host did not point at the management interface")
	}

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "network.mtu.set", "reason": "integration test of the network module",
			"payload": map[string]any{"network": map[string]any{
				"interface": iface, "mtu": "auto", "rollback_seconds": 60}},
		}, 3*time.Minute)
	})

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "network.mtu.set", "reason": "integration test of the network module",
		"payload": map[string]any{"network": map[string]any{
			"interface": iface, "mtu": "1400", "rollback_seconds": 60}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("MTU change: state = %s, %s", job.State, lastMessage(attempts))
	}
	// The message is to say that the rescue timer was armed and was disarmed
	// after checking the path to the panel.
	if !strings.Contains(lastMessage(attempts), "the rollback was disarmed") {
		t.Errorf("change without a connectivity confirmation: %s", lastMessage(attempts))
	}

	after := hostNetworkSnapshot(t, h, host.ID)
	for _, entry := range after.Interfaces {
		if entry.Name == iface && entry.MTU != 1400 {
			// The inventory may be a cycle older than the change, so a
			// missing new value is not an error here - but a wrong value is.
			if entry.MTU != 1500 {
				t.Errorf("MTU of interface %s = %d", iface, entry.MTU)
			}
		}
	}
}

// networkPlanView is the plan a host computed for a network change, as the
// job result carries it.
type networkPlanView struct {
	Interface string   `json:"interface"`
	Action    string   `json:"action"`
	Changes   []string `json:"changes"`
	Refusal   string   `json:"refusal"`
	Adapter   string   `json:"adapter"`
	Document  string   `json:"document"`
	PlanHash  string   `json:"plan_hash"`
	Current   *struct {
		MTU string `json:"mtu"`
	} `json:"current"`
}

// hostWithWriteAdapter returns the first connected host whose network is
// written through the given mechanism, together with its network state.
func hostWithWriteAdapter(t *testing.T, h *harness, adapter string) (hostView, networkSnapshot) {
	t.Helper()
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		state := hostNetworkSnapshot(t, h, host.ID)
		if state.WriteAdapter == adapter {
			return host, state
		}
	}
	t.Skipf("no connected host writes its network through %s", adapter)
	return hostView{}, networkSnapshot{}
}

// networkPlan orders a plan of an MTU change and reads what the host
// computed. A plan touches nothing on the host.
func networkPlan(t *testing.T, h *harness, hostID, iface, mtu string) networkPlanView {
	t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action": "network.plan", "reason": "integration test of the netplan adapter",
		"payload": map[string]any{"network": map[string]any{"interface": iface, "mtu": mtu}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("planning on %s: state = %s, %s", iface, job.State, lastMessage(attempts))
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
		var plan networkPlanView
		if err := json.Unmarshal(response.Items[i].Detail.Plan, &plan); err != nil {
			t.Fatalf("network plan: %v", err)
		}
		return plan
	}
	t.Fatalf("the job %s carries no network plan", job.ID)
	return networkPlanView{}
}

// TestNetplanHostPlansInItsOwnFile finds the host that writes its network
// through netplan - the Ubuntu host of the lab - and checks that a plan is
// computed there against the merged state, into the panel's own file.
func TestNetplanHostPlansInItsOwnFile(t *testing.T) {
	h := newHarness(t)
	host, state := hostWithWriteAdapter(t, h, "netplan")
	if state.ManagementInterface == "" {
		t.Fatal("the host did not point at the management interface")
	}

	// A real change is planned on an interface the change cannot cut the panel
	// off through.
	planned := false
	for _, iface := range state.Interfaces {
		if iface.Management || iface.Kind != "ethernet" || iface.OperState != "up" {
			continue
		}
		plan := networkPlan(t, h, host.ID, iface.Name, "1400")
		if plan.Refusal != "" {
			t.Logf("interface %s: %s", iface.Name, plan.Refusal)
			continue
		}
		if plan.Adapter != "netplan" {
			t.Errorf("the plan names the adapter %q", plan.Adapter)
		}
		if plan.Action != "update" || len(plan.Changes) != 1 || !strings.Contains(plan.Changes[0], "MTU") {
			t.Errorf("plan on %s: %q %v", iface.Name, plan.Action, plan.Changes)
		}
		// The document is the panel's file after the merge: the touched interface
		// with the MTU, and nothing of the distribution's definition copied in.
		if !strings.Contains(plan.Document, iface.Name) || !strings.Contains(plan.Document, "mtu: 1400") {
			t.Errorf("the plan document does not carry the change: %q", plan.Document)
		}
		if strings.Contains(plan.Document, state.ManagementInterface) {
			t.Errorf("the plan document touches the management interface: %q", plan.Document)
		}
		assertNoChangePlan(t, h, host.ID, iface.Name, plan)
		planned = true
		break
	}
	if planned {
		return
	}

	// Without another interface the management one is planned with the value the
	// kernel reports, then with the value the plan itself calls current: the
	// second is a no-op plan and has to say so.
	kernelMTU := "1500"
	for _, iface := range state.Interfaces {
		if iface.Management && iface.MTU > 0 {
			kernelMTU = strconv.Itoa(iface.MTU)
		}
	}
	plan := networkPlan(t, h, host.ID, state.ManagementInterface, kernelMTU)
	if plan.Refusal != "" {
		t.Fatalf("the management interface refused a plan: %s", plan.Refusal)
	}
	if plan.Adapter != "netplan" {
		t.Fatalf("plan = %+v", plan)
	}
	assertNoChangePlan(t, h, host.ID, state.ManagementInterface, plan)
}

// assertNoChangePlan plans the interface once more with the MTU the given plan
// calls current.
func assertNoChangePlan(t *testing.T, h *harness, hostID, iface string, plan networkPlanView) {
	t.Helper()
	if plan.Current == nil || plan.Current.MTU == "" {
		t.Fatalf("the plan on %s does not say what the host has now: %+v", iface, plan)
	}
	same := networkPlan(t, h, hostID, iface, plan.Current.MTU)
	if same.Refusal != "" {
		t.Fatalf("the no-op plan on %s was refused: %s", iface, same.Refusal)
	}
	if same.Action != "no_change" || len(same.Changes) != 0 {
		t.Errorf("a plan with the current MTU %q says %q %v", plan.Current.MTU, same.Action, same.Changes)
	}
	if same.PlanHash == "" || (same.PlanHash == plan.PlanHash && plan.Action != "no_change") {
		t.Errorf("fingerprints: change %q, no change %q", plan.PlanHash, same.PlanHash)
	}
}
