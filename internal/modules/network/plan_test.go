package network

import (
	"strings"
	"testing"
)

func testProfile() Profile {
	return Profile{
		Connection: "Wired connection 1", Interface: "eth1", Method: "auto",
		Routes: []string{"10.9.0.0/24 192.168.56.1"}, MTU: "1500",
	}
}

func TestMTUPlanDistinguishesChangeFromNoChange(t *testing.T) {
	current := testProfile()
	change := ComputeMTU("eth1", current, "9000")
	if change.Action != PlanUpdate || len(change.Changes) != 1 ||
		!strings.Contains(change.Changes[0], "MTU from 1500 to 9000") {
		t.Errorf("MTU plan: %+v", change)
	}
	none := ComputeMTU("eth1", current, "1500")
	if none.Action != PlanNoChange || len(none.Changes) != 0 {
		t.Errorf("no-change plan: %+v", none)
	}
	if change.PlanHash == none.PlanHash || change.PlanHash == "" {
		t.Error("plan fingerprints do not differ")
	}
	if bad := ComputeMTU("eth1", current, "12"); bad.Refusal == "" {
		t.Error("MTU 12 passed without a refusal")
	}
}

func TestRoutesPlanComparesAsSet(t *testing.T) {
	current := testProfile()
	current.Routes = []string{"10.9.0.0/24 192.168.56.1", "10.8.0.0/24 192.168.56.1"}
	plan := ComputeRoutes("eth1", current, []string{"10.8.0.0/24 192.168.56.1", "10.9.0.0/24 192.168.56.1"})
	if plan.Action != PlanNoChange {
		t.Errorf("route order counted as a change: %+v", plan)
	}
	empty := ComputeRoutes("eth1", current, []string{})
	if empty.Action != PlanUpdate || !strings.Contains(empty.Changes[0], "to none") {
		t.Errorf("route removal: %+v", empty)
	}
}

func TestProfilePlanLeavesRoutesAndMTU(t *testing.T) {
	current := testProfile()
	plan := ComputeProfile("eth1", current, "manual", []string{"192.168.56.61/24"}, "", nil)
	if plan.Action != PlanUpdate {
		t.Fatalf("profile plan: %+v", plan)
	}
	if plan.Desired.MTU != "1500" || len(plan.Desired.Routes) != 1 {
		t.Errorf("the address profile touched the routes or the MTU: %+v", plan.Desired)
	}
	for _, change := range plan.Changes {
		if strings.HasPrefix(change, "routes") || strings.HasPrefix(change, "MTU") {
			t.Errorf("change outside the order: %s", change)
		}
	}
	if refused := ComputeProfile("eth1", current, "manual", nil, "", nil); refused.Refusal == "" {
		t.Error("manual without an address passed without a refusal")
	}
}

func TestRefusedPlanHasFingerprint(t *testing.T) {
	plan := RefusedPlan("eth9", PlanMTU, "the interface eth9 has no NetworkManager profile")
	if plan.Refusal == "" || plan.PlanHash == "" || plan.Current != nil {
		t.Errorf("refusal: %+v", plan)
	}
	change := ComputeMTU("eth1", testProfile(), "9000")
	before := change.PlanHash
	change.Refuse("management channel")
	if change.PlanHash == before {
		t.Error("the refusal did not change the fingerprint")
	}
}

func TestResolverPlanChangesOnlyResolver(t *testing.T) {
	current := testProfile()
	current.DNS = []string{"192.168.56.50"}
	plan := ComputeDNS("eth1", current, []string{"192.168.56.50"}, []string{"flotestro.test"}, true)
	if plan.Action != PlanUpdate || plan.Operation != PlanDNS {
		t.Fatalf("resolver plan: %+v", plan)
	}
	if len(plan.Changes) != 2 {
		t.Errorf("resolver changes: %v", plan.Changes)
	}
	if plan.Desired.MTU != current.MTU || len(plan.Desired.Routes) != len(current.Routes) ||
		plan.Desired.Method != current.Method {
		t.Errorf("the resolver plan touched the rest of the profile: %+v", plan.Desired)
	}
	none := ComputeDNS("eth1", current, []string{"192.168.56.50"}, nil, false)
	if none.Action != PlanNoChange {
		t.Errorf("a resolver in the target state counted as a change: %+v", none)
	}
	if empty := ComputeDNS("eth1", current, nil, nil, false); empty.Refusal == "" {
		t.Error("a resolver without a server passed without a refusal")
	}
}
