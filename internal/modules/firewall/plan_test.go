package firewall

import (
	"strings"
	"testing"
)

func smtpRule() RuleSpec {
	return RuleSpec{ID: "smtp", Chain: "input", Action: "drop", Protocol: "tcp",
		Ports: []string{"25"}, Sources: []string{"10.10.0.0/16"}}
}

// TestPlanDistinguishesMissingRuleFromDifferentRule guards the essence of
// the per-host plan: the same rule ordered on two hosts is two different
// changes.
func TestPlanDistinguishesMissingRuleFromDifferentRule(t *testing.T) {
	missing := ComputeRule(Registry{}, smtpRule(), "aaa", AdapterNftables)
	if missing.Action != PlanCreate || missing.Current != nil {
		t.Errorf("a host without the rule has the plan %q (current=%v)", missing.Action, missing.Current)
	}

	other := smtpRule()
	other.Ports = []string{"587"}
	change := ComputeRule(Registry{Rules: []RuleSpec{other}}, smtpRule(), "aaa", AdapterNftables)
	if change.Action != PlanUpdate {
		t.Errorf("a host with a different rule has the plan %q", change.Action)
	}
	if !contains(change.Changes, "ports") {
		t.Errorf("the plan does not name the port change: %+v", change.Changes)
	}
	if missing.PlanHash == change.PlanHash {
		t.Error("two different found states gave the same plan fingerprint")
	}
}

// TestNoChangePlanIgnoresOrder guards that the order of ports and sources
// is not the operator's decision - the same rule written differently is
// still the same.
func TestNoChangePlanIgnoresOrder(t *testing.T) {
	current := smtpRule()
	current.Ports = []string{"25", "465"}
	current.Sources = []string{"10.10.0.0/16", "10.20.0.0/16"}
	requested := smtpRule()
	requested.Ports = []string{"465", "25"}
	requested.Sources = []string{"10.20.0.0/16", "10.10.0.0/16"}

	plan := ComputeRule(Registry{Rules: []RuleSpec{current}}, requested, "aaa", AdapterNftables)
	if plan.Action != PlanNoChange {
		t.Fatalf("the same rule in a different order has the plan %q (%+v)", plan.Action, plan.Changes)
	}
}

// TestPlanFingerprintDependsOnRuleset guards that the same diff against a
// different ruleset is a different change: it enters a different
// neighbourhood of rules.
func TestPlanFingerprintDependsOnRuleset(t *testing.T) {
	first := ComputeRule(Registry{}, smtpRule(), "ruleset-a", AdapterNftables)
	second := ComputeRule(Registry{}, smtpRule(), "ruleset-b", AdapterNftables)
	if first.PlanHash == second.PlanHash {
		t.Error("a plan against a different ruleset has the same fingerprint")
	}
	if first.RulesetHash != "ruleset-a" {
		t.Errorf("the plan does not carry the ruleset fingerprint: %q", first.RulesetHash)
	}
}

// TestRemovalPlanDistinguishesPanelRule guards that removing a rule the
// host does not know is visible before approval, not after.
func TestRemovalPlanDistinguishesPanelRule(t *testing.T) {
	present := ComputeRemoval(Registry{Rules: []RuleSpec{smtpRule()}}, "smtp", "aaa", AdapterNftables)
	if present.Action != PlanRemove || present.Current == nil {
		t.Errorf("removing an existing rule has the plan %q", present.Action)
	}
	absent := ComputeRemoval(Registry{}, "smtp", "aaa", AdapterNftables)
	if absent.Action != PlanRemoveAbsent {
		t.Errorf("removing an unknown rule has the plan %q", absent.Action)
	}
}

func contains(items []string, fragment string) bool {
	for _, item := range items {
		if strings.Contains(item, fragment) {
			return true
		}
	}
	return false
}
