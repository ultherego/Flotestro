package firewall

import (
	"strings"
	"testing"
)

// Output copied from an Ubuntu host with ufw enabled: the operator's ssh
// rule and two rules of the panel, one of them with several sources.
const ufwStatusVerbose = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
25/tcp                     DENY IN     10.10.0.0/16               # flotestro:smtp - test
8443/tcp                   ALLOW IN    192.168.56.0/24            # flotestro:panel
22/tcp (v6)                ALLOW IN    Anywhere (v6)
`

const ufwShowAdded = `Added user rules (see 'ufw status' for the current rules):
ufw allow 22/tcp
ufw deny in proto tcp from 10.10.0.0/16 to any port 25 comment 'flotestro:smtp - test'
ufw allow in proto tcp from 192.168.56.0/24 to any port 8443 comment 'flotestro:panel'
ufw allow out on enp0s8 from any to any comment 'ops'
ufw deny in from fd00::/8 to any
`

func TestUFWStatusIsRead(t *testing.T) {
	status := ParseUFWStatus(ufwStatusVerbose)
	if !status.Active || status.Logging != "on (low)" {
		t.Errorf("status = %+v", status)
	}
	// The default policy is what a packet meets when no rule matches; no
	// rule list says that.
	if status.Defaults != "deny (incoming), allow (outgoing), disabled (routed)" {
		t.Errorf("defaults = %q", status.Defaults)
	}
	if UFWActive("Status: inactive\n") {
		t.Error("an inactive ufw counted as active")
	}
	if !UFWEnabled("# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n") ||
		UFWEnabled("ENABLED=no\n") || UFWEnabled("") {
		t.Error("ufw.conf was misread")
	}
}

// The rules are read in the form they can be deleted by: "ufw delete" takes
// the specification the rule was added with, and the numbers of "ufw
// status numbered" shift with every deletion.
func TestUFWRulesCarryOwnershipMarker(t *testing.T) {
	rules := ParseUFWAdded(ufwShowAdded)
	if len(rules) != 5 {
		t.Fatalf("rules = %d", len(rules))
	}
	if rules[0].Source != SourceManual || rules[0].Text != "allow 22/tcp" || rules[0].Table != UFWTable {
		t.Errorf("operator rule = %+v", rules[0])
	}
	if rules[1].Source != SourceManaged || rules[1].Comment != "flotestro:smtp - test" ||
		UFWRuleID(rules[1].Comment) != "smtp" {
		t.Errorf("panel rule = %+v", rules[1])
	}
	if strings.Contains(rules[1].Text, "comment") {
		t.Errorf("the rule text carries the comment: %q", rules[1].Text)
	}
	if rules[2].Chain != ChainInput || rules[3].Chain != ChainOutput {
		t.Errorf("directions = %q / %q", rules[2].Chain, rules[3].Chain)
	}
	// A comment that is not the panel's marker is somebody else's rule,
	// whatever it says.
	if rules[3].Source != SourceManual || UFWRuleID(rules[3].Comment) != "" {
		t.Errorf("a foreign comment was taken for a marker: %+v", rules[3])
	}
	if rules[4].Family != "ip6" {
		t.Errorf("an IPv6 source did not mark the family: %+v", rules[4])
	}
	for i, rule := range rules {
		if rule.Handle != i+1 {
			t.Errorf("rule %d has handle %d", i, rule.Handle)
		}
	}
}

func TestUFWRuleIsAssembledFromFieldsThePanelUnderstands(t *testing.T) {
	rule := RuleSpec{
		ID: "smtp", Chain: ChainInput, Action: ActionDrop, Protocol: "tcp",
		Ports: []string{"25", "1000-2000"}, Sources: []string{"10.10.0.0/16", "10.20.0.0/16"},
		Interface: "enp0s8", Comment: "test",
	}
	steps, err := UFWArguments(rule)
	if err != nil {
		t.Fatal(err)
	}
	// One source per ufw rule: a rule with two sources is two ufw rules
	// sharing the marker.
	if len(steps) != 2 {
		t.Fatalf("steps = %d", len(steps))
	}
	command := strings.Join(steps[0], " ")
	if command != UFWPath+" --force deny in on enp0s8 proto tcp from 10.10.0.0/16 to any port 25,1000:2000 comment flotestro:smtp - test" {
		t.Errorf("command = %q", command)
	}
	// The comment travels as one argument: nothing here passes through a
	// shell.
	if steps[0][len(steps[0])-1] != "flotestro:smtp - test" {
		t.Errorf("marker argument = %q", steps[0][len(steps[0])-1])
	}
	removal, err := UFWDeleteArguments(rule)
	if err != nil {
		t.Fatal(err)
	}
	if removal[1][2] != "delete" || !strings.HasSuffix(strings.Join(removal[1], " "), "from 10.20.0.0/16 to any port 25,1000:2000 comment flotestro:smtp - test") {
		t.Errorf("removal = %v", removal[1])
	}

	lines := CommandLines(steps)
	if !strings.HasSuffix(lines[0], "comment 'flotestro:smtp - test'") {
		t.Errorf("rendered line = %q", lines[0])
	}

	open := RuleSpec{ID: "web", Chain: ChainOutput, Action: ActionAccept, Protocol: "udp", Ports: []string{"53"}}
	steps, err = UFWArguments(open)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(steps[0], " ") != UFWPath+" --force allow out proto udp from any to any port 53 comment flotestro:web" {
		t.Errorf("command = %q", strings.Join(steps[0], " "))
	}
}

// ufw has no icmp on its command line and a narrow comment alphabet: both
// fall out at the plan stage rather than on the host.
func TestUFWRefusesWhatItCannotExpress(t *testing.T) {
	icmp := RuleSpec{ID: "ping", Chain: ChainInput, Action: ActionDrop, Protocol: "icmp"}
	if _, err := UFWArguments(icmp); err == nil {
		t.Error("an icmp rule passed to ufw")
	}
	quoted := RuleSpec{ID: "x", Chain: ChainInput, Action: ActionDrop, Protocol: "tcp",
		Ports: []string{"25"}, Comment: "it's"}
	if _, err := UFWArguments(quoted); err == nil {
		t.Error("a comment with a quote passed to ufw")
	}
	// The panel's own validation still applies underneath.
	empty := RuleSpec{ID: "x", Chain: ChainInput, Action: ActionDrop}
	if _, err := UFWArguments(empty); err == nil {
		t.Error("a rule without a match passed to ufw")
	}
}

// The transition between two registries deletes what changed or vanished
// by its old specification and adds what appeared or changed. The rollback
// is the same function the other way round: ufw has no rebuild short of a
// reset that drops the operator's rules too.
func TestUFWTransitionIsComputedFromRegistries(t *testing.T) {
	smtp := RuleSpec{ID: "smtp", Chain: ChainInput, Action: ActionDrop, Protocol: "tcp",
		Ports: []string{"25"}, Sources: []string{"10.10.0.0/16"}}
	panel := RuleSpec{ID: "panel", Chain: ChainInput, Action: ActionAccept, Protocol: "tcp",
		Ports: []string{"8443"}, Sources: []string{"192.168.56.0/24"}}
	before := Registry{Rules: []RuleSpec{smtp, panel}}

	changed := smtp
	changed.Ports = []string{"25", "465"}
	web := RuleSpec{ID: "web", Chain: ChainInput, Action: ActionAccept, Protocol: "tcp", Ports: []string{"443"}}
	after := Registry{Rules: []RuleSpec{changed, web}}

	steps, err := UFWTransition(before, after)
	if err != nil {
		t.Fatal(err)
	}
	lines := CommandLines(steps)
	if len(lines) != 4 {
		t.Fatalf("transition = %v", lines)
	}
	// The old smtp and the vanished panel rule go first, then the new smtp
	// and web. The panel's "drop" is ufw's "deny" and "accept" its "allow".
	if !strings.Contains(lines[0], "delete deny in proto tcp from 10.10.0.0/16 to any port 25 comment") ||
		!strings.Contains(lines[1], "delete allow in proto tcp from 192.168.56.0/24 to any port 8443") {
		t.Errorf("deletions = %v", lines[:2])
	}
	if !strings.Contains(lines[2], "port 25,465") || !strings.Contains(lines[3], "port 443") ||
		strings.Contains(lines[2], "delete") {
		t.Errorf("additions = %v", lines[2:])
	}

	back, err := UFWTransition(after, before)
	if err != nil {
		t.Fatal(err)
	}
	backLines := CommandLines(back)
	if len(backLines) != 4 || !strings.Contains(backLines[0], "delete") ||
		!strings.Contains(backLines[3], "port 8443") {
		t.Errorf("rollback transition = %v", backLines)
	}
	// The same registry twice is no change at all.
	if none, _ := UFWTransition(after, after); len(none) != 0 {
		t.Errorf("an unchanged registry produced commands: %v", CommandLines(none))
	}
	// A rule in the same set written in another order is the same rule.
	reordered := changed
	reordered.Ports = []string{"465", "25"}
	if none, _ := UFWTransition(after, Registry{Rules: []RuleSpec{reordered, web}}); len(none) != 0 {
		t.Errorf("a reordered rule produced commands: %v", CommandLines(none))
	}
}

// A deletion of a rule ufw no longer has is the state the step wanted: it
// happens on the rollback of a change that stopped halfway. Any other
// failure, and any failure of an addition, stays a failure.
func TestUFWDeletionOfAbsentRuleIsNotAFailure(t *testing.T) {
	removal, _ := UFWDeleteArguments(smtpRule())
	if !UFWDeletionOfAbsentRule(removal[0], "Could not delete non-existent rule\nCould not delete non-existent rule (v6)") {
		t.Error("the deletion of an absent rule counted as a failure")
	}
	if UFWDeletionOfAbsentRule(removal[0], "ERROR: Bad port") {
		t.Error("another ufw error passed as an absent rule")
	}
	addition, _ := UFWArguments(smtpRule())
	if UFWDeletionOfAbsentRule(addition[0], "Could not delete non-existent rule") {
		t.Error("an addition passed as the deletion of an absent rule")
	}
}

func TestUFWPlanCarriesTheCommands(t *testing.T) {
	plan := ComputeRule(Registry{}, smtpRule(), "aaa", AdapterUFW)
	before := plan.PlanHash
	steps, err := UFWTransition(Registry{}, Registry{}.Set(smtpRule()))
	if err != nil {
		t.Fatal(err)
	}
	plan.Describe(CommandLines(steps))
	if len(plan.Commands) != 1 || !strings.HasPrefix(plan.Commands[0], UFWPath) {
		t.Errorf("plan commands = %v", plan.Commands)
	}
	if plan.PlanHash == before {
		t.Error("the commands did not change the fingerprint")
	}
}
