package firewall

import (
	"strings"
	"testing"
)

func TestRuleIsAssembledFromFieldsThePanelUnderstands(t *testing.T) {
	rule := RuleSpec{
		ID: "panel-8443", Chain: ChainInput, Action: ActionAccept,
		Protocol: "tcp", Ports: []string{"8443", "9000-9010"},
		Sources: []string{"192.168.56.0/24"}, Comment: "management channel",
	}
	arguments, err := RuleArguments(rule)
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Join(arguments, " ")
	// The rule goes only to the panel table: foreign chains are rewritten
	// without our participation.
	if !strings.Contains(command, "add rule inet flotestro input") {
		t.Errorf("command = %q", command)
	}
	if !strings.Contains(command, "ip saddr 192.168.56.0/24") {
		t.Errorf("no source match: %q", command)
	}
	if !strings.Contains(command, "tcp dport { 8443, 9000-9010 }") {
		t.Errorf("no ports: %q", command)
	}
	// The counter is always there: without it the rule does not answer
	// whether anything passed through it.
	if !strings.Contains(command, "counter accept") {
		t.Errorf("no counter: %q", command)
	}
	if !strings.Contains(command, CommentPrefix) {
		t.Errorf("rule without an ownership marker: %q", command)
	}
}

func TestBadRuleIsRejected(t *testing.T) {
	cases := []struct {
		rule RuleSpec
		why  string
	}{
		{RuleSpec{ID: "Bad Name", Chain: ChainInput, Action: ActionAccept, Protocol: "tcp", Ports: []string{"22"}}, "name with a space"},
		{RuleSpec{ID: "test", Chain: "PREROUTING", Action: ActionAccept, Protocol: "tcp", Ports: []string{"22"}}, "foreign chain"},
		{RuleSpec{ID: "test", Chain: ChainInput, Action: "log", Protocol: "tcp", Ports: []string{"22"}}, "unknown action"},
		{RuleSpec{ID: "test", Chain: ChainInput, Action: ActionDrop, Protocol: "tcp", Ports: []string{"0"}}, "port zero"},
		{RuleSpec{ID: "test", Chain: ChainInput, Action: ActionDrop, Protocol: "tcp", Ports: []string{"100-50"}}, "empty range"},
		{RuleSpec{ID: "test", Chain: ChainInput, Action: ActionDrop, Sources: []string{"10.0.0.1"}}, "source without a mask"},
		{RuleSpec{ID: "test", Chain: ChainInput, Action: ActionDrop, Protocol: "tcp", Ports: []string{"22"}, Comment: `a" drop; #`}, "comment with a quote"},
		// A rule without a match covers all traffic; that is a separate
		// decision, not the result of an empty form.
		{RuleSpec{ID: "test", Chain: ChainInput, Action: ActionDrop}, "rule without a match"},
	}
	for _, tc := range cases {
		if _, err := RuleArguments(tc.rule); err == nil {
			t.Errorf("accepted rule: %s", tc.why)
		}
	}
}

// The management channel is the only thing that must not be lost: without
// it the host stops answering and there is nothing to revert the change
// with.
func TestRuleCannotCutOffPanel(t *testing.T) {
	const panel = "192.168.56.10"
	const port = 8443

	blockingPort := RuleSpec{ID: "block", Chain: ChainInput, Action: ActionDrop,
		Protocol: "tcp", Ports: []string{"8000-9000"}}
	if err := ProtectsManagementChannel(blockingPort, panel, port); err == nil {
		t.Error("accepted a rule covering the management port")
	}

	blockingSource := RuleSpec{ID: "block", Chain: ChainInput, Action: ActionDrop,
		Sources: []string{"192.168.56.0/24"}}
	if err := ProtectsManagementChannel(blockingSource, panel, port); err == nil {
		t.Error("accepted a rule covering the panel address")
	}

	// An accepting rule cuts nothing off.
	accepting := RuleSpec{ID: "ok", Chain: ChainInput, Action: ActionAccept,
		Protocol: "tcp", Ports: []string{"8443"}}
	if err := ProtectsManagementChannel(accepting, panel, port); err != nil {
		t.Errorf("rejected an accepting rule: %v", err)
	}

	// Blocking another port from another network does not touch the
	// management channel.
	other := RuleSpec{ID: "ok", Chain: ChainInput, Action: ActionDrop,
		Protocol: "tcp", Ports: []string{"25"}, Sources: []string{"10.10.0.0/16"}}
	if err := ProtectsManagementChannel(other, panel, port); err != nil {
		t.Errorf("rejected a rule unrelated to the panel: %v", err)
	}
}

func TestRemovalConcernsOnlyOwnChains(t *testing.T) {
	if _, err := RemovalArguments("POSTROUTING", 5); err == nil {
		t.Error("accepted a removal from a foreign chain")
	}
	if _, err := RemovalArguments(ChainInput, 0); err == nil {
		t.Error("accepted a removal without a handle")
	}
	arguments, err := RemovalArguments(ChainInput, 7)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(arguments, " ") != NftPath+" delete rule inet flotestro input handle 7" {
		t.Errorf("command = %v", arguments)
	}
}

// Output copied from a host of the test fleet.
const zonesOutput = `FedoraServer (default, active)
  target: default
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 
  services: cockpit dhcpv6-client ssh
  ports: 
  rich rules: 

block
  target: %%REJECT%%
  interfaces: 
  services: 
  ports: 8443/tcp 9000/udp
`

func TestZonesDescribeAccessPerInterface(t *testing.T) {
	zones := ParseZones(zonesOutput, "FedoraServer")
	if len(zones) != 2 {
		t.Fatalf("zones = %d", len(zones))
	}
	defaultZone := zones[0]
	if !defaultZone.Default || !defaultZone.Active {
		t.Errorf("default zone = %+v", defaultZone)
	}
	if len(defaultZone.Interfaces) != 2 || defaultZone.Interfaces[1] != "enp0s8" {
		t.Errorf("interfaces = %v", defaultZone.Interfaces)
	}
	if len(defaultZone.Services) != 3 {
		t.Errorf("services = %v", defaultZone.Services)
	}
	// An empty field stays empty, not a list with an empty string.
	if len(defaultZone.Ports) != 0 || len(defaultZone.Sources) != 0 {
		t.Errorf("empty fields = %v / %v", defaultZone.Ports, defaultZone.Sources)
	}
	if zones[1].Target != "%%REJECT%%" || len(zones[1].Ports) != 2 {
		t.Errorf("block zone = %+v", zones[1])
	}
	if zones[1].Default || zones[1].Active {
		t.Errorf("an inactive zone marked as active: %+v", zones[1])
	}
}

// A firewalld change must go to the permanent state and be reloaded: a
// change in only one of them vanishes, but each time at a different moment.
func TestFirewalldChangeIsPermanentAndReloaded(t *testing.T) {
	steps, err := PortArguments("FedoraServer", "8443", "tcp", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 {
		t.Fatalf("steps = %d", len(steps))
	}
	if !strings.Contains(strings.Join(steps[0], " "), "--permanent") {
		t.Errorf("non-permanent change: %v", steps[0])
	}
	if steps[1][1] != "--reload" {
		t.Errorf("no reload: %v", steps[1])
	}
	for _, bad := range []struct{ zone, port, protocol string }{
		{"bad zone", "8443", "tcp"},
		{"FedoraServer", "0", "tcp"},
		{"FedoraServer", "8443", "sctp"},
	} {
		if _, err := PortArguments(bad.zone, bad.port, bad.protocol, true); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// The registry is the source of truth about the panel rules: the handle is
// assigned by the kernel and changes at every table reload.
func TestRegistryRebuildsTableFromScratch(t *testing.T) {
	registry := Registry{}
	registry = registry.Set(RuleSpec{ID: "panel", Chain: ChainInput,
		Action: ActionAccept, Protocol: "tcp", Ports: []string{"8443"}})
	registry = registry.Set(RuleSpec{ID: "mail", Chain: ChainInput,
		Action: ActionDrop, Protocol: "tcp", Ports: []string{"25"}})
	// The same name means the same rule: a repeat duplicates nothing.
	registry = registry.Set(RuleSpec{ID: "panel", Chain: ChainInput,
		Action: ActionAccept, Protocol: "tcp", Ports: []string{"8443", "8080"}})
	if len(registry.Rules) != 2 {
		t.Fatalf("rules = %d", len(registry.Rules))
	}
	if len(registry.Rules[0].Ports) != 2 {
		t.Errorf("the rule was not replaced: %+v", registry.Rules[0])
	}

	steps, err := RebuildArguments(registry)
	if err != nil {
		t.Fatal(err)
	}
	commands := make([]string, 0, len(steps))
	for _, step := range steps {
		commands = append(commands, strings.Join(step, " "))
	}
	joined := strings.Join(commands, "\n")
	// The table is built from scratch, because the rule order decides
	// which one acts first.
	if !strings.Contains(joined, "flush table inet flotestro") {
		t.Errorf("no table flush:\n%s", joined)
	}
	if strings.Index(joined, "flush table") > strings.Index(joined, "add rule") {
		t.Errorf("flush after adding rules:\n%s", joined)
	}

	registry, found := registry.Remove("panel")
	if !found || len(registry.Rules) != 1 || registry.Rules[0].ID != "mail" {
		t.Errorf("after removal = %+v", registry.Rules)
	}
	if _, found := registry.Remove("missing"); found {
		t.Error("removed a rule that does not exist")
	}
}
