package firewall

import (
	"strings"
	"testing"
)

// Output copied from a host of the test fleet: docker tables managed by
// iptables-nft and the panel's own table.
const nftOutput = `# Warning: table ip nat is managed by iptables-nft, do not touch!
table ip nat { # handle 1
	chain DOCKER { # handle 1
		iifname "docker0" counter packets 0 bytes 0 return # handle 4
		iifname != "docker0" tcp dport 8081 counter packets 12 bytes 640 dnat to 172.17.0.2:80 # handle 13
	}

	chain POSTROUTING { # handle 2
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 172.17.0.0/16 oifname != "docker0" counter packets 3 bytes 180 masquerade # handle 3
	}
}
table inet flotestro { # handle 7
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		tcp dport 8443 counter packets 5 bytes 300 accept comment "flotestro: management channel" # handle 2
		ip saddr 10.0.0.0/8 drop # handle 3
	}
}`

func TestRulesCarryTextFromNft(t *testing.T) {
	snapshot := ParseRuleset(nftOutput)

	if snapshot.Adapter != AdapterNftables || snapshot.Hash == "" {
		t.Fatalf("adapter = %q, fingerprint = %q", snapshot.Adapter, snapshot.Hash)
	}
	if len(snapshot.Tables) != 2 || len(snapshot.Chains) != 3 || len(snapshot.Rules) != 5 {
		t.Fatalf("tables = %d, chains = %d, rules = %d",
			len(snapshot.Tables), len(snapshot.Chains), len(snapshot.Rules))
	}

	// The rule text is the text from nft, without the handle appended at
	// the end: the operator knows this notation from the command line.
	var dnat Rule
	for _, rule := range snapshot.Rules {
		if rule.Handle == 13 {
			dnat = rule
		}
	}
	if strings.Contains(dnat.Text, "handle") {
		t.Errorf("the rule text carries the handle: %q", dnat.Text)
	}
	if !strings.HasSuffix(dnat.Text, "dnat to 172.17.0.2:80") {
		t.Errorf("rule text = %q", dnat.Text)
	}
	if dnat.Packets == nil || *dnat.Packets != 12 || dnat.Bytes == nil || *dnat.Bytes != 640 {
		t.Errorf("counters = %v / %v", dnat.Packets, dnat.Bytes)
	}
	// A rule without a counter must not pretend zero packets passed through
	// it.
	for _, rule := range snapshot.Rules {
		if rule.Handle == 3 && rule.Table == FlotestroTable && rule.Packets != nil {
			t.Errorf("a rule without a counter got zero: %+v", rule)
		}
	}
}

// A table belonging to another program is rewritten without the panel's
// participation, so a rule in it is neither ours nor durable.
func TestOriginDistinguishesForeignTables(t *testing.T) {
	snapshot := ParseRuleset(nftOutput)

	byName := map[string]Table{}
	for _, table := range snapshot.Tables {
		byName[table.Name] = table
	}
	if byName["nat"].Source != SourceForeign || byName["nat"].Owner != "iptables-nft" {
		t.Errorf("nat table = %+v", byName["nat"])
	}
	if byName["flotestro"].Source != SourceManaged {
		t.Errorf("panel table = %+v", byName["flotestro"])
	}
	for _, rule := range snapshot.Rules {
		if rule.Table == "nat" && rule.Source != SourceForeign {
			t.Errorf("rule in a foreign table = %+v", rule)
		}
		if rule.Table == FlotestroTable && rule.Source != SourceManaged {
			t.Errorf("panel rule = %+v", rule)
		}
	}
}

func TestChainHookIsRead(t *testing.T) {
	snapshot := ParseRuleset(nftOutput)

	byName := map[string]Chain{}
	for _, chain := range snapshot.Chains {
		byName[chain.Table+"/"+chain.Name] = chain
	}
	postrouting := byName["nat/POSTROUTING"]
	if postrouting.Hook != "postrouting" || postrouting.Policy != "accept" ||
		postrouting.Type != "nat" || postrouting.Priority != "srcnat" {
		t.Errorf("base chain = %+v", postrouting)
	}
	// A regular chain is not hooked into the packet path and has no policy;
	// writing "accept" there would be false.
	if byName["nat/DOCKER"].Hook != "" || byName["nat/DOCKER"].Policy != "" {
		t.Errorf("a regular chain got a hook: %+v", byName["nat/DOCKER"])
	}
}

// The counters grow on their own, so they must not change the fingerprint:
// otherwise every read would invalidate a plan made a moment earlier.
func TestFingerprintDoesNotDependOnCounters(t *testing.T) {
	first := ParseRuleset(nftOutput).Hash
	second := ParseRuleset(strings.ReplaceAll(nftOutput,
		"counter packets 12 bytes 640", "counter packets 99 bytes 9999")).Hash
	if first != second {
		t.Errorf("the fingerprint changed after a counter change: %q vs %q", first, second)
	}
	other := ParseRuleset(strings.ReplaceAll(nftOutput, "tcp dport 8443", "tcp dport 8444")).Hash
	if first == other {
		t.Error("the fingerprint did not change after a rule change")
	}
}
