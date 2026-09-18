package firewall

import (
	"encoding/hex"
	"strings"
	"testing"
)

// tuple renders a line of /etc/ufw/user.rules the way ufw writes it, with the
// comment hex-encoded as the tool does.
func tuple(fields, comment string) string {
	line := "### tuple ### " + fields
	if comment != "" {
		line += " comment=" + hex.EncodeToString([]byte(comment))
	}
	return line
}

func TestUFWFileRulesReadTheTuplesAndTheirComments(t *testing.T) {
	content := strings.Join([]string{
		"*filter",
		":ufw-user-input - [0:0]",
		"### RULES ###",
		tuple("allow_in tcp 22 0.0.0.0/0 any 0.0.0.0/0", "flotestro:ssh - kept by the panel"),
		"-A ufw-user-input -p tcp --dport 22 -j ACCEPT",
		tuple("deny_out udp 53 0.0.0.0/0 any 10.0.0.0/8", ""),
		"### END RULES ###",
		"COMMIT",
	}, "\n")

	rules := UFWFileRules("ip", content)
	if len(rules) != 2 {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[0].Chain != ChainInput || rules[0].Source != SourceManaged ||
		rules[0].Comment != "flotestro:ssh - kept by the panel" {
		t.Fatalf("the panel rule was read as %+v", rules[0])
	}
	if strings.Contains(rules[0].Text, "comment=") {
		t.Fatalf("the encoded comment stayed in the text: %q", rules[0].Text)
	}
	if UFWRuleID(rules[0].Comment) != "ssh" {
		t.Fatalf("rule id = %q", UFWRuleID(rules[0].Comment))
	}
	if rules[1].Chain != ChainOutput || rules[1].Source != SourceManual {
		t.Fatalf("the manual rule was read as %+v", rules[1])
	}
}

// A rule ufw keeps and the kernel filters with is not a drift, however
// differently the two write it down.
func TestARuleInBothViewsIsNotDrift(t *testing.T) {
	filed := UFWFileRules("ip", tuple("allow_in tcp 22 0.0.0.0/0 any 0.0.0.0/0", "flotestro:ssh"))
	loaded := []Rule{{Family: "ip", Chain: "ufw-user-input",
		Text: `meta l4proto tcp tcp dport 22 counter packets 3 bytes 180 accept comment "flotestro:ssh"`}}
	if drift := UFWDrift(filed, loaded); len(drift) != 0 {
		t.Fatalf("drift = %+v", drift)
	}
}

// A rule written into the file and never loaded looks enforced and filters
// nothing. The panel is to say so before somebody depends on it.
func TestARuleOnlyInTheFileIsReportedAsNotLoaded(t *testing.T) {
	filed := UFWFileRules("ip", strings.Join([]string{
		tuple("allow_in tcp 22 0.0.0.0/0 any 0.0.0.0/0", "flotestro:ssh"),
		tuple("allow_in tcp 8443 0.0.0.0/0 any 0.0.0.0/0", "flotestro:panel"),
	}, "\n"))
	loaded := []Rule{{Family: "ip", Chain: "ufw-user-input",
		Text: `meta l4proto tcp tcp dport 22 counter packets 0 bytes 0 accept`}}

	drift := UFWDrift(filed, loaded)
	if len(drift) != 1 {
		t.Fatalf("drift = %+v", drift)
	}
	if drift[0].Reason != DriftUFWNotLoaded || drift[0].RuleID != "panel" ||
		drift[0].Chain != ChainInput || drift[0].Detail == "" {
		t.Fatalf("drift = %+v", drift[0])
	}
}

// A rule the kernel filters with and no file keeps disappears at the next
// reload: a port silently opens or closes without anyone ordering it.
func TestARuleOnlyInTheKernelIsReportedAsNotPersisted(t *testing.T) {
	filed := UFWFileRules("ip", tuple("allow_in tcp 22 0.0.0.0/0 any 0.0.0.0/0", ""))
	loaded := []Rule{
		{Family: "ip", Chain: "ufw-user-input", Text: `tcp dport 22 counter packets 0 bytes 0 accept`},
		{Family: "ip", Chain: "ufw-user-input", Text: `tcp dport 3306 counter packets 0 bytes 0 accept`},
	}
	drift := UFWDrift(filed, loaded)
	if len(drift) != 1 || drift[0].Reason != DriftUFWNotPersisted ||
		!strings.Contains(drift[0].Rule, "3306") {
		t.Fatalf("drift = %+v", drift)
	}
}

// The two files hold two families, and a rule of one is not the counterpart
// of a rule of the other.
func TestTheFamiliesAreComparedApart(t *testing.T) {
	filed := UFWFileRules("ip6", tuple("allow_in tcp 22 ::/0 any ::/0", ""))
	loaded := []Rule{{Family: "ip", Chain: "ufw-user-input", Text: `tcp dport 22 counter packets 0 bytes 0 accept`}}
	drift := UFWDrift(filed, loaded)
	reasons := map[string]int{}
	for _, entry := range drift {
		reasons[entry.Reason]++
	}
	if reasons[DriftUFWNotLoaded] != 1 || reasons[DriftUFWNotPersisted] != 1 {
		t.Fatalf("drift = %+v", drift)
	}
}

// A rule without a protocol is one line in the file and two rules in the
// kernel; neither of them is a drift.
func TestARuleWithoutAProtocolCoversBothOfTheKernelRules(t *testing.T) {
	filed := UFWFileRules("ip", tuple("allow_in any 22 0.0.0.0/0 any 0.0.0.0/0", ""))
	loaded := []Rule{
		{Family: "ip", Chain: "ufw-user-input", Text: `tcp dport 22 counter packets 0 bytes 0 accept`},
		{Family: "ip", Chain: "ufw-user-input", Text: `udp dport 22 counter packets 0 bytes 0 accept`},
	}
	if drift := UFWDrift(filed, loaded); len(drift) != 0 {
		t.Fatalf("drift = %+v", drift)
	}
}

// A port list and a port range are written differently by ufw and by nft, and
// mean the same rule.
func TestTheTwoNotationsOfPortsMeetEachOther(t *testing.T) {
	filed := UFWFileRules("ip", strings.Join([]string{
		tuple("allow_in tcp 443,80 0.0.0.0/0 any 0.0.0.0/0", ""),
		tuple("allow_in tcp 8000:9000 0.0.0.0/0 any 10.0.0.0/8", ""),
	}, "\n"))
	loaded := []Rule{
		{Family: "ip", Chain: "ufw-user-input", Text: `tcp dport { 80, 443 } counter packets 0 bytes 0 accept`},
		{Family: "ip", Chain: "ufw-user-input", Text: `ip saddr 10.0.0.0/8 tcp dport 8000-9000 counter packets 0 bytes 0 accept`},
	}
	if drift := UFWDrift(filed, loaded); len(drift) != 0 {
		t.Fatalf("drift = %+v", drift)
	}
}

// An application profile names ports the file does not hold. The panel says it
// cannot compare the rule instead of inventing a drift - and, because it
// cannot, it does not accuse the kernel rules either.
func TestAnApplicationProfileIsReportedAsNotComparable(t *testing.T) {
	filed := UFWFileRules("ip", tuple("allow_in tcp any 0.0.0.0/0 any 0.0.0.0/0 dapp=OpenSSH", ""))
	loaded := []Rule{{Family: "ip", Chain: "ufw-user-input", Text: `tcp dport 22 counter packets 0 bytes 0 accept`}}
	drift := UFWDrift(filed, loaded)
	if len(drift) != 1 || drift[0].Reason != DriftUFWNotComparable {
		t.Fatalf("drift = %+v", drift)
	}
}

// A rate limit is a jump to a chain of its own: neither view can be read as
// the other, and the panel says exactly that.
func TestARateLimitIsNotComparedEitherWay(t *testing.T) {
	filed := UFWFileRules("ip", tuple("limit_in tcp 22 0.0.0.0/0 any 0.0.0.0/0", ""))
	loaded := []Rule{{Family: "ip", Chain: "ufw-user-input", Text: `tcp dport 22 counter packets 0 bytes 0 jump ufw-user-limit`}}
	drift := UFWDrift(filed, loaded)
	if len(drift) != 2 {
		t.Fatalf("drift = %+v", drift)
	}
	for _, entry := range drift {
		if entry.Reason != DriftUFWNotComparable {
			t.Fatalf("drift = %+v", drift)
		}
	}
}

// Only the user chains are compared. What ufw builds around them is its own
// scaffolding, rebuilt at every reload.
func TestOnlyTheUserChainsAreCompared(t *testing.T) {
	loaded := UFWLoadedRules([]Rule{
		{Chain: "ufw-before-input", Text: "ct state established,related counter accept"},
		{Chain: "ufw-user-input", Text: "tcp dport 22 counter accept"},
		{Chain: "ufw-user-logging-input", Text: `counter log prefix "[UFW BLOCK] "`},
		{Chain: "ufw-user-output", Text: "udp dport 53 counter accept"},
	})
	if len(loaded) != 2 || loaded[0].Chain != "ufw-user-input" || loaded[1].Chain != "ufw-user-output" {
		t.Fatalf("loaded = %+v", loaded)
	}
}

// A word in a comment is not a verdict: a rule commented "drop the rest"
// still accepts.
func TestTheCommentIsNotReadAsTheVerdict(t *testing.T) {
	filed := UFWFileRules("ip", tuple("allow_in tcp 22 0.0.0.0/0 any 0.0.0.0/0", "drop the rest"))
	loaded := []Rule{{Family: "ip", Chain: "ufw-user-input",
		Text: `tcp dport 22 counter packets 0 bytes 0 accept comment "drop the rest"`}}
	if drift := UFWDrift(filed, loaded); len(drift) != 0 {
		t.Fatalf("drift = %+v", drift)
	}
}

// ufw writes the direction twice over its versions: as a suffix of the
// action, and as a field of its own. Both are the same rule, and a rule read
// with the wrong direction would be reported as two drifts at once.
func TestTheDirectionIsReadInBothOfTheFormsUFWWritesIt(t *testing.T) {
	for _, form := range []string{
		"deny_out udp 53 0.0.0.0/0 any 0.0.0.0/0",
		"deny udp 53 0.0.0.0/0 any 0.0.0.0/0 out",
	} {
		filed := UFWFileRules("ip", tuple(form, ""))
		if len(filed) != 1 || filed[0].Chain != ChainOutput {
			t.Fatalf("%q was read as %+v", form, filed)
		}
		loaded := []Rule{{Family: "ip", Chain: "ufw-user-output",
			Text: `udp dport 53 counter packets 0 bytes 0 drop`}}
		if drift := UFWDrift(filed, loaded); len(drift) != 0 {
			t.Fatalf("%q: drift = %+v", form, drift)
		}
	}
}

// A rule bound to an interface is the same rule in both views, and a rule
// bound to another interface is not.
func TestTheInterfaceIsPartOfTheRule(t *testing.T) {
	filed := UFWFileRules("ip", tuple("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in_eth0", ""))
	same := []Rule{{Family: "ip", Chain: "ufw-user-input",
		Text: `iifname "eth0" tcp dport 22 counter packets 0 bytes 0 accept`}}
	if drift := UFWDrift(filed, same); len(drift) != 0 {
		t.Fatalf("drift = %+v", drift)
	}
	other := []Rule{{Family: "ip", Chain: "ufw-user-input",
		Text: `iifname "eth1" tcp dport 22 counter packets 0 bytes 0 accept`}}
	if drift := UFWDrift(filed, other); len(drift) != 2 {
		t.Fatalf("a rule on another interface passed as the same rule: %+v", drift)
	}
}
