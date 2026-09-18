package firewall

import (
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// The files ufw keeps its user rules in. They are what the host filters with
// after the next reload or reboot; what it filters with right now is in the
// kernel, and the two are not the same thing.
const (
	UFWUserRulesFile  = "/etc/ufw/user.rules"
	UFWUser6RulesFile = "/etc/ufw/user6.rules"
)

// The ufw chains the user rules live in. Everything else ufw builds - the
// before and after chains, the logging and the limit chains - is the tool's
// own scaffolding and is rebuilt from scratch at every reload.
const (
	ufwUserInputChain   = "ufw-user-input"
	ufwUserOutputChain  = "ufw-user-output"
	ufwUserForwardChain = "ufw-user-forward"
)

// The directions of a ufw rule. They come from the chain in the kernel and
// from the action of a tuple in the file.
const (
	directionIn      = "in"
	directionOut     = "out"
	directionForward = "fwd"
)

// The reasons a ufw host drifts. A rule is either in both views or it is a
// fact the operator has to know before depending on it.
const (
	// DriftUFWNotLoaded: ufw keeps the rule for the next start, and the
	// kernel is not filtering with it. Nothing enforces it until somebody
	// reloads ufw - and then it appears without anyone ordering it.
	DriftUFWNotLoaded = "ufw_rule_not_loaded"
	// DriftUFWNotPersisted: the kernel filters with a rule ufw does not keep.
	// It disappears at the next reload or reboot, quietly opening or closing
	// a port nobody touched.
	DriftUFWNotPersisted = "ufw_rule_not_persisted"
	// DriftUFWNotComparable: the rule is written in a notation the two views
	// do not share - an application profile, a rate limit, an address set -
	// so the panel cannot say whether it is loaded. Unknown is reported as
	// unknown rather than passed off as agreement.
	DriftUFWNotComparable = "ufw_rule_not_comparable"
)

// UFWFileRules reads the user rules ufw keeps in one of its files.
//
// Only the tuple lines are read. The iptables lines below them are what ufw
// generates from the tuples, and reading them would be reading the same fact
// twice - in a notation that changes with the version of the tool.
//
// The family is the caller's word, because the file says nothing about it:
// user.rules holds the IPv4 rules and user6.rules the IPv6 ones.
func UFWFileRules(family, content string) []Rule {
	var rules []Rule
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		rest, found := strings.CutPrefix(line, "### tuple ###")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 6 {
			continue
		}
		rule := Rule{
			Family: family,
			Table:  UFWTable,
			Chain:  ChainInput,
			Handle: len(rules) + 1,
			Source: SourceManual,
		}
		if direction, _, _ := ufwTupleExtras(fields); direction == directionOut {
			rule.Chain = ChainOutput
		}
		kept := make([]string, 0, len(fields))
		for _, field := range fields {
			value, found := strings.CutPrefix(field, "comment=")
			if !found {
				kept = append(kept, field)
				continue
			}
			// ufw stores the comment hex-encoded, because blanks separate the
			// fields of its own format. The encoded form says nothing to a
			// person, so the rule carries the text and the decoded comment.
			if decoded, err := hex.DecodeString(value); err == nil {
				rule.Comment = string(decoded)
			}
		}
		rule.Text = strings.Join(kept, " ")
		if strings.HasPrefix(rule.Comment, CommentPrefix) {
			rule.Source = SourceManaged
		}
		rules = append(rules, rule)
	}
	return rules
}

// UFWLoadedRules picks, out of the rules read from the kernel, the ones ufw
// put into its user chains. They are what the host filters with now.
func UFWLoadedRules(rules []Rule) []Rule {
	var loaded []Rule
	for _, rule := range rules {
		switch rule.Chain {
		case ufwUserInputChain, ufwUserOutputChain, ufwUserForwardChain:
			loaded = append(loaded, rule)
		}
	}
	return loaded
}

// UFWDrift compares what ufw keeps in its files with what the kernel filters
// with now.
//
// The panel used to read the rules through "ufw show added" alone - the
// tool's own account of itself. A rule written into user.rules by hand and
// never loaded, and a rule loaded into the kernel that no file keeps, are
// both invisible that way: the first does nothing while looking enforced,
// the second stops doing anything at the next reload. Both are reported here,
// each with its own reason.
//
// A rule neither view can express in the other's notation is reported as
// exactly that. When there is one, the rules of the kernel that found no
// counterpart are left unreported: an application profile the file names by
// its name and the kernel by its ports would otherwise look like two drifts
// at once, and a firewall that cries drift is one nobody reads.
func UFWDrift(filed, loaded []Rule) []Drift {
	var drift []Drift
	filedMatches, filedUnreadable := ufwMatches(filed, ufwFiledMatch,
		"ufw keeps this rule in a notation the kernel does not use, so the panel cannot say whether it is loaded", &drift)
	loadedMatches, _ := ufwMatches(loaded, ufwLoadedMatch,
		"the kernel holds this rule in a notation the ufw files do not use, so the panel cannot say whether it is kept", &drift)

	for index, rule := range filed {
		match, ok := filedMatches[index]
		if !ok || ufwMatched(match, loadedMatches) {
			continue
		}
		drift = append(drift, Drift{
			Reason: DriftUFWNotLoaded, Rule: rule.Text, RuleID: UFWRuleID(rule.Comment),
			Family: rule.Family, Chain: rule.Chain,
			Detail: "ufw keeps this rule for its next start and the kernel is not filtering with it; it takes effect only when ufw is reloaded",
		})
	}
	if filedUnreadable > 0 {
		// With a rule the files spell in their own way, a rule of the kernel
		// without a counterpart may well be that very rule. The panel does not
		// name a drift it cannot prove.
		return drift
	}
	for index, rule := range loaded {
		match, ok := loadedMatches[index]
		if !ok || ufwMatched(match, filedMatches) {
			continue
		}
		drift = append(drift, Drift{
			Reason: DriftUFWNotPersisted, Rule: rule.Text, RuleID: UFWRuleID(rule.Comment),
			Family: rule.Family, Chain: rule.Chain,
			Detail: "the kernel filters with this rule and no ufw file keeps it; it disappears at the next reload or reboot",
		})
	}
	return drift
}

// ufwMatches reads one side of the comparison and records the rules it could
// not read as a drift of their own: a rule nobody can compare is not a rule
// that agrees.
func ufwMatches(rules []Rule, read func(Rule) (ufwMatch, bool), detail string,
	drift *[]Drift) (map[int]ufwMatch, int) {
	matches := make(map[int]ufwMatch, len(rules))
	unreadable := 0
	for index, rule := range rules {
		match, ok := read(rule)
		if !ok {
			unreadable++
			*drift = append(*drift, Drift{
				Reason: DriftUFWNotComparable, Rule: rule.Text, RuleID: UFWRuleID(rule.Comment),
				Family: rule.Family, Chain: rule.Chain, Detail: detail,
			})
			continue
		}
		matches[index] = match
	}
	return matches, unreadable
}

// ufwMatch is the part of a rule both views can express.
//
// What ufw writes into its files and what nft prints out of the kernel are
// two notations of one rule. These fields survive the translation in both
// directions; anything else - the counters, the order, the way an address is
// spelled - is the notation rather than the rule.
type ufwMatch struct {
	family    string
	direction string
	verdict   string
	protocol  string
	ports     string
	source    string
	iface     string
}

// compatible says whether two matches describe the same rule.
//
// A rule without a protocol covers every protocol: "ufw allow 22" is one line
// in the file and two rules in the kernel, and neither of them is a drift.
func (m ufwMatch) compatible(other ufwMatch) bool {
	if m.family != other.family || m.direction != other.direction ||
		m.verdict != other.verdict || m.ports != other.ports ||
		m.source != other.source || m.iface != other.iface {
		return false
	}
	return m.protocol == other.protocol || m.protocol == "any" || other.protocol == "any"
}

func ufwMatched(match ufwMatch, against map[int]ufwMatch) bool {
	for _, candidate := range against {
		if match.compatible(candidate) {
			return true
		}
	}
	return false
}

// ufwTupleExtras reads the fields ufw writes after the addresses: the
// direction, the interface the rule is bound to, and whether it names an
// application profile.
//
// The direction is written twice by different versions of the tool - as a
// suffix of the action, and as a field of its own - so the action is read
// first and a field of its own wins over it. A tuple that says neither is an
// incoming rule, which is what ufw meant before it had the other kind.
func ufwTupleExtras(fields []string) (direction, iface string, profile bool) {
	direction = ufwTupleDirection(fields[0])
	for _, extra := range fields[6:] {
		if strings.HasPrefix(extra, "dapp=") || strings.HasPrefix(extra, "sapp=") {
			// An application profile names ports the file does not hold; the
			// kernel holds the ports and not the name.
			profile = true
			continue
		}
		name, device, _ := strings.Cut(extra, "_")
		switch name {
		case directionIn, directionOut, directionForward:
			direction = name
			iface = device
		}
	}
	return direction, iface, profile
}

// ufwTupleDirection reads the direction out of the action of a tuple. ufw
// wrote no direction before it had per-direction rules, and that meant
// incoming.
func ufwTupleDirection(action string) string {
	_, suffix, found := strings.Cut(action, "_")
	if !found {
		return directionIn
	}
	switch suffix {
	case directionOut, directionForward:
		return suffix
	default:
		return directionIn
	}
}

// ufwVerdict translates what ufw calls an action into what the kernel calls
// a verdict.
func ufwVerdict(action string) (string, bool) {
	name, _, _ := strings.Cut(action, "_")
	switch name {
	case "allow":
		return ActionAccept, true
	case "deny":
		return ActionDrop, true
	case "reject":
		return ActionReject, true
	default:
		// A rate limit is a jump to a chain of its own, and the tuple says
		// nothing about the limit itself: the two views cannot be compared.
		return "", false
	}
}

// ufwFiledMatch reads a rule ufw keeps in its file.
func ufwFiledMatch(rule Rule) (ufwMatch, bool) {
	fields := strings.Fields(rule.Text)
	if len(fields) < 6 {
		return ufwMatch{}, false
	}
	verdict, ok := ufwVerdict(fields[0])
	if !ok {
		return ufwMatch{}, false
	}
	direction, iface, profile := ufwTupleExtras(fields)
	if profile {
		return ufwMatch{}, false
	}
	return ufwMatch{
		family:    rule.Family,
		direction: direction,
		verdict:   verdict,
		protocol:  ufwProtocol(fields[1]),
		ports:     ufwPorts(fields[2]),
		source:    ufwAddress(fields[5]),
		iface:     iface,
	}, true
}

var (
	nftProtocol  = regexp.MustCompile(`(?:meta l4proto|ip6? protocol) ([a-z0-9-]+)`)
	nftPortWord  = regexp.MustCompile(`\b([a-z0-9-]+) dport `)
	nftPortValue = regexp.MustCompile(`dport (?:\{([^}]*)\}|([0-9]+(?:-[0-9]+)?))`)
	nftSource    = regexp.MustCompile(`\bip6? saddr (?:\{([^}]*)\}|([^\s]+))`)
	nftInterface = regexp.MustCompile(`\b[io]ifname "([^"]*)"`)
	// The verdicts and the ways out of a chain. The last one in the rule is
	// the one that decides the packet; a jump or a return decides nothing the
	// file could be compared with.
	nftVerdict = regexp.MustCompile(`\b(accept|drop|reject|return|queue|jump|goto)\b`)
)

// lastVerdict returns the verdict a rule ends with. The comment is taken out
// first: a rule commented "drop the rest" does not drop anything.
func lastVerdict(text string) (string, bool) {
	found := nftVerdict.FindAllStringSubmatch(ruleComment.ReplaceAllString(text, ""), -1)
	if len(found) == 0 {
		return "", false
	}
	switch verdict := found[len(found)-1][1]; verdict {
	case ActionAccept, ActionDrop, ActionReject:
		return verdict, true
	default:
		return "", false
	}
}

// ufwLoadedMatch reads a rule the kernel filters with, as nft prints it.
func ufwLoadedMatch(rule Rule) (ufwMatch, bool) {
	text := rule.Text
	match := ufwMatch{family: rule.Family, protocol: "any", ports: "any", source: "any"}
	switch rule.Chain {
	case ufwUserInputChain:
		match.direction = directionIn
	case ufwUserOutputChain:
		match.direction = directionOut
	case ufwUserForwardChain:
		match.direction = directionForward
	default:
		return ufwMatch{}, false
	}
	verdict, ok := lastVerdict(text)
	if !ok {
		// A jump to another chain - the rate limit, the logging - is not a
		// rule the file can be compared with.
		return ufwMatch{}, false
	}
	match.verdict = verdict
	if fields := nftProtocol.FindStringSubmatch(text); fields != nil {
		match.protocol = ufwProtocol(fields[1])
	} else if fields := nftPortWord.FindStringSubmatch(text); fields != nil {
		match.protocol = ufwProtocol(fields[1])
	}
	if fields := nftPortValue.FindStringSubmatch(text); fields != nil {
		if fields[1] != "" {
			match.ports = ufwPorts(fields[1])
		} else {
			match.ports = ufwPorts(fields[2])
		}
	}
	if fields := nftSource.FindStringSubmatch(text); fields != nil {
		if fields[1] != "" {
			// An address set is one rule in the kernel and several in the
			// file, or none at all; it is not compared.
			return ufwMatch{}, false
		}
		match.source = ufwAddress(fields[2])
	}
	if fields := nftInterface.FindStringSubmatch(text); fields != nil {
		match.iface = fields[1]
	}
	return match, true
}

// ufwProtocol normalises the name of a protocol. "any" is not a protocol but
// the absence of one, and both views spell it differently.
func ufwProtocol(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	// "th" is how nft names the transport header when the rule does not care
	// which protocol carries it; ufw writes the same thing as "any".
	if name == "" || name == "any" || name == "all" || name == "th" {
		return "any"
	}
	return name
}

// ufwPorts normalises a port, a list or a range into one spelling: ufw writes
// a range with a colon and nft with a dash, and a list keeps the order it was
// typed in.
func ufwPorts(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "any" {
		return "any"
	}
	parts := strings.Split(value, ",")
	ports := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.ReplaceAll(part, ":", "-"))
		if part == "" {
			continue
		}
		ports = append(ports, part)
	}
	if len(ports) == 0 {
		return "any"
	}
	sort.Strings(ports)
	return strings.Join(ports, ",")
}

// ufwAddress normalises an address. "the whole internet" is written three
// ways between the two views, and all three mean the same rule.
func ufwAddress(value string) string {
	value = strings.TrimSpace(value)
	switch value {
	case "", "any", "0.0.0.0/0", "::/0":
		return "any"
	}
	return value
}
