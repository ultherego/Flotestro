package firewall

import (
	"fmt"
	"regexp"
	"strings"
)

// The ufw tool and its files.
const (
	UFWPath       = "/usr/sbin/ufw"
	UFWConfigFile = "/etc/ufw/ufw.conf"
	// UFWTable is the table name the panel shows for ufw rules: ufw has
	// no tables of its own the operator would name.
	UFWTable = "ufw"
	// UFWRegistryFile holds the ufw rules the panel created.
	UFWRegistryFile = "ufw-rules.json"
)

// UFWEnabled reads /etc/ufw/ufw. conf. It is what the agent can check without
// starting a process; the helper asks "ufw status" for the running answer.
func UFWEnabled(config string) bool {
	for _, line := range strings.Split(config, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(key) == "ENABLED" {
			return strings.EqualFold(strings.Trim(strings.TrimSpace(value), `"'`), "yes")
		}
	}
	return false
}

// UFWStatus is the header of "ufw status verbose".
type UFWStatus struct {
	Active bool `json:"active"`
	// Defaults is the default policy line as ufw prints it: "deny
	// (incoming), allow (outgoing), disabled (routed)".
	Defaults string `json:"defaults,omitempty"`
	Logging  string `json:"logging,omitempty"`
	// Reason says, for an inactive ufw, what the panel does instead: an installed
	// ufw the operator sees on the host is not the mechanism the panel writes
	// through, and the operator is to know where the rules go.
	Reason string `json:"reason,omitempty"`
}

// UFW's answers about an inactive firewall.
const (
	UFWInactiveWithNftables = "ufw is installed but inactive; the panel writes its own nftables table on this host"
	UFWInactiveReadOnly     = "ufw is installed but inactive, and this host has no nft binary for the panel's own table"
)

// ParseUFWStatus reads the output of "ufw status verbose".
func ParseUFWStatus(output string) UFWStatus {
	var status UFWStatus
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Status":
			status.Active = value == "active"
		case "Default":
			status.Defaults = value
		case "Logging":
			status.Logging = value
		}
	}
	return status
}

// UFWActive says whether "ufw status" reports an active firewall.
func UFWActive(output string) bool {
	return ParseUFWStatus(output).Active
}

var (
	ufwComment = regexp.MustCompile(`\s+comment\s+'((?:[^']|'\\'')*)'\s*$`)
	// ufw accepts a narrow set of characters in a comment; a quote inside one
	// would have to be escaped through its shell quoting, and the panel does not
	// go there.
	ufwCommentText = regexp.MustCompile(`^[A-Za-z0-9 ._:@/,-]*$`)
)

// ParseUFWAdded reads the output of "ufw show added": the user rules in the
// form of the commands that created them.
func ParseUFWAdded(output string) []Rule {
	var rules []Rule
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "ufw ") {
			continue
		}
		text := strings.TrimSpace(strings.TrimPrefix(line, "ufw "))
		rule := Rule{Family: "inet", Table: UFWTable, Chain: ChainInput,
			Handle: len(rules) + 1, Source: SourceManual}
		if fields := ufwComment.FindStringSubmatch(text); fields != nil {
			rule.Comment = strings.ReplaceAll(fields[1], `'\''`, "'")
			text = strings.TrimSpace(ufwComment.ReplaceAllString(text, ""))
		}
		rule.Text = text
		words := strings.Fields(text)
		for i, word := range words {
			if word == "out" && i < 2 {
				rule.Chain = ChainOutput
			}
			if strings.Contains(word, ":") && i > 0 && words[i-1] == "from" {
				rule.Family = "ip6"
			}
		}
		if strings.HasPrefix(rule.Comment, CommentPrefix) {
			rule.Source = SourceManaged
		}
		rules = append(rules, rule)
	}
	return rules
}

// UFWMarker assembles the ownership marker of a ufw rule: the panel prefix
// and the rule name, then the operator's comment.
func (r RuleSpec) UFWMarker() string {
	marker := CommentPrefix + r.ID
	if r.Comment != "" {
		marker += " - " + r.Comment
	}
	return marker
}

// UFWRuleID reads the rule name out of a ufw comment. An empty result means
// a rule that is not the panel's.
func UFWRuleID(comment string) string {
	rest, found := strings.CutPrefix(comment, CommentPrefix)
	if !found {
		return ""
	}
	id, _, _ := strings.Cut(strings.TrimSpace(rest), " ")
	return id
}

// ValidateUFW checks what ufw can express on top of the panel's own
// validation. ufw has no icmp in user rules and no address lists.
func (r RuleSpec) ValidateUFW() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Protocol == "icmp" {
		return fmt.Errorf("ufw does not take icmp rules on its command line")
	}
	if !ufwCommentText.MatchString(r.Comment) {
		return fmt.Errorf("ufw accepts only letters, digits, spaces and . _ : @ / , - in a comment")
	}
	return nil
}

// UFWArguments assembles the commands adding a rule.
func UFWArguments(rule RuleSpec) ([][]string, error) {
	if err := rule.ValidateUFW(); err != nil {
		return nil, err
	}
	sources := rule.Sources
	if len(sources) == 0 {
		sources = []string{"any"}
	}
	var steps [][]string
	for _, source := range sources {
		steps = append(steps, ufwRule(rule, source, false))
	}
	return steps, nil
}

// UFWDeleteArguments assembles the commands deleting a rule by the same
// specification it was added with, marker included.
func UFWDeleteArguments(rule RuleSpec) ([][]string, error) {
	if err := rule.ValidateUFW(); err != nil {
		return nil, err
	}
	sources := rule.Sources
	if len(sources) == 0 {
		sources = []string{"any"}
	}
	var steps [][]string
	for _, source := range sources {
		steps = append(steps, ufwRule(rule, source, true))
	}
	return steps, nil
}

// ufwRule renders one ufw rule as an argument list. The comment goes as a
// single argument: nothing here passes through a shell.
func ufwRule(rule RuleSpec, source string, remove bool) []string {
	command := []string{UFWPath, "--force"}
	if remove {
		command = append(command, "delete")
	}
	command = append(command, ufwAction(rule.Action))
	direction := "in"
	if rule.Chain == ChainOutput {
		direction = "out"
	}
	command = append(command, direction)
	if rule.Interface != "" {
		command = append(command, "on", rule.Interface)
	}
	if rule.Protocol != "" {
		command = append(command, "proto", rule.Protocol)
	}
	command = append(command, "from", source, "to", "any")
	if len(rule.Ports) > 0 {
		ports := make([]string, 0, len(rule.Ports))
		for _, port := range rule.Ports {
			// ufw writes a range with a colon; the panel's form uses a dash.
			ports = append(ports, strings.ReplaceAll(port, "-", ":"))
		}
		command = append(command, "port", strings.Join(ports, ","))
	}
	return append(command, "comment", rule.UFWMarker())
}

// UFWDeletionOfAbsentRule says whether a failed step was the deletion of a
// rule ufw no longer has. That is the state the step wanted, not a failure.
func UFWDeletionOfAbsentRule(step []string, output string) bool {
	if len(step) < 3 || step[0] != UFWPath || step[2] != "delete" {
		return false
	}
	return strings.Contains(strings.ToLower(output), "non-existent rule")
}

// ufwAction names the panel action in ufw's words: ufw drops with "deny"
// and accepts with "allow".
func ufwAction(action string) string {
	switch action {
	case ActionAccept:
		return "allow"
	case ActionDrop:
		return "deny"
	}
	return action
}

// UFWTransition assembles the commands carrying the ufw rules from one
// registry to another: the rules that changed or vanished are deleted by their
// old specification, the rules that appeared or changed are added.
func UFWTransition(from, to Registry) ([][]string, error) {
	var steps [][]string
	for _, old := range from.Rules {
		current, present := to.Find(old.ID)
		if present && sameUFWRule(old, current) {
			continue
		}
		removal, err := UFWDeleteArguments(old)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", old.ID, err)
		}
		steps = append(steps, removal...)
	}
	for _, rule := range to.Rules {
		previous, present := from.Find(rule.ID)
		if present && sameUFWRule(previous, rule) {
			continue
		}
		addition, err := UFWArguments(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		steps = append(steps, addition...)
	}
	return steps, nil
}

func sameUFWRule(a, b RuleSpec) bool {
	return len(differences(a, b)) == 0
}

// CommandLines renders argument lists as the operator would type them, for
// the plan. The lists themselves run without a shell.
func CommandLines(steps [][]string) []string {
	lines := make([]string, 0, len(steps))
	for _, step := range steps {
		words := make([]string, 0, len(step))
		for _, word := range step {
			if strings.ContainsAny(word, " '") {
				word = "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
			}
			words = append(words, word)
		}
		lines = append(lines, strings.Join(words, " "))
	}
	return lines
}

// UFWStatusArguments reads the state of ufw.
func UFWStatusArguments() []string {
	return []string{UFWPath, "status", "verbose"}
}

// UFWAddedArguments lists the user rules as the commands that created them.
func UFWAddedArguments() []string {
	return []string{UFWPath, "show", "added"}
}
