package firewall

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// The panel chains. The panel holds two: for incoming and outgoing traffic.
// More is not needed, and every extra one is another place where the rule
// order decides access to the host.
const (
	ChainInput  = "input"
	ChainOutput = "output"
)

// Allowed rule actions.
const (
	ActionAccept = "accept"
	ActionDrop   = "drop"
	ActionReject = "reject"
)

// CommentPrefix marks the panel rules. The comment is the only durable
// ownership marker: the handle is assigned by the kernel and changes at
// every table reload.
const CommentPrefix = "flotestro:"

// RuleSpec describes a rule in a form the panel can assemble and revert.
//
// The panel does not accept raw nft notation: the rule text is a language,
// and accepting a language from the operator would mean the host runs
// everything that can be written in it. The wizard assembles the rule from
// fields the panel understands.
type RuleSpec struct {
	// ID is the rule name given by the operator. It goes into the comment,
	// so the rule can be found after a table reload.
	ID    string `json:"id"`
	Chain string `json:"chain"`
	// Action decides what happens to a matching packet.
	Action string `json:"action"`
	// Protocol empty means any protocol.
	Protocol string `json:"protocol,omitempty"`
	// Ports are destination ports: single ones or ranges "1000-2000".
	Ports []string `json:"ports,omitempty"`
	// Sources are source addresses with a mask.
	Sources   []string `json:"sources,omitempty"`
	Interface string   `json:"interface,omitempty"`
	Comment   string   `json:"comment,omitempty"`
}

var (
	ruleIdentifier = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	portRange      = regexp.MustCompile(`^(\d{1,5})(?:-(\d{1,5}))?$`)
	interfaceName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)
)

// Validate checks the rule before assembling the command.
func (r RuleSpec) Validate() error {
	if !ruleIdentifier.MatchString(r.ID) {
		return fmt.Errorf("invalid rule name %q", r.ID)
	}
	if r.Chain != ChainInput && r.Chain != ChainOutput {
		return fmt.Errorf("a rule may only go to the chain %q or %q",
			ChainInput, ChainOutput)
	}
	switch r.Action {
	case ActionAccept, ActionDrop, ActionReject:
	default:
		return fmt.Errorf("unsupported action %q", r.Action)
	}
	switch r.Protocol {
	case "", "tcp", "udp", "icmp":
	default:
		return fmt.Errorf("unsupported protocol %q", r.Protocol)
	}
	if len(r.Ports) > 0 && r.Protocol != "tcp" && r.Protocol != "udp" {
		return fmt.Errorf("ports make sense only for tcp and udp")
	}
	for _, port := range r.Ports {
		if err := validatePort(port); err != nil {
			return err
		}
	}
	for _, source := range r.Sources {
		if _, _, err := net.ParseCIDR(source); err != nil {
			return fmt.Errorf("the source %q is not an address with a mask", source)
		}
	}
	if r.Interface != "" && !interfaceName.MatchString(r.Interface) {
		return fmt.Errorf("invalid interface name %q", r.Interface)
	}
	if strings.ContainsAny(r.Comment, `"\`+"\n") {
		return fmt.Errorf("the comment must not contain a quote or a newline")
	}
	// A rule without any match covers all traffic. Blocking all traffic is
	// a separate decision, not the result of an empty form.
	if r.Protocol == "" && len(r.Ports) == 0 && len(r.Sources) == 0 && r.Interface == "" {
		return fmt.Errorf("a rule without any match covers all traffic")
	}
	return nil
}

func validatePort(port string) error {
	fields := portRange.FindStringSubmatch(port)
	if fields == nil {
		return fmt.Errorf("the port %q is neither a number nor a range", port)
	}
	from, _ := strconv.Atoi(fields[1])
	if from < 1 || from > 65535 {
		return fmt.Errorf("the port %d is outside the range 1-65535", from)
	}
	if fields[2] != "" {
		to, _ := strconv.Atoi(fields[2])
		if to < 1 || to > 65535 || to <= from {
			return fmt.Errorf("the port range %q is empty or out of range", port)
		}
	}
	return nil
}

// Marker assembles the ownership marker of the rule.
func (r RuleSpec) Marker() string {
	if r.Comment == "" {
		return CommentPrefix + " " + r.ID
	}
	return CommentPrefix + " " + r.ID + " - " + r.Comment
}

// Expression assembles the rule text in the nft language.
//
// The fields are returned separately, not as one string, so that the
// command goes as an argument list: text glued into one argument would have
// to pass through a shell.
func (r RuleSpec) Expression() []string {
	var parts []string
	if r.Interface != "" {
		key := "iifname"
		if r.Chain == ChainOutput {
			key = "oifname"
		}
		parts = append(parts, key, `"`+r.Interface+`"`)
	}
	if len(r.Sources) > 0 {
		// The inet family serves both protocols, so the keyword choice
		// depends on what the address is.
		parts = append(parts, addressKeyword(r.Sources[0]), "saddr", set(r.Sources))
	}
	if r.Protocol == "icmp" {
		parts = append(parts, "meta", "l4proto", "icmp")
	} else if r.Protocol != "" && len(r.Ports) > 0 {
		parts = append(parts, r.Protocol, "dport", set(r.Ports))
	} else if r.Protocol != "" {
		parts = append(parts, "meta", "l4proto", r.Protocol)
	}
	// The counter is always there: a rule without a counter does not answer
	// the question "did anything pass through it".
	parts = append(parts, "counter", r.Action, "comment", `"`+r.Marker()+`"`)
	return parts
}

func addressKeyword(address string) string {
	if strings.Contains(address, ":") {
		return "ip6"
	}
	return "ip"
}

// set assembles a list of values in the nft set form. A single element is
// written directly, because nft expands a one-element set anyway.
func set(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return "{ " + strings.Join(values, ", ") + " }"
}

// TableSetupArguments assembles the commands creating the panel table.
//
// The table is our own, because the host firewall usually belongs to
// somebody already: docker rewrites its chains at every container start,
// and firewalld at a reload. The chain policy stays "accept": the panel
// table adds explicit rules, it does not cut the host off by default.
func TableSetupArguments() [][]string {
	return [][]string{
		{NftPath, "add", "table", FlotestroFamily, FlotestroTable},
		{NftPath, "add", "chain", FlotestroFamily, FlotestroTable, ChainInput,
			"{ type filter hook input priority 0 ; policy accept ; }"},
		{NftPath, "add", "chain", FlotestroFamily, FlotestroTable, ChainOutput,
			"{ type filter hook output priority 0 ; policy accept ; }"},
	}
}

// RuleArguments assembles the command adding a rule.
func RuleArguments(rule RuleSpec) ([]string, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	command := []string{NftPath, "add", "rule", FlotestroFamily, FlotestroTable, rule.Chain}
	return append(command, rule.Expression()...), nil
}

// RemovalArguments assembles the command removing a rule by handle.
func RemovalArguments(chain string, handle int) ([]string, error) {
	if chain != ChainInput && chain != ChainOutput {
		return nil, fmt.Errorf("the panel removes rules only from its own chains")
	}
	if handle <= 0 {
		return nil, fmt.Errorf("invalid rule handle %d", handle)
	}
	return []string{NftPath, "delete", "rule", FlotestroFamily, FlotestroTable,
		chain, "handle", strconv.Itoa(handle)}, nil
}

// ProtectsManagementChannel checks that the rule does not cut the panel off
// from the host.
//
// It is the only rule that must not be lost: without it the host stops
// answering and there is nothing to revert the change with. The check is
// conservative - in doubt it refuses, because the cost of a false refusal
// is one click, and the cost of a false approval is a trip to the server
// room.
func ProtectsManagementChannel(rule RuleSpec, panelAddress string, agentPort int) error {
	if rule.Action == ActionAccept {
		return nil
	}
	if rule.Chain == ChainInput && matchesPort(rule, agentPort) {
		return fmt.Errorf("the rule covers the port %d the host talks to the panel through", agentPort)
	}
	if panelAddress != "" && matchesAddress(rule, panelAddress) {
		return fmt.Errorf("the rule covers the address %s the host talks to the panel through", panelAddress)
	}
	// A rule without an address or port restriction covers the management
	// channel too.
	if len(rule.Sources) == 0 && len(rule.Ports) == 0 && rule.Interface == "" {
		return fmt.Errorf("a rule without a restriction covers the connection to the panel too")
	}
	return nil
}

func matchesPort(rule RuleSpec, port int) bool {
	if len(rule.Ports) == 0 {
		// No ports means the whole protocol, and so this port too.
		return rule.Protocol == "" || rule.Protocol == "tcp"
	}
	for _, entry := range rule.Ports {
		fields := portRange.FindStringSubmatch(entry)
		if fields == nil {
			continue
		}
		from, _ := strconv.Atoi(fields[1])
		to := from
		if fields[2] != "" {
			to, _ = strconv.Atoi(fields[2])
		}
		if port >= from && port <= to {
			return true
		}
	}
	return false
}

func matchesAddress(rule RuleSpec, address string) bool {
	if len(rule.Sources) == 0 {
		return false
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	for _, source := range rule.Sources {
		_, network, err := net.ParseCIDR(source)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
