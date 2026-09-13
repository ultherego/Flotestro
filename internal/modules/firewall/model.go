// Package firewall describes the firewall rules of a host.
//
// The module reads the kernel state, not the configuration files of
// services: what the host really filters and what somebody wrote into the
// configuration can drift apart - and a packet bounces off the former.
package firewall

import "time"

// Firewall adapters. The name says who holds the rules on this host.
const (
	AdapterNftables  = "nftables"
	AdapterFirewalld = "firewalld"
	AdapterUFW       = "ufw"
)

// Rule origin. The panel does not pretend everything on the host is its
// own.
const (
	SourceManaged = "managed"
	SourceManual  = "manual"
	// SourceForeign marks a table belonging to another program: docker,
	// firewalld or iptables-nft. The panel does not touch it.
	SourceForeign = "foreign"
)

// FlotestroTable is the only table the panel creates and changes.
//
// The panel rules live in a table of their own, because the host firewall
// usually belongs to somebody already: docker rewrites its chains at every
// container start, and firewalld at every reload. Entering somebody else's
// chains ends in a rule that vanishes without a trace.
const (
	FlotestroFamily = "inet"
	FlotestroTable  = "flotestro"
)

// Rule is one rule in the form nft shows it.
//
// The text is the text from nft, not assembled by the panel: the operator
// knows this notation from the command line, and our own rendering would
// drift from what the host really has.
type Rule struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Chain  string `json:"chain"`
	Handle int    `json:"handle"`
	Text   string `json:"text"`
	Source string `json:"source"`
	// Comment carries the panel marker when the rule belongs to Flotestro.
	Comment string `json:"comment,omitempty"`
	// Packets and Bytes are the rule counters. No value means a rule
	// without a counter, not a rule nothing has passed through.
	Packets *uint64 `json:"packets,omitempty"`
	Bytes   *uint64 `json:"bytes,omitempty"`
}

// Chain is a chain together with its hook and policy.
type Chain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	// Type, Hook and Priority are empty for regular chains: not every chain
	// is hooked into the packet path.
	Type     string `json:"type,omitempty"`
	Hook     string `json:"hook,omitempty"`
	Priority string `json:"priority,omitempty"`
	// Policy concerns base chains only. Empty means no policy, not the
	// policy "accept".
	Policy string `json:"policy,omitempty"`
	Source string `json:"source"`
}

// Table is a rule table together with its owner.
type Table struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	Source string `json:"source"`
	// Owner carries the nft warning about a table belonging to another
	// program.
	Owner string `json:"owner,omitempty"`
}

// Zone describes a firewalld zone.
type Zone struct {
	Name       string   `json:"name"`
	Active     bool     `json:"active"`
	Default    bool     `json:"default"`
	Target     string   `json:"target,omitempty"`
	Interfaces []string `json:"interfaces,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	Services   []string `json:"services,omitempty"`
	Ports      []string `json:"ports,omitempty"`
}

// Snapshot is the picture of the host firewall at one moment.
type Snapshot struct {
	// Adapter names the mechanism that holds the rules on this host.
	Adapter string `json:"adapter,omitempty"`
	// Hash is the fingerprint of the whole ruleset. A change ordered
	// against a different ruleset is not the same change the operator
	// viewed.
	Hash   string  `json:"hash,omitempty"`
	Tables []Table `json:"tables,omitempty"`
	Chains []Chain `json:"chains,omitempty"`
	Rules  []Rule  `json:"rules,omitempty"`
	Zones  []Zone  `json:"zones,omitempty"`
	// Writable says whether the panel can change anything here and why not.
	Writable       bool      `json:"writable"`
	ReadOnlyReason string    `json:"read_only_reason,omitempty"`
	ObservedAt     time.Time `json:"observed_at"`
	// UnavailableReason says why the state could not be determined. A host
	// without rules and a host not asked are two different answers.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}
