// Package dns describes the host resolver.
//
// The module covers only how the host resolves names. Records in the
// directory are a separate scope with separate permissions: a zone entry in
// FreeIPA is seen by every client of the domain, the host resolver only by
// this host.
package dns

import "time"

// Owners of the resolv.conf file. The owner decides whether the panel may
// change anything at all: a file managed by a service will be overwritten
// anyway, so writing into it would be a change that vanishes on the next
// network event.
const (
	OwnerResolved       = "systemd-resolved"
	OwnerNetworkManager = "networkmanager"
	OwnerDHCP           = "dhcp-client"
	OwnerManual         = "manual"
	OwnerUnknown        = ""
)

// Resolver operating modes.
const (
	ModeStub   = "stub"
	ModeStatic = "static"
	ModeUplink = "uplink"
	ModeFile   = "file"
)

// Link describes the resolver assigned to a single interface.
//
// Per-link DNS matters here: a domain-joined host usually has the directory
// server on one interface and the provider's server on the other, and the
// question "which of them answers" has a different answer for every name.
type Link struct {
	Name    string   `json:"name"`
	Index   int      `json:"index,omitempty"`
	Servers []string `json:"servers,omitempty"`
	Domains []string `json:"domains,omitempty"`
	// DefaultRoute says whether this link serves names outside its domains.
	DefaultRoute *bool  `json:"default_route,omitempty"`
	DNSSEC       string `json:"dnssec,omitempty"`
	DNSOverTLS   string `json:"dns_over_tls,omitempty"`
}

// Snapshot is the state of the host resolver.
type Snapshot struct {
	// Owner says who writes resolv.conf. Empty means the owner is
	// undetermined, not that there is no owner.
	Owner string `json:"owner,omitempty"`
	Mode  string `json:"mode,omitempty"`
	// ResolvConf and ResolvConfTarget describe the file itself: the operator
	// needs to know whether they look at a file or at a symlink to the stub.
	ResolvConf       string   `json:"resolv_conf,omitempty"`
	ResolvConfTarget string   `json:"resolv_conf_target,omitempty"`
	Servers          []string `json:"servers,omitempty"`
	SearchDomains    []string `json:"search_domains,omitempty"`
	Links            []Link   `json:"links,omitempty"`
	DNSSEC           string   `json:"dnssec,omitempty"`
	DNSOverTLS       string   `json:"dns_over_tls,omitempty"`
	// Writable says whether the panel can change anything here and why not.
	Writable          bool      `json:"writable"`
	WriteAdapter      string    `json:"write_adapter,omitempty"`
	ReadOnlyReason    string    `json:"read_only_reason,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// QueryResult describes a single name resolution test.
//
// The test is a fact from the host, not from the panel: the panel sits in a
// different network and its answer says nothing about what the host sees.
type QueryResult struct {
	Name string `json:"name"`
	// Addresses is an empty list when the name has no address - and then
	// Error says why. An empty list without a reason would be silence.
	Addresses  []string `json:"addresses,omitempty"`
	Server     string   `json:"server,omitempty"`
	Error      string   `json:"error,omitempty"`
	TookMillis int64    `json:"took_millis"`
}
