package freeipa

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Directory DNS is a different scope from the host's resolver: there the
// panel tells a host whom to ask, and here - what the directory answers the
// whole network. A record pointing at a wrong address breaks not one host but
// everyone who asks about it.

// The record types the panel can write.
//
// The list is closed and short on purpose. NS, SOA and DNSSEC records change
// how the zone itself works rather than its content - and they are not
// something one adds from a fleet management panel.
const (
	RecordA     = "A"
	RecordAAAA  = "AAAA"
	RecordCNAME = "CNAME"
	RecordTXT   = "TXT"
	RecordSRV   = "SRV"
	RecordPTR   = "PTR"
)

// recordAttribute translates a record type into the directory's field name.
var recordAttribute = map[string]string{
	RecordA:     "arecord",
	RecordAAAA:  "aaaarecord",
	RecordCNAME: "cnamerecord",
	RecordTXT:   "txtrecord",
	RecordSRV:   "srvrecord",
	RecordPTR:   "ptrrecord",
}

var (
	zoneNamePattern   = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.?$`)
	recordNamePattern = regexp.MustCompile(`^(\*|@|[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?)(\.[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?)*$`)
)

// Zone is a DNS zone in the directory.
type Zone struct {
	Name string `json:"name"`
	// Reverse marks a reverse zone (in-addr.arpa or ip6.arpa).
	Reverse bool `json:"reverse"`
}

// Record is one entry in a zone.
type Record struct {
	Zone   string   `json:"zone"`
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Values []string `json:"values"`
	TTL    int      `json:"ttl,omitempty"`
}

// FQDN builds the full name of a record.
func (r Record) FQDN() string {
	if r.Name == "@" || r.Name == "" {
		return strings.TrimSuffix(r.Zone, ".")
	}
	return strings.TrimSuffix(r.Name, ".") + "." + strings.TrimSuffix(r.Zone, ".")
}

// RecordSpec describes a record ordered by the panel.
type RecordSpec struct {
	Zone  string
	Name  string
	Type  string
	Value string
	TTL   int
}

// Validate checks a record before anything goes to the directory.
func (s RecordSpec) Validate() error {
	if !zoneNamePattern.MatchString(s.Zone) {
		return fmt.Errorf("invalid zone name %q", s.Zone)
	}
	if !recordNamePattern.MatchString(s.Name) {
		return fmt.Errorf("invalid record name %q", s.Name)
	}
	if _, known := recordAttribute[s.Type]; !known {
		return fmt.Errorf("the panel does not write records of type %q", s.Type)
	}
	if s.TTL < 0 || s.TTL > 604800 {
		return fmt.Errorf("the TTL %d is out of the range 0-604800", s.TTL)
	}
	value := strings.TrimSpace(s.Value)
	if value == "" {
		return fmt.Errorf("a record requires a value")
	}
	if strings.ContainsAny(value, "\n\r") {
		return fmt.Errorf("the record value contains a newline")
	}
	switch s.Type {
	case RecordA:
		address := net.ParseIP(value)
		if address == nil || address.To4() == nil {
			return fmt.Errorf("%q is not an IPv4 address", value)
		}
	case RecordAAAA:
		address := net.ParseIP(value)
		if address == nil || address.To4() != nil {
			return fmt.Errorf("%q is not an IPv6 address", value)
		}
	case RecordCNAME, RecordPTR:
		if !zoneNamePattern.MatchString(strings.TrimSuffix(value, ".")) {
			return fmt.Errorf("%q is not a domain name", value)
		}
	case RecordSRV:
		// The format is: priority weight port target.
		fields := strings.Fields(value)
		if len(fields) != 4 {
			return fmt.Errorf("an SRV record has the form \"priority weight port target\"")
		}
		for _, field := range fields[:3] {
			number, err := strconv.Atoi(field)
			if err != nil || number < 0 || number > 65535 {
				return fmt.Errorf("invalid number %q in the SRV record", field)
			}
		}
	case RecordTXT:
		if len(value) > 255 {
			return fmt.Errorf("the value of the TXT record is longer than 255 characters")
		}
	}
	return nil
}

// Zones returns the DNS zones of the directory.
func (c *Client) Zones(ctx context.Context) ([]Zone, error) {
	return cached(ctx, c, "dns-zones", func() ([]Zone, error) {
		records, err := c.findRecords(ctx, "dnszone_find")
		if err != nil {
			return nil, err
		}
		zones := make([]Zone, 0, len(records))
		for _, record := range records {
			name := strings.TrimSuffix(first(record, "idnsname"), ".")
			if name == "" {
				continue
			}
			zones = append(zones, Zone{
				Name:    name,
				Reverse: strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa"),
			})
		}
		return zones, nil
	})
}

// Records returns the records of one zone.
//
// We do not cache them: a record is what changes in response to the panel's
// operations, and a list from a minute ago would show the state from before
// the change.
func (c *Client) Records(ctx context.Context, zone string) ([]Record, error) {
	if !zoneNamePattern.MatchString(zone) {
		return nil, fmt.Errorf("invalid zone name %q", zone)
	}
	result, err := c.call(ctx, "dnsrecord_find", []string{zone}, map[string]any{
		"all": true, "sizelimit": 0,
	})
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Result    []map[string]any `json:"result"`
		Truncated bool             `json:"truncated"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, fmt.Errorf("the dnsrecord_find response: %w", err)
	}
	if decoded.Truncated {
		return nil, fmt.Errorf("the directory truncated the list of records of the zone %s", zone)
	}

	var records []Record
	for _, entry := range decoded.Result {
		name := first(entry, "idnsname")
		for recordType, attribute := range recordAttribute {
			values := strings_(entry, attribute)
			if len(values) == 0 {
				continue
			}
			record := Record{Zone: strings.TrimSuffix(zone, "."), Name: name, Type: recordType, Values: values}
			if ttl := first(entry, "dnsttl"); ttl != "" {
				record.TTL, _ = strconv.Atoi(ttl)
			}
			records = append(records, record)
		}
	}
	return records, nil
}

// EnsureRecord adds a record to a zone.
//
// The directory adds the value to the record rather than replacing the whole
// entry: a name with two addresses stays a name with two addresses. The panel
// removes nothing while writing - removal is a separate operation of higher
// risk.
func (c *Client) EnsureRecord(ctx context.Context, spec RecordSpec) (Record, error) {
	if err := spec.Validate(); err != nil {
		return Record{}, err
	}
	options := map[string]any{
		recordAttribute[spec.Type]: []string{spec.Value},
	}
	if spec.TTL > 0 {
		options["dnsttl"] = spec.TTL
	}
	if _, err := c.call(ctx, "dnsrecord_add",
		[]string{spec.Zone, spec.Name}, options); err != nil {
		return Record{}, err
	}
	return Record{
		Zone: strings.TrimSuffix(spec.Zone, "."), Name: spec.Name,
		Type: spec.Type, Values: []string{spec.Value}, TTL: spec.TTL,
	}, nil
}

// RemoveRecord removes one value of a record.
func (c *Client) RemoveRecord(ctx context.Context, spec RecordSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	_, err := c.call(ctx, "dnsrecord_del", []string{spec.Zone, spec.Name}, map[string]any{
		recordAttribute[spec.Type]: []string{spec.Value},
	})
	return err
}

// FullName builds the full name of a record from the zone and a relative
// name.
//
// An entry at the root of a zone is written as "@" and must not give a name
// starting with that character: the PTR target "@.example.test." points at
// nothing while looking like a valid record.
func FullName(zone, name string) string {
	zoneName := strings.TrimSuffix(zone, ".")
	if name == "" || name == "@" {
		return zoneName
	}
	return strings.TrimSuffix(name, ".") + "." + zoneName
}

// NameInZone computes the relative name of a PTR record within the given
// reverse zone.
//
// A reverse zone does not have to cover a whole /24 or /64: an installation
// may have a narrower split, named explicitly in the request. The relative
// name is then longer than one label - and computing it for a /24 gave a
// record for an entirely different address. That is why we compute the full
// arpa name and subtract the zone from it instead of assuming the width of
// the split.
func NameInZone(address, zone string) (string, error) {
	full, err := FullReverseName(address)
	if err != nil {
		return "", err
	}
	cleaned := strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if cleaned == "" {
		return "", fmt.Errorf("no reverse zone was named")
	}
	if !strings.HasSuffix(full, "."+cleaned) {
		return "", fmt.Errorf("the address %s does not belong to the zone %s", address, cleaned)
	}
	return strings.TrimSuffix(full, "."+cleaned), nil
}

// FullReverseName computes the full arpa name for an address.
func FullReverseName(address string) (string, error) {
	zone, name, err := ReverseZone(address)
	if err != nil {
		return "", err
	}
	return name + "." + zone, nil
}

// ReverseZone computes the zone and the name of the PTR record for an
// address.
//
// The reverse record is a separate, visible element of the plan: it decides
// what a query about an address answers - and forgetting it is the most
// common mistake when adding hosts.
func ReverseZone(address string) (zone, name string, err error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return "", "", fmt.Errorf("%q is not an IP address", address)
	}
	if four := ip.To4(); four != nil {
		// A /24 zone is what FreeIPA assumes by default when creating reverse
		// zones; narrower splits require naming the zone explicitly.
		return fmt.Sprintf("%d.%d.%d.in-addr.arpa", four[2], four[1], four[0]),
			strconv.Itoa(int(four[3])), nil
	}
	// IPv6: the name is the hexadecimal nibbles in reverse order; the zone
	// covers the first 64 bits of the address.
	expanded := ip.To16()
	var nibbles []string
	for i := len(expanded) - 1; i >= 0; i-- {
		nibbles = append(nibbles,
			strconv.FormatUint(uint64(expanded[i]&0x0f), 16),
			strconv.FormatUint(uint64(expanded[i]>>4), 16))
	}
	return strings.Join(nibbles[16:], ".") + ".ip6.arpa",
		strings.Join(nibbles[:16], "."), nil
}
