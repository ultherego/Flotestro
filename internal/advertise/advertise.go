// Package advertise holds the addresses the agents see the control plane
// under.
//
// The choice of address is one decision with four consequences, and they used
// to be wired separately from one string read at start: the names in the
// panel's certificate, the refusal of an enrolment while the panel is reachable
// from nowhere but this machine, the addresses written into a generated agent
// configuration, and the names a relay may not be issued a certificate for.
// Four call sites, one of them silent when it is missed - a relay taking a
// certificate for the panel's own address looks exactly like a working
// installation.
//
// So the four read one Source instead of each holding a copy. There is one
// value in force at a time, it answers all four questions, and it is read where
// it is used rather than at the start: an administrator confirms the address
// while the panel runs.
package advertise

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// Source answers, from the one value in force, everything the choice of address
// decides. It is the seam: a consumer holds a Source, not a list of names, so a
// confirmation reaches all four at once and none of them can be forgotten.
type Source interface {
	// CertificateNames is what the panel's own certificate is issued for,
	// together with a generation that changes whenever the value in force does.
	// The holder of a certificate compares the generation to know it has to
	// issue again, the way it compares the authority that signs.
	CertificateNames() (dnsNames []string, ips []net.IP, generation uint64)
	// LoopbackOnly says the panel is reachable from nothing but the machine it
	// runs on, whatever it was asked to advertise.
	LoopbackOnly() bool
	// Reachable are the addresses a host on another machine can use, which is
	// what a generated agent configuration dials.
	Reachable() []string
	// ReservedNames are the names a relay may not be issued a certificate for.
	ReservedNames() []string
}

// Set is the names and addresses the agents reach the panel at, in the order
// they try them.
type Set struct {
	names []string
}

// Of takes the names as given, trimmed, with the blanks and the repetitions
// dropped and the order kept.
func Of(names []string) Set {
	var (
		kept []string
		seen = map[string]bool{}
	)
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		key := canonical(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, name)
	}
	return Set{names: kept}
}

// Parse takes the comma-separated form the environment and the flag use.
func Parse(value string) Set { return Of(strings.Split(value, ",")) }

// Names returns the set as it was given.
func (s Set) Names() []string { return append([]string(nil), s.names...) }

// Empty says the set names nothing at all.
func (s Set) Empty() bool { return len(s.names) == 0 }

// String is the comma-separated form.
func (s Set) String() string { return strings.Join(s.names, ",") }

// Equal compares two sets by the names and their order.
func (s Set) Equal(other Set) bool {
	if len(s.names) != len(other.names) {
		return false
	}
	for i := range s.names {
		if canonical(s.names[i]) != canonical(other.names[i]) {
			return false
		}
	}
	return true
}

// CertificateNames is what the panel's certificate has to carry. Loopback is
// always in it: the panel is reached over loopback from the machine it runs on
// - the administrator's own browser, a health check inside the pod - whatever
// the fleet is told to dial.
func (s Set) CertificateNames() (dnsNames []string, ips []net.IP) {
	ips = []net.IP{net.ParseIP("127.0.0.1")}
	seenIP := map[string]bool{"127.0.0.1": true}
	seenName := map[string]bool{}
	for _, name := range s.names {
		if ip := net.ParseIP(name); ip != nil {
			if seenIP[ip.String()] {
				continue
			}
			seenIP[ip.String()] = true
			ips = append(ips, ip)
			continue
		}
		if key := canonical(name); !seenName[key] && key != "localhost" {
			seenName[key] = true
			dnsNames = append(dnsNames, name)
		}
	}
	return append(dnsNames, "localhost"), ips
}

// LoopbackOnly is true when the set names nothing a host on another machine
// could reach. An empty set counts: the certificate is then issued for
// 127.0.0.1 alone, and the packaged control-plane.env ships the value empty.
func (s Set) LoopbackOnly() bool {
	for _, name := range s.names {
		if !IsLoopback(name) {
			return false
		}
	}
	return true
}

// Reachable are the names a host on another machine can use. A set that has
// none answers with the loopback ones it does have, so a single-machine
// installation still gets an instruction it can run there.
func (s Set) Reachable() []string {
	var reachable, loopback []string
	for _, name := range s.names {
		if IsLoopback(name) {
			loopback = append(loopback, name)
			continue
		}
		reachable = append(reachable, name)
	}
	if len(reachable) == 0 {
		return loopback
	}
	return reachable
}

// Validate refuses what cannot be a name of the panel. These names go into a
// certificate, into a YAML file and into the shell command an operator pastes
// on a host, so the panel checks them before it stores them rather than after.
func (s Set) Validate() error {
	if s.Empty() {
		return ErrNoName
	}
	for _, name := range s.names {
		if err := validName(name); err != nil {
			return err
		}
	}
	return nil
}

// The refusals of a proposed set, as the error guide lists them.
var (
	// ErrNoName means a confirmation that names nothing.
	ErrNoName = errors.New("advertised_address_missing")
	// ErrInvalidName means a name that is neither an IP address nor a DNS name:
	// a URL, a host:port pair, an address with a zone, a label with a space.
	ErrInvalidName = errors.New("advertised_address_invalid")
)

// maxNameLength is the ceiling a DNS name has in the wire format, and the
// ceiling a subject alternative name is checked against.
const maxNameLength = 253

func validName(name string) error {
	if ip := net.ParseIP(name); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("%w: %s is not an address a host can dial", ErrInvalidName, name)
		}
		return nil
	}
	switch {
	case len(name) > maxNameLength:
		return fmt.Errorf("%w: a name of %d characters is longer than the %d a DNS name may have",
			ErrInvalidName, len(name), maxNameLength)
	case strings.Contains(name, "/"), strings.Contains(name, ":"):
		return fmt.Errorf("%w: %q names a URL or a port; the panel is advertised as a name "+
			"or an address alone, and the port comes from the listener", ErrInvalidName, name)
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			return fmt.Errorf("%w: %q has an empty label", ErrInvalidName, name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: the label %q of %q starts or ends with a hyphen",
				ErrInvalidName, label, name)
		}
		for _, char := range label {
			switch {
			case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z',
				char >= '0' && char <= '9', char == '-', char == '_':
			default:
				return fmt.Errorf("%w: %q is not a character of a DNS name, and %q carries it",
					ErrInvalidName, string(char), name)
			}
		}
	}
	return nil
}

// IsLoopback says a name reaches nothing but the machine the panel runs on.
func IsLoopback(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return true
	}
	if ip := net.ParseIP(name); ip != nil {
		return ip.IsLoopback()
	}
	return canonical(name) == "localhost"
}

// canonical folds a name the way a certificate check does: case and the
// trailing dot of an absolute name say nothing about which host is meant.
func canonical(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// Candidate is an address the panel found on this machine. It is a proposal and
// nothing more: only an administrator's confirmation makes one the address the
// fleet is told to dial, because the panel cannot tell which of its interfaces
// the hosts can route to, and putting the wrong one into the certificate is a
// fleet that enrols and drops out again.
type Candidate struct {
	Name string `json:"name"`
	// Kind says where it was found: "address" for one read off an interface,
	// "hostname" for the name this machine answers to.
	Kind string `json:"kind"`
	// Interface is the interface the address sits on, empty for a hostname. It is
	// read from the host, never guessed.
	Interface string `json:"interface,omitempty"`
	// Loopback marks a candidate that reaches nothing but this machine. It stays
	// in the list, named for what it is, rather than being hidden: on a
	// single-machine installation it is the honest answer.
	Loopback bool `json:"loopback"`
}

// Detect reads the addresses of this machine and the name it answers to. It
// proposes; it never adopts.
func Detect() []Candidate {
	var candidates []Candidate
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addresses, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, address := range addresses {
				network, ok := address.(*net.IPNet)
				if !ok {
					continue
				}
				ip := network.IP
				// A link-local address needs a zone to be dialled at all, and a
				// certificate cannot carry one; proposing it would be proposing a
				// name that never connects.
				if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
					continue
				}
				candidates = append(candidates, Candidate{
					Name: ip.String(), Kind: "address",
					Interface: iface.Name, Loopback: ip.IsLoopback(),
				})
			}
		}
	}
	if name, err := os.Hostname(); err == nil {
		if name = strings.TrimSpace(name); name != "" && validName(name) == nil {
			candidates = append(candidates, Candidate{
				Name: name, Kind: "hostname", Loopback: IsLoopback(name),
			})
		}
	}
	// The reachable ones first, then by name: the list is read by a person
	// choosing from it, and the order it comes off the kernel is not an order.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Loopback != candidates[j].Loopback {
			return !candidates[i].Loopback
		}
		return candidates[i].Name < candidates[j].Name
	})
	return candidates
}
