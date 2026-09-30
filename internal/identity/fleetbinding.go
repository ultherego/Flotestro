package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ultherego/flotestro/internal/hosts"
)

// The directory names a host in full - FreeIPA refuses an entry that is not
// fully qualified, so a service principal is always <service>/<host>.<domain> -
// while the panel stores the fleet under the name the agent reported, often a
// short one. The view of the services and the rotation of a keytab bind the two
// through this one resolution, so that they can never name different hosts.

// ErrFleetHostAmbiguous means more than one host of the fleet carries the name
// the directory holds. The binding stays unresolved: choosing one of them would
// be a guess about which host is given the task.
var ErrFleetHostAmbiguous = errors.New("more than one host of the fleet carries the name the principal names")

// FleetLister is the part of the host table the binding reads.
type FleetLister interface {
	List(ctx context.Context, filter hosts.ListFilter) ([]hosts.Host, error)
}

// QualifiedHostname is the fully qualified form of a host's name: the name as
// the panel stores it when it already carries a domain, and the name under the
// given domain when it does not. Without a domain to add, a short name stays
// short and so matches nothing the directory holds.
func QualifiedHostname(hostname, domain string) string {
	name := strings.ToLower(strings.Trim(strings.TrimSpace(hostname), "."))
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if name == "" || domain == "" || strings.Contains(name, ".") {
		return name
	}
	return name + "." + domain
}

// ResolveFleetHost binds the fully qualified name the directory holds to the one
// host of the fleet that carries it.
//
// The match is unambiguous when exactly one of the listed hosts qualifies to
// that same name: either the panel stores the host fully qualified and the two
// names are equal, or it stores a short name which, under the domain the host
// itself reported - or the given one when it reported none - is the name the
// directory holds. A short name on its own is a candidate and never a certainty,
// so a fleet that holds both agent-debian and agent-debian.flotestro.test, or
// the same short name twice with no domain on record, leaves the binding
// unresolved instead of routing a task to one of them by chance.
func ResolveFleetHost(listed []hosts.Host, fqdn, domain string) (hosts.Host, error) {
	wanted := strings.ToLower(strings.Trim(strings.TrimSpace(fqdn), "."))
	if wanted == "" {
		return hosts.Host{}, fmt.Errorf("%w: the principal names no host", ErrHostNotInFleet)
	}
	var matched []hosts.Host
	for _, host := range listed {
		// A host that reported its own domain is qualified with that one: a host
		// of another domain does not answer to this name, whoever else might.
		qualifier := domain
		if host.Identity.Domain != "" {
			qualifier = host.Identity.Domain
		}
		if QualifiedHostname(host.Hostname, qualifier) == wanted {
			matched = append(matched, host)
		}
	}
	switch len(matched) {
	case 1:
		return matched[0], nil
	case 0:
		return hosts.Host{}, fmt.Errorf("%w: %s", ErrHostNotInFleet, wanted)
	default:
		// The identifiers, not the names: two hosts stored under the same short
		// name are told apart by nothing else.
		identifiers := make([]string, 0, len(matched))
		for _, host := range matched {
			identifiers = append(identifiers, host.Hostname+" ("+host.ID+")")
		}
		return hosts.Host{}, fmt.Errorf("%w: %s is carried by %s", ErrFleetHostAmbiguous,
			wanted, strings.Join(identifiers, ", "))
	}
}

// LookupFleetHost resolves the name the directory holds over the panel's host
// table. The candidates are read by the first label of that name, since a short
// name is what the panel stores, and the domain the short names are qualified
// with is the one the directory's own name carries.
func LookupFleetHost(ctx context.Context, lister FleetLister, fqdn string) (hosts.Host, error) {
	if lister == nil {
		return hosts.Host{}, fmt.Errorf("this panel has no fleet store to resolve %s through", fqdn)
	}
	wanted := strings.ToLower(strings.Trim(strings.TrimSpace(fqdn), "."))
	label, domain, _ := strings.Cut(wanted, ".")
	if label == "" || domain == "" {
		return hosts.Host{}, fmt.Errorf("%w: %q is not a fully qualified name", ErrHostNotInFleet, fqdn)
	}
	// The search matches the label anywhere in the hostname, so it returns the
	// host stored short next to the one stored in full - which is what tells an
	// ambiguous binding from a certain one. A label shared by more hosts than
	// the page holds resolves to no host rather than to a wrong one.
	listed, err := lister.List(ctx, hosts.ListFilter{Search: label, Limit: 500})
	if err != nil {
		return hosts.Host{}, err
	}
	return ResolveFleetHost(listed, wanted, domain)
}
