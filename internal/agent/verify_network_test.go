package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/modules/dns"
	"github.com/ultherego/flotestro/internal/modules/network"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The network verifier is checked against a host made of two stub readers: the
// interfaces with their routes, and the resolver the host would answer with.

func networkHost(snapshot network.Snapshot, resolver dns.Snapshot) *hostReaders {
	return &hostReaders{
		network:  func(context.Context) network.Snapshot { return snapshot },
		resolver: func(context.Context) dns.Snapshot { return resolver },
	}
}

// addressed is an interface that is up and carries the given addresses.
func addressed(name string, addresses ...string) network.Interface {
	link := network.Interface{Name: name, OperState: "up", MTU: 1500}
	for _, address := range addresses {
		family := network.FamilyIPv4
		if strings.Contains(address, ":") {
			family = network.FamilyIPv6
		}
		link.Addresses = append(link.Addresses,
			network.Address{Family: family, Address: address, Permanent: true})
	}
	return link
}

// defaultRoute is the route a gateway is written as on the host.
func defaultRoute(device, gateway, family string) network.Route {
	return network.Route{Destination: "default", Gateway: gateway, Interface: device, Family: family}
}

// localRoute is a route of the family that carries no gateway: it is what makes
// the table of that family a table that was read.
func localRoute(device, destination, family string) network.Route {
	return network.Route{Destination: destination, Interface: device, Family: family}
}

// boolOf is the pointer form of a kernel switch the host reports.
func boolOf(value bool) *bool { return &value }

func networkOrder(payload *opspec.NetworkPayload) verifyInput {
	return verifyInput{
		action:  opspec.ActionNetworkProfileApply,
		payload: opspec.Payload{Network: payload},
	}
}

func TestVerifyingAnOrderedGateway(t *testing.T) {
	in := networkOrder(&opspec.NetworkPayload{
		Interface: "eth0", Method: "manual",
		Addresses: []string{"10.0.0.10/24"}, Gateway: "10.0.0.1",
	})
	link := addressed("eth0", "10.0.0.10/24")

	applied := network.Snapshot{
		Interfaces: []network.Interface{link},
		Routes:     []network.Route{defaultRoute("eth0", "10.0.0.1", network.FamilyIPv4)},
	}
	expectVerified(t, verifyNetworkState(context.Background(), networkHost(applied, dns.Snapshot{}), in))

	// The address landed and the gateway did not: the table of the family was
	// read, so this is a difference and not an unread host.
	withoutGateway := network.Snapshot{
		Interfaces: []network.Interface{link},
		Routes:     []network.Route{localRoute("eth0", "10.0.0.0/24", network.FamilyIPv4)},
	}
	expectMismatch(t, verifyNetworkState(context.Background(), networkHost(withoutGateway, dns.Snapshot{}), in))

	// Another router than the one ordered is not the change that was ordered.
	elsewhere := network.Snapshot{
		Interfaces: []network.Interface{link},
		Routes:     []network.Route{defaultRoute("eth0", "10.0.0.254", network.FamilyIPv4)},
	}
	expectMismatch(t, verifyNetworkState(context.Background(), networkHost(elsewhere, dns.Snapshot{}), in))

	// No route of the family at all: the host was not read, and an unread host
	// is never a success.
	noTable := network.Snapshot{Interfaces: []network.Interface{link}}
	expectUnreadable(t, verifyNetworkState(context.Background(), networkHost(noTable, dns.Snapshot{}), in))
}

func TestVerifyingAnOrderedGatewayOfTheSecondFamily(t *testing.T) {
	in := networkOrder(&opspec.NetworkPayload{
		Interface: "eth0", Method6: "manual",
		Addresses6: []string{"2001:db8::10/64"}, Gateway6: "fe80::1",
	})
	link := addressed("eth0", "2001:db8::10/64")
	link.IPv6 = &network.IPv6Settings{Disabled: boolOf(false)}

	applied := network.Snapshot{
		Interfaces: []network.Interface{link},
		Routes: []network.Route{
			defaultRoute("eth0", "fe80::1", network.FamilyIPv6),
			defaultRoute("eth0", "10.0.0.1", network.FamilyIPv4),
		},
	}
	expectVerified(t, verifyNetworkState(context.Background(), networkHost(applied, dns.Snapshot{}), in))

	// The first family has its default route and the second has none: a
	// verifier reading only one table would call this applied.
	firstFamilyOnly := network.Snapshot{
		Interfaces: []network.Interface{link},
		Routes: []network.Route{
			defaultRoute("eth0", "10.0.0.1", network.FamilyIPv4),
			localRoute("eth0", "2001:db8::/64", network.FamilyIPv6),
		},
	}
	expectMismatch(t, verifyNetworkState(context.Background(), networkHost(firstFamilyOnly, dns.Snapshot{}), in))
}

func TestVerifyingAProfileThatOrdersNoAddress(t *testing.T) {
	// The order the panel validates without addresses: an automatic method
	// with a gateway and servers typed next to it.
	in := networkOrder(&opspec.NetworkPayload{
		Interface: "eth0", Method: "auto",
		Gateway: "10.0.0.1", DNS: []string{"10.0.0.53"},
	})
	link := addressed("eth0", "192.168.122.55/24")
	resolver := dns.Snapshot{Links: []dns.Link{{Name: "eth0", Servers: []string{"10.0.0.53"}}}}

	// An interface that is up and carries an address it got from DHCP says
	// nothing about the gateway that was ordered.
	leased := network.Snapshot{
		Interfaces: []network.Interface{link},
		Routes:     []network.Route{defaultRoute("eth0", "192.168.122.1", network.FamilyIPv4)},
	}
	expectMismatch(t, verifyNetworkState(context.Background(), networkHost(leased, resolver), in))

	applied := network.Snapshot{
		Interfaces: []network.Interface{addressed("eth0", "10.0.0.10/24")},
		Routes:     []network.Route{defaultRoute("eth0", "10.0.0.1", network.FamilyIPv4)},
	}
	expectVerified(t, verifyNetworkState(context.Background(), networkHost(applied, resolver), in))
}

func TestVerifyingTheOrderedResolvers(t *testing.T) {
	in := networkOrder(&opspec.NetworkPayload{
		Interface: "eth0", Method: "manual",
		Addresses: []string{"10.0.0.10/24"}, DNS: []string{"10.0.0.53", "10.0.0.54"},
	})
	host := network.Snapshot{
		Interfaces: []network.Interface{addressed("eth0", "10.0.0.10/24")},
		Routes:     []network.Route{defaultRoute("eth0", "10.0.0.1", network.FamilyIPv4)},
	}

	onTheLink := dns.Snapshot{Links: []dns.Link{
		{Name: "eth0", Servers: []string{"10.0.0.53", "10.0.0.54"}},
		{Name: "eth1", Servers: []string{"192.0.2.53"}},
	}}
	expectVerified(t, verifyNetworkState(context.Background(), networkHost(host, onTheLink), in))

	// The address is on the host and the servers are not: the change is not
	// the one that was ordered.
	halfWritten := dns.Snapshot{Links: []dns.Link{{Name: "eth0", Servers: []string{"10.0.0.53"}}}}
	expectMismatch(t, verifyNetworkState(context.Background(), networkHost(host, halfWritten), in))

	fromTheLease := dns.Snapshot{Servers: []string{"192.168.122.1"}}
	expectMismatch(t, verifyNetworkState(context.Background(), networkHost(host, fromTheLease), in))

	// A resolver that could not be read is unknown, not a pass.
	silent := dns.Snapshot{UnavailableReason: "resolvectl is not on this host"}
	expectUnreadable(t, verifyNetworkState(context.Background(), networkHost(host, silent), in))
	expectUnreadable(t, verifyNetworkState(context.Background(), networkHost(host, dns.Snapshot{}), in))

	withoutResolver := &hostReaders{network: func(context.Context) network.Snapshot { return host }}
	expectUnreadable(t, verifyNetworkState(context.Background(), withoutResolver, in))
}

func TestVerifyingTheRouterAdvertisementSwitch(t *testing.T) {
	in := networkOrder(&opspec.NetworkPayload{Interface: "eth0", AcceptRA: network.AcceptRAOn})
	host := func(acceptRA int) network.Snapshot {
		link := addressed("eth0", "2001:db8::10/64")
		link.IPv6 = &network.IPv6Settings{Disabled: boolOf(false), AcceptRA: &acceptRA}
		return network.Snapshot{Interfaces: []network.Interface{link}}
	}

	expectVerified(t, verifyNetworkState(context.Background(), networkHost(host(1), dns.Snapshot{}), in))

	// accept_ra 2 is on-forwarding: another setting than the one ordered, and
	// taking it for "on" reports a change that did not happen.
	expectMismatch(t, verifyNetworkState(context.Background(), networkHost(host(2), dns.Snapshot{}), in))
	expectMismatch(t, verifyNetworkState(context.Background(), networkHost(host(0), dns.Snapshot{}), in))

	forwarding := networkOrder(&opspec.NetworkPayload{
		Interface: "eth0", AcceptRA: network.AcceptRAForwarding})
	expectVerified(t, verifyNetworkState(context.Background(), networkHost(host(2), dns.Snapshot{}), forwarding))
	expectMismatch(t, verifyNetworkState(context.Background(), networkHost(host(1), dns.Snapshot{}), forwarding))
}
