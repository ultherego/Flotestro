package network

import (
	"strings"
	"testing"
)

// NetworkManager refuses ipv6.dns-search on a connection whose second family
// carries no configuration - "this property is not allowed for
// 'method=link-local'" - and refuses the whole invocation with it. So a resolver
// change on such a host failed outright, while its IPv4 half was perfectly
// writable. Measured on agent-arch on 02.10.
func TestTheResolverChangeLeavesOutTheFamilyThatCarriesNoResolver(t *testing.T) {
	for _, method := range []string{"link-local", "disabled", "ignore"} {
		commands, err := DNSArguments("lab", []string{"192.168.56.50"},
			[]string{"flotestro.test"}, false, method)
		if err != nil {
			t.Fatalf("method %s: %v", method, err)
		}
		flat := strings.Join(commands[0], " ")
		for _, key := range []string{"ipv6.dns", "ipv6.dns-search", "ipv6.ignore-auto-dns"} {
			if strings.Contains(flat, key) {
				t.Errorf("method %s: the command still names %s: %s", method, key, flat)
			}
		}
		if !strings.Contains(flat, "ipv4.dns-search flotestro.test") {
			t.Errorf("method %s: the first family lost its search domains: %s", method, flat)
		}
	}
}

func TestTheResolverChangeKeepsBothFamiliesWhereTheSecondCarriesOne(t *testing.T) {
	for _, method := range []string{"", "auto", "manual", "dhcp", "shared"} {
		commands, err := DNSArguments("lab", []string{"192.168.56.50", "2001:db8::53"},
			[]string{"flotestro.test"}, false, method)
		if err != nil {
			t.Fatalf("method %q: %v", method, err)
		}
		flat := strings.Join(commands[0], " ")
		if !strings.Contains(flat, "ipv6.dns 2001:db8::53") {
			t.Errorf("method %q: the second family lost its server: %s", method, flat)
		}
		if !strings.Contains(flat, "ipv6.dns-search flotestro.test") {
			t.Errorf("method %q: the second family lost its search domains: %s", method, flat)
		}
	}
}

// An IPv6 server ordered onto a connection that cannot hold one is a refusal
// with a reason. Writing the first family and saying nothing about the second
// would report a resolver the host does not have.
func TestAnIPv6ServerOnAConnectionThatCarriesNoneIsRefusedByName(t *testing.T) {
	_, err := DNSArguments("lab", []string{"2001:db8::53"}, nil, false, "link-local")
	if err == nil {
		t.Fatal("an IPv6 server was accepted onto a link-local connection")
	}
	for _, want := range []string{"link-local", "2001:db8::53", "lab"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}
}
