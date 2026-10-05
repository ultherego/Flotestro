package network

import (
	"slices"
	"strings"
	"testing"
)

// An IPv6 search list the host keeps deliberately empty is a policy of its
// own. nmcli prints "--" for an empty list property, the reader turned that
// into no list at all, and the write then treated "no list" as "take the first
// family's" - so a rollback to this profile put lab.example into
// ipv6.dns-search, which the host had never had (audit of 6c38561, HOP-N01).
func TestAnEmptyIPv6SearchListIsRestoredAsEmpty(t *testing.T) {
	const shown = `connection.id:flotestro-lab
ipv4.method:manual
ipv4.addresses:192.168.56.40/24
ipv4.dns:192.168.56.50
ipv4.dns-search:lab.example
ipv4.ignore-auto-dns:no
ipv6.method:manual
ipv6.addresses:2001:db8::40/64
ipv6.dns:2001:db8::53
ipv6.dns-search:--
ipv6.ignore-auto-dns:yes`

	profile := ParseProfile(shown)
	if len(profile.DNSSearch6) != 0 || !profile.DNSSearch6Set {
		t.Fatalf("the host was asked and answered with an empty list: %+v", profile.DNSSearch6)
	}
	arguments, err := ProfileArguments(profile)
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, command := range arguments {
		line += strings.Join(command, " ") + "\n"
	}
	if !strings.Contains(line, "ipv6.dns-search  ") {
		t.Errorf("the write does not restore the empty IPv6 search list:\n%s", line)
	}
	if strings.Contains(line, "ipv6.dns-search lab.example") {
		t.Errorf("the write puts the IPv4 search domains into the second family:\n%s", line)
	}
}

// An order written by hand is the one case where nothing was read, and there
// the first family's domains still stand in for the second.
func TestAnOrderThatWasNeverAskedTakesTheFirstFamilysDomains(t *testing.T) {
	profile := Profile{Connection: "lab", Method: "auto", DNSSearch: []string{"lab.example"}}
	arguments, err := ProfileArguments(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(arguments[0], " "), "ipv6.dns-search lab.example") {
		t.Errorf("an unasked order lost the search domains: %v", arguments[0])
	}
}

// An edit of the first family is an edit of the first family. The copy the
// plan is computed from left the second family's resolver settings out, so
// every address change also set ipv6.dns-search to the IPv4 list and put
// ipv6.ignore-auto-dns back to accepting the automatic servers - two changes
// the operator never ordered and never saw (audit of 6c38561, HOP-N01).
func TestAnIPv4EditKeepsTheSecondFamilysResolver(t *testing.T) {
	current := ParseProfile(`connection.id:lab
ipv4.method:manual
ipv4.addresses:192.168.56.40/24
ipv4.dns:192.168.56.50
ipv4.dns-search:lab.example
ipv4.ignore-auto-dns:no
ipv6.method:manual
ipv6.addresses:2001:db8::40/64
ipv6.dns:2001:db8::53
ipv6.dns-search:v6.example
ipv6.ignore-auto-dns:yes`)

	plan := ComputeProfile("enp0s8", current, ProfileRequest{
		Method: "manual", Addresses: []string{"192.168.56.41/24"}, Gateway: "192.168.56.1",
		DNS: []string{"192.168.56.50"},
	}, IPv6Settings{})
	if plan.Refusal != "" {
		t.Fatalf("the edit was refused: %s", plan.Refusal)
	}
	if !slices.Equal(plan.Desired.DNSSearch6, []string{"v6.example"}) {
		t.Errorf("the IPv4 edit changed the IPv6 search list to %v", plan.Desired.DNSSearch6)
	}
	if !plan.Desired.IgnoreAutoDNS6 {
		t.Error("the IPv4 edit put ipv6.ignore-auto-dns back to accepting the automatic servers")
	}
	arguments, err := ProfileArguments(*plan.Desired)
	if err != nil {
		t.Fatal(err)
	}
	write := strings.Join(arguments[0], " ")
	if !strings.Contains(write, "ipv6.dns-search v6.example") ||
		!strings.Contains(write, "ipv6.ignore-auto-dns yes") {
		t.Errorf("the write loses the second family's resolver: %s", write)
	}
}

// A rollback restores from a snapshot of the profile, so the snapshot has to
// keep what the host keeps. The two families' search domains and
// ignore-auto-dns used to be merged into one pair - the domains as a union and
// the flag as an OR - so a profile with ipv4.ignore-auto-dns=no and ipv6=yes
// came back with yes on both, and both families came back with the union of
// the search lists. The rollback changed a resolver policy nobody had asked it
// to change.
func TestAProfileKeepsTheTwoFamiliesApart(t *testing.T) {
	const shown = `ipv4.method:manual
ipv4.addresses:192.168.56.40/24
ipv4.gateway:192.168.56.1
ipv4.dns:192.168.56.50
ipv4.dns-search:lab.example
ipv4.ignore-auto-dns:no
ipv6.method:manual
ipv6.addresses:2001:db8::40/64
ipv6.dns:2001:db8::53
ipv6.dns-search:v6.example
ipv6.ignore-auto-dns:yes`

	profile := ParseProfile(shown)
	profile.Connection = "flotestro-lab"

	if got := profile.DNSSearch; !slices.Equal(got, []string{"lab.example"}) {
		t.Errorf("the first family's search domains = %v, want only lab.example", got)
	}
	if got := profile.DNSSearch6; !slices.Equal(got, []string{"v6.example"}) {
		t.Errorf("the second family's search domains = %v, want only v6.example", got)
	}
	if profile.IgnoreAutoDNS {
		t.Error("the first family rejects the automatic servers and the host says it does not")
	}
	if !profile.IgnoreAutoDNS6 {
		t.Error("the second family does reject them and the snapshot lost that")
	}

	// And what the rollback would write has to carry them apart again.
	arguments, err := ProfileArguments(profile)
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, command := range arguments {
		line += strings.Join(command, " ") + "\n"
	}
	for _, want := range []string{
		"ipv4.dns-search lab.example",
		"ipv6.dns-search v6.example",
		"ipv4.ignore-auto-dns no",
		"ipv6.ignore-auto-dns yes",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the rollback does not write %q:\n%s", want, line)
		}
	}
}
