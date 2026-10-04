package network

import (
	"slices"
	"strings"
	"testing"
)

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
