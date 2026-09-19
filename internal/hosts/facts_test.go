package hosts

import (
	"errors"
	"strings"
	"testing"
)

// The owner is a name the operator types; the panel keeps it short and
// printable, and lets it be empty, because "nobody" is an honest answer.
func TestNormalizeOwner(t *testing.T) {
	cases := []struct {
		in, want string
		invalid  bool
	}{
		{in: "  platform team  ", want: "platform team"},
		{in: "", want: ""},
		{in: strings.Repeat("a", MaxOwnerLength), want: strings.Repeat("a", MaxOwnerLength)},
		{in: strings.Repeat("a", MaxOwnerLength+1), invalid: true},
		{in: "line\nbreak", invalid: true},
		{in: "tab\there", invalid: true},
	}
	for _, c := range cases {
		got, err := NormalizeOwner(c.in)
		if c.invalid {
			if !errors.Is(err, ErrInvalidOwner) {
				t.Errorf("NormalizeOwner(%q) = %q, %v; want ErrInvalidOwner", c.in, got, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NormalizeOwner(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

// A manual management address is an IP address or a host name, spelled one way
// whatever the operator typed; anything else is refused before it reaches the
// row, because an address nobody can dial is worse than none.
func TestNormalizeManagementAddress(t *testing.T) {
	cases := []struct {
		in, want string
		invalid  bool
	}{
		{in: "", want: ""},
		{in: " 192.168.56.30 ", want: "192.168.56.30"},
		{in: "2001:DB8::1", want: "2001:db8::1"},
		{in: "Db01.Example.Internal.", want: "db01.example.internal"},
		{in: "web-02", want: "web-02"},
		{in: "-bad.example", invalid: true},
		{in: "bad_name.example", invalid: true},
		{in: "http://db01", invalid: true},
		{in: "10.0.0.1:22", invalid: true},
		{in: strings.Repeat("a", 64) + ".example", invalid: true},
	}
	for _, c := range cases {
		got, err := NormalizeManagementAddress(c.in)
		if c.invalid {
			if !errors.Is(err, ErrInvalidAddress) {
				t.Errorf("NormalizeManagementAddress(%q) = %q, %v; want ErrInvalidAddress", c.in, got, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NormalizeManagementAddress(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

// The list filters on facts a host may not have reported: a host that has not
// said whether it needs a reboot is in neither the "yes" nor the "no" list,
// and the SQL has to say so rather than treat null as false.
func TestFilterConditionsLeaveUnknownFactsOut(t *testing.T) {
	yes, no := true, false
	conditions, _, err := ListFilter{RebootRequired: &yes, SecurityUpdates: &yes, IdentityDomain: "corp.example"}.conditions()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(conditions, " and ")
	for _, want := range []string{"h.reboot_required = true", "h.pending_security_updates > 0", "h.identity_domain = $1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the conditions %q lack %q", joined, want)
		}
	}
	conditions, _, err = ListFilter{RebootRequired: &no, SecurityUpdates: &no}.conditions()
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(conditions, " and ")
	for _, want := range []string{"h.reboot_required = false", "h.pending_security_updates = 0"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the conditions %q lack %q", joined, want)
		}
	}
	if strings.Contains(joined, "coalesce") {
		t.Errorf("the conditions %q read an unknown count as zero", joined)
	}
}
