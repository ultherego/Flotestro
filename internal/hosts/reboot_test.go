package hosts

import "testing"

// A restart is shown by two boot identifiers that are both known and
// different. An empty one on either side is an unknown, and an unknown must
// not read as a restart: the panel used to declare the reboot done for a host
// that reported no identifier, or for which it held none from before the
// change (audit of 6c38561, D8).
func TestARestartIsOnlyShownByTwoKnownIdentifiers(t *testing.T) {
	cases := []struct {
		name, before, after string
		shown               bool
	}{
		{name: "two identifiers that differ", before: "boot-a", after: "boot-b", shown: true},
		{name: "the same identifier", before: "boot-a", after: "boot-a"},
		{name: "nothing read from the host", before: "boot-a", after: ""},
		{name: "nothing held from before", before: "", after: "boot-b"},
		{name: "neither side known", before: "", after: ""},
	}
	for _, c := range cases {
		shown, missing := RebootShown(c.before, c.after)
		if shown != c.shown {
			t.Errorf("%s: RebootShown(%q, %q) = %v, expected %v",
				c.name, c.before, c.after, shown, c.shown)
		}
		if shown && missing != "" {
			t.Errorf("%s: a shown restart carries the reason %q", c.name, missing)
		}
		if !shown && missing == "" {
			t.Errorf("%s: a restart that is not shown says nothing about why", c.name)
		}
	}
}
