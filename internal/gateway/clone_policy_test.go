package gateway

import "testing"

// TestCloneReactionFollowsThePolicy guards the decision on a copied identity:
// the report policy records and lets the newer session stand, the quarantine
// policy cuts the host off with both sessions, and no detection is no reaction
func TestCloneReactionFollowsThePolicy(t *testing.T) {
	elsewhere := cloneSighting{Detected: true}
	here := cloneSighting{Detected: true, SameAddress: true}
	nothing := cloneSighting{}
	cases := []struct {
		name     string
		policy   ClonePolicy
		sighting cloneSighting
		want     cloneReaction
	}{
		{"report, clone seen", CloneReport, elsewhere, cloneReaction{Policy: CloneReport}},
		{"quarantine, clone seen", CloneQuarantine, elsewhere,
			cloneReaction{Policy: CloneQuarantine, Quarantine: true, EndSessions: true}},
		{"unset is quarantine", "", elsewhere,
			cloneReaction{Policy: CloneQuarantine, Quarantine: true, EndSessions: true}},
		{"quarantine, same address", CloneQuarantine, here, cloneReaction{Policy: CloneQuarantine}},
		{"quarantine, nothing seen", CloneQuarantine, nothing, cloneReaction{Policy: CloneQuarantine}},
		{"report, nothing seen", CloneReport, nothing, cloneReaction{Policy: CloneReport}},
	}
	for _, c := range cases {
		if got := reactToClone(c.policy, c.sighting); got != c.want {
			t.Errorf("%s: reaction %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestSameAddressIgnoresThePort guards the comparison of two sessions'
// addresses: the port differs every time, an unknown address matches nothing.
func TestSameAddressIgnoresThePort(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"192.168.56.30:51234", "192.168.56.30:51900", true},
		{"192.168.56.30:51234", "203.0.113.7:51234", false},
		{"[fd00::30]:4433", "[fd00::30]:4434", true},
		{"", "192.168.56.30:51234", false},
		{"192.168.56.30", "192.168.56.30:51234", true},
	}
	for _, c := range cases {
		if got := sameAddress(c.a, c.b); got != c.want {
			t.Errorf("sameAddress(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestClonePolicyIsReadStrictly guards the configuration: the two words are
// accepted in any case and spacing, empty is the default, and a word the
// gateway does not know is refused rather than taken for one of them.
func TestClonePolicyIsReadStrictly(t *testing.T) {
	for value, want := range map[string]ClonePolicy{
		"": CloneQuarantine, "report": CloneReport, " Quarantine ": CloneQuarantine, "REPORT": CloneReport,
	} {
		got, err := ParseClonePolicy(value)
		if err != nil || got != want {
			t.Errorf("%q read as %q, %v; want %q", value, got, err, want)
		}
	}
	for _, value := range []string{"disconnect", "true", "quarantine,report"} {
		if got, err := ParseClonePolicy(value); err == nil {
			t.Errorf("%q was accepted as %q", value, got)
		}
	}
}
