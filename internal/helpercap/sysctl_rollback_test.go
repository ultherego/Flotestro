package helpercap

import "testing"

// CR-09. A capability for a kernel change authorizes two requests: the change
// the panel signed, and the rollback to what the host held before it. Which of
// the two a request is used to be read off the first key - and a key whose
// prior value already equals the value the panel asked for fits both, so an
// honest rollback was refused as a mixture.
func TestARollbackIsNotAMixtureBecauseOneKeyDidNotMove(t *testing.T) {
	want := map[string]string{"net.ipv4.ip_forward": "1", "net.ipv4.conf.all.rp_filter": "1"}
	before := map[string]string{"net.ipv4.ip_forward": "1", "net.ipv4.conf.all.rp_filter": "0"}

	// The change itself.
	if err := boundSysctl(map[string]string{
		"net.ipv4.ip_forward": "1", "net.ipv4.conf.all.rp_filter": "1"}, want, before); err != nil {
		t.Fatalf("the change the panel signed was refused: %v", err)
	}
	// The rollback: exactly what the host held, including the key that was
	// already at the value the panel asked for.
	if err := boundSysctl(before, want, before); err != nil {
		t.Fatalf("the rollback to what the host held was refused: %v", err)
	}

	// A mixture is still neither: one key forward, one key back.
	mixed := map[string]string{"net.ipv4.ip_forward": "0", "net.ipv4.conf.all.rp_filter": "1"}
	if err := boundSysctl(mixed, want, before); err == nil {
		t.Error("a request that is neither the change nor the rollback was accepted")
	}

	// And a value that is neither the change nor what was there is refused by
	// name, which is the check this one sits beside.
	invented := map[string]string{"net.ipv4.ip_forward": "2", "net.ipv4.conf.all.rp_filter": "1"}
	if err := boundSysctl(invented, want, before); err == nil {
		t.Error("a value the capability never authorized was accepted")
	}

	// Without a record of what was there, only the change is authorized: an
	// unknown prior value is not a rollback target.
	if err := boundSysctl(before, want, nil); err == nil {
		t.Error("a rollback was accepted although nothing recorded what the host held")
	}
}
