package hosts

import (
	"strings"
	"testing"
)

// The three states ask three different questions of the registry: a host that never reported
// an adapter is not a host that reported it unusable.
func TestACapabilityStateAsksOfTheRegistryWhatItSays(t *testing.T) {
	ask := func(state string) (string, error) {
		conditions, _, err := ListFilter{Capability: "docker", CapabilityState: state}.conditions()
		return strings.Join(conditions, " and "), err
	}
	available, err := ask("")
	if err != nil || !strings.Contains(available, "r.available)") || strings.Contains(available, "not ") {
		t.Fatalf("the default is the hosts that have it: %q %v", available, err)
	}
	if same, _ := ask(CapabilityAvailable); same != available {
		t.Fatalf("available differs from the default: %q", same)
	}
	missing, _ := ask(CapabilityMissing)
	if !strings.Contains(missing, "not r.available") || strings.Contains(missing, "not exists") {
		t.Fatalf("missing is a row that says unusable: %q", missing)
	}
	unknown, _ := ask(CapabilityUnknown)
	if !strings.Contains(unknown, "not exists") || strings.Contains(unknown, "r.available") {
		t.Fatalf("unknown is the absence of any row: %q", unknown)
	}
	if _, err := ask("absent"); err == nil {
		t.Fatal("a state that is none of the three was accepted")
	}
}
