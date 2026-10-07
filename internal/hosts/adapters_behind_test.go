package hosts

import "testing"

// Satisfies and AdaptersBehind answer two halves of one question - "does this
// host meet the requirement" and "which adapter is it about" - and two lists of
// the same thing drift. This holds them together: every requirement Satisfies
// treats specially has to name its adapters, and the adapters it names have to
// be ones that can actually satisfy it.
func TestEveryRequirementNamesTheAdaptersBehindIt(t *testing.T) {
	special := []string{
		NeedPackages, NeedPackageRepair, NeedNetworkWrite,
		NeedDNSWrite, NeedFirewallWrite, NeedFirewallZones, NeedLVM,
	}
	for _, requirement := range special {
		adapters := AdaptersBehind(requirement)
		if len(adapters) == 0 {
			t.Errorf("%s is a requirement of its own and names no adapter", requirement)
			continue
		}
		for _, adapter := range adapters {
			if adapter == requirement {
				t.Errorf("%s names itself as the adapter behind it, which is what makes it special",
					requirement)
			}
		}
		// And the adapters named really do satisfy it: a registry where one of
		// them is available and offers everything has to meet the requirement.
		for _, adapter := range adapters {
			registry := Capabilities{{
				Name: adapter, Available: true,
				Features: map[string]bool{"write": true, "zones": true, "lvm": true, "repair": true},
			}}
			if !registry.Satisfies(requirement) {
				t.Errorf("%s is named behind %s and a host offering it does not satisfy the requirement",
					adapter, requirement)
			}
		}
	}

	// An ordinary requirement is its own adapter, which is the whole of the
	// default case.
	if got := AdaptersBehind(CapSSHD); len(got) != 1 || got[0] != CapSSHD {
		t.Errorf("an adapter requirement came back as %v", got)
	}
	if got := AdaptersBehind(""); got != nil {
		t.Errorf("no requirement came back as %v", got)
	}
}

// And the empty registry answers "no" rather than panicking, because a host
// that has not reported yet is the common case on a fleet that is still
// enrolling.
func TestARegistryThatSaysNothingSatisfiesNothing(t *testing.T) {
	var registry Capabilities
	for _, requirement := range []string{
		NeedPackages, NeedNetworkWrite, NeedLVM, CapSSHD, CapSystemd,
	} {
		if registry.Satisfies(requirement) {
			t.Errorf("a host that has reported no adapter satisfies %s", requirement)
		}
	}
	if !registry.Satisfies("") {
		t.Error("an operation that requires no adapter is refused on a silent host")
	}
}
