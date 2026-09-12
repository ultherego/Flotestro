package hosts

import "testing"

// An operation's requirement is a logical name: an upgrade is not to know
// whether the host uses apt or dnf.
func TestThePackagesRequirementIsMetByEveryManager(t *testing.T) {
	apt := Capabilities{{Name: CapAPT, Version: 1, Available: true}}
	dnf := Capabilities{{Name: CapDNF, Version: 1, Available: true}}
	neither := Capabilities{
		{Name: CapAPT, Version: 1, Available: false},
		{Name: CapDNF, Version: 1, Available: false},
	}
	if !apt.Satisfies(NeedPackages) || !dnf.Satisfies(NeedPackages) {
		t.Error("a package manager that is present did not satisfy the requirement")
	}
	if neither.Satisfies(NeedPackages) {
		t.Error("a host without a package manager satisfied the requirement")
	}
}

// Repairing the package database exists for apt only. The host is to say so
// when the operation is ordered rather than reject the task after delivery.
func TestARepairRequiresTheAdapterFeature(t *testing.T) {
	withRepair := Capabilities{{Name: CapAPT, Version: 1, Available: true,
		Features: map[string]bool{"repair": true}}}
	if !withRepair.Satisfies(NeedPackageRepair) {
		t.Error("apt with the repair feature did not satisfy the repair requirement")
	}

	fedora := Capabilities{{Name: CapDNF, Version: 1, Available: true,
		Features: map[string]bool{"repair": false}}}
	if fedora.Satisfies(NeedPackageRepair) {
		t.Error("dnf without a repair satisfied the repair requirement")
	}

	withoutTools := Capabilities{{Name: CapAPT, Version: 1, Available: true,
		Features: map[string]bool{"repair": false}}}
	if withoutTools.Satisfies(NeedPackageRepair) {
		t.Error("apt without the debconf tools satisfied the repair requirement")
	}
}

// An agent from before the registry sends no features. Silence must not take
// away from a host an operation that works on it - that would mean treating
// ignorance as a fact.
func TestAnUnknownFeatureDoesNotTakeAwayAnOperation(t *testing.T) {
	beforeRegistry := Capabilities{{Name: CapAPT, Version: 0, Available: true}}
	if !beforeRegistry.Satisfies(NeedPackageRepair) {
		t.Error("a host from before the registry lost the package repair")
	}

	value, known := beforeRegistry.FeatureState(CapAPT, "repair")
	if value || known {
		t.Errorf("feature = %v, known = %v; expected an undetermined state", value, known)
	}
}

// An adapter that is not there certainly has no parts - and that is
// knowledge, not its absence.
func TestAMissingAdapterIsAnAnswer(t *testing.T) {
	registry := Capabilities{{Name: CapAPT, Version: 1, Available: false}}
	if value, known := registry.FeatureState(CapAPT, "repair"); value || !known {
		t.Errorf("feature = %v, known = %v; expected a known absence", value, known)
	}
	empty := Capabilities{}
	if value, known := empty.FeatureState(CapDocker, "anything"); value || !known {
		t.Errorf("feature = %v, known = %v; expected a known absence", value, known)
	}
}

// The reason for unavailability comes from the host and is to reach the
// operator unchanged.
func TestTheReasonComesFromTheHost(t *testing.T) {
	registry := Capabilities{{Name: CapSystemd, Available: false,
		Reason: "this host does not run systemd"}}
	if got := registry.Reason(CapSystemd); got != "this host does not run systemd" {
		t.Errorf("reason = %q", got)
	}
	if got := registry.Reason(CapDocker); got != "" {
		t.Errorf("the reason of an unknown adapter = %q, expected empty", got)
	}
}
