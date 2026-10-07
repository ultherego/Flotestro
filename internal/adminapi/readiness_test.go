package adminapi

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The aggregate is built from two tables the product already keeps: which
// adapter each operation needs, and which adapters each host reports. These
// hold the joining rules, which are where it can go wrong.

func TestTheCostOfAGapIsReadInOperations(t *testing.T) {
	// Every requirement an operation names has to be one AdaptersBehind can
	// speak about, or the screen shows a gap it cannot explain.
	for _, action := range opspec.AllActions() {
		requirement := action.RequiredCapability()
		if requirement == "" {
			continue
		}
		if len(hosts.AdaptersBehind(requirement)) == 0 {
			t.Errorf("%s needs %q and no adapter is named behind it", action, requirement)
		}
	}
}

func TestAHostThatSaidNothingIsNotAHostWithoutAdapters(t *testing.T) {
	// The distinction the whole screen rests on. A silent host fails every
	// requirement, but it is not reported as missing them: it is reported as
	// silent, and the fleet's count of silent hosts carries it.
	var silent hosts.Capabilities
	if silent.Satisfies("docker") {
		t.Fatal("a host that reported nothing satisfies a requirement")
	}
	if reason := capabilityReason(silent, "docker"); reason != "" {
		t.Errorf("a host that reported nothing gave the reason %q", reason)
	}

	// A host that did report, and said why, hands that sentence over - it is
	// the diagnosis and the remedy in one.
	spoke := hosts.Capabilities{
		{Name: "docker", Available: false, Reason: "this host has no Docker socket"},
	}
	if reason := capabilityReason(spoke, "docker"); reason != "this host has no Docker socket" {
		t.Errorf("the host's own sentence came back as %q", reason)
	}
}

func TestTheReasonFollowsTheAdapterAndNotTheRequirement(t *testing.T) {
	// A requirement is not always an adapter: "packages" is any of three, and
	// "storage.lvm" is one adapter and one of its features. The reason belongs
	// to the adapter, so it has to be found through the mapping rather than by
	// looking for a registry entry named after the requirement - which would
	// have found nothing and shown an empty column.
	registry := hosts.Capabilities{
		{Name: "packages.apt", Available: false, Reason: "apt-get is not installed on this host"},
		{Name: "storage", Available: false, Reason: "this host reports no block devices"},
	}
	if reason := capabilityReason(registry, hosts.NeedPackages); reason == "" {
		t.Error("the family requirement found no reason, though an adapter behind it gave one")
	}
	if reason := capabilityReason(registry, hosts.NeedLVM); reason != "this host reports no block devices" {
		t.Errorf("the feature requirement came back with %q", reason)
	}
	// And an adapter that is available carries no reason, however loudly it
	// reported: a present adapter is not an explanation for a gap.
	present := hosts.Capabilities{
		{Name: "docker", Available: true, Reason: "ignored"},
	}
	if reason := capabilityReason(present, "docker"); reason != "" {
		t.Errorf("an available adapter explained a gap with %q", reason)
	}
}

func TestTheReasonNamesTheAdapterTheHostActuallyHas(t *testing.T) {
	// A family: the host runs dnf and dnf offers no repair. Saying "apt-get is
	// not installed on this host" is true of the machine and false about the
	// gap, and it is what the screen said on 07.10 about agent-fedora.
	fedora := hosts.Capabilities{
		{Name: "packages.apt", Available: false, Reason: "apt-get is not installed on this host"},
		{Name: "packages.dnf", Available: true, Features: map[string]bool{"repair": false}},
	}
	reason := capabilityReason(fedora, hosts.NeedPackageRepair)
	if !strings.Contains(reason, "packages.dnf") {
		t.Errorf("the reason for a dnf host is %q and does not name dnf", reason)
	}
	if strings.Contains(reason, "apt") {
		t.Errorf("the reason for a dnf host talks about apt: %q", reason)
	}

	// A feature: the adapter is present and the feature is off, so nothing in
	// the registry is unavailable and the old rule found nothing to say.
	silentFirewall := hosts.Capabilities{
		{Name: "firewall", Available: true, Features: map[string]bool{"zones": false}},
	}
	if reason := capabilityReason(silentFirewall, hosts.NeedFirewallZones); reason == "" {
		t.Error("a present adapter without the feature explained nothing")
	}

	// And an adapter that is simply absent still speaks for itself.
	arch := hosts.Capabilities{
		{Name: "certificates.renew", Available: false, Reason: "this host does not run certmonger"},
	}
	if reason := capabilityReason(arch, "certificates.renew"); reason != "this host does not run certmonger" {
		t.Errorf("an absent adapter came back with %q", reason)
	}
}
