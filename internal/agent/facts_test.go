package agent

import (
	"testing"
	"time"
)

func TestRevisionIgnoresTheTimestamp(t *testing.T) {
	base := Facts{
		Hostname:  "agent-debian",
		MachineID: "abc",
		OS:        OSInfo{Family: "debian", Version: "13"},
		Packages:  Packages{Manager: "apt", Upgradable: uintPtr(3)},
	}

	first := base
	first.CollectedAt = time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	second := base
	second.CollectedAt = time.Date(2026, 8, 22, 11, 30, 0, 0, time.UTC)

	firstRev, _, err := first.Revision()
	if err != nil {
		t.Fatalf("revision: %v", err)
	}
	secondRev, _, err := second.Revision()
	if err != nil {
		t.Fatalf("revision: %v", err)
	}

	// The passage of time alone is not a change of the state of the host and must
	// not create a revision.
	if firstRev != secondRev {
		t.Fatalf("the same state gave different revisions: %s != %s", firstRev, secondRev)
	}
}

func TestRevisionDetectsAStateChange(t *testing.T) {
	before := Facts{OS: OSInfo{Family: "debian"}, Packages: Packages{Upgradable: uintPtr(0)}}
	after := before
	after.Packages.Upgradable = uintPtr(7)

	beforeRev, _, err := before.Revision()
	if err != nil {
		t.Fatalf("revision: %v", err)
	}
	afterRev, _, err := after.Revision()
	if err != nil {
		t.Fatalf("revision: %v", err)
	}
	if beforeRev == afterRev {
		t.Fatal("a change in the number of updates did not change the revision")
	}
}

func TestOSFamilyMapsDistributionsToAdapterFamilies(t *testing.T) {
	cases := []struct {
		name    string
		release map[string]string
		want    string
	}{
		{"debian", map[string]string{"ID": "debian"}, "debian"},
		{"ubuntu by ID", map[string]string{"ID": "ubuntu"}, "debian"},
		{"fedora", map[string]string{"ID": "fedora"}, "rhel"},
		{"rocky by ID_LIKE", map[string]string{"ID": "rocky", "ID_LIKE": "rhel centos fedora"}, "rhel"},
		{"arch", map[string]string{"ID": "arch"}, "arch"},
		{"an unknown one stays itself", map[string]string{"ID": "plan9"}, "plan9"},
		{"no data", map[string]string{}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := osFamily(tc.release); got != tc.want {
				t.Fatalf("osFamily = %q, expected %q", got, tc.want)
			}
		})
	}
}

func TestReadHealthUsesTheCache(t *testing.T) {
	cached := Facts{
		FailedUnits:      []string{"foo.service", "bar.service"},
		FailedUnitsKnown: true,
		RebootRequired:   boolPtr(true),
		Packages:         Packages{Upgradable: uintPtr(12), SecurityUpgradable: uintPtr(4)},
	}

	// The heartbeat starts no processes, so these values have to come from the
	// last inventory cycle.
	health := ReadHealth(cached)
	if health.FailedUnits == nil || *health.FailedUnits != 2 {
		t.Fatalf("failed units = %v, expected 2", health.FailedUnits)
	}
	if health.RebootRequired == nil || !*health.RebootRequired {
		t.Fatal("the reboot required flag was lost")
	}
	if health.PendingUpdates == nil || *health.PendingUpdates != 12 {
		t.Fatalf("pending updates = %v, expected 12", health.PendingUpdates)
	}
	if health.PendingSecurityUpdates == nil || *health.PendingSecurityUpdates != 4 {
		t.Fatalf("security updates = %v, expected 4", health.PendingSecurityUpdates)
	}
	if health.UptimeSeconds == 0 {
		t.Fatal("the uptime was not read from /proc")
	}
}

// A regression: the agent used to report zero and false where the read failed.
// A state that was not determined has to stay undetermined all the way to the
// heartbeat.
func TestReadHealthDoesNotTurnIgnoranceIntoZero(t *testing.T) {
	// The package adapter failed, systemd was not queried, the restart is
	// unknown.
	cached := Facts{
		FailedUnitsKnown: false,
		RebootRequired:   nil,
		Packages:         Packages{Manager: "dnf", UnavailableReason: "code 1: permission denied"},
	}

	health := ReadHealth(cached)
	if health.FailedUnits != nil {
		t.Fatalf("an undetermined number of failed units became %d", *health.FailedUnits)
	}
	if health.RebootRequired != nil {
		t.Fatalf("an undetermined reboot required became %v", *health.RebootRequired)
	}
	if health.PendingUpdates != nil {
		t.Fatalf("an undetermined number of updates became %d", *health.PendingUpdates)
	}
	if health.PendingSecurityUpdates != nil {
		t.Fatalf("an undetermined number of security updates became %d",
			*health.PendingSecurityUpdates)
	}
}

func uintPtr(value uint32) *uint32 { return &value }
