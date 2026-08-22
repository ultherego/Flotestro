package agent

import (
	"testing"
	"time"
)

func TestRevisionIgnorujeZnacznikCzasu(t *testing.T) {
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
		t.Fatalf("rewizja: %v", err)
	}
	secondRev, _, err := second.Revision()
	if err != nil {
		t.Fatalf("rewizja: %v", err)
	}

	// Sam uplyw czasu nie jest zmiana stanu hosta i nie moze tworzyc rewizji.
	if firstRev != secondRev {
		t.Fatalf("ten sam stan dal rozne rewizje: %s != %s", firstRev, secondRev)
	}
}

func TestRevisionWykrywaZmianeStanu(t *testing.T) {
	before := Facts{OS: OSInfo{Family: "debian"}, Packages: Packages{Upgradable: uintPtr(0)}}
	after := before
	after.Packages.Upgradable = uintPtr(7)

	beforeRev, _, err := before.Revision()
	if err != nil {
		t.Fatalf("rewizja: %v", err)
	}
	afterRev, _, err := after.Revision()
	if err != nil {
		t.Fatalf("rewizja: %v", err)
	}
	if beforeRev == afterRev {
		t.Fatal("zmiana liczby aktualizacji nie zmienila rewizji")
	}
}

func TestOSFamilyMapujeDystrybucjeNaRodzineAdapterow(t *testing.T) {
	cases := []struct {
		name    string
		release map[string]string
		want    string
	}{
		{"debian", map[string]string{"ID": "debian"}, "debian"},
		{"ubuntu przez ID", map[string]string{"ID": "ubuntu"}, "debian"},
		{"fedora", map[string]string{"ID": "fedora"}, "rhel"},
		{"rocky przez ID_LIKE", map[string]string{"ID": "rocky", "ID_LIKE": "rhel centos fedora"}, "rhel"},
		{"arch", map[string]string{"ID": "arch"}, "arch"},
		{"nieznana zostaje soba", map[string]string{"ID": "plan9"}, "plan9"},
		{"brak danych", map[string]string{}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := osFamily(tc.release); got != tc.want {
				t.Fatalf("osFamily = %q, oczekiwano %q", got, tc.want)
			}
		})
	}
}

func TestReadHealthKorzystaZBufora(t *testing.T) {
	cached := Facts{
		FailedUnits:      []string{"foo.service", "bar.service"},
		FailedUnitsKnown: true,
		RebootRequired:   boolPtr(true),
		Packages:         Packages{Upgradable: uintPtr(12), SecurityUpgradable: uintPtr(4)},
	}

	// Heartbeat nie uruchamia procesow, wiec te wartosci musza pochodzic
	// z ostatniego cyklu inventory.
	health := ReadHealth(cached)
	if health.FailedUnits == nil || *health.FailedUnits != 2 {
		t.Fatalf("failed units = %v, oczekiwano 2", health.FailedUnits)
	}
	if health.RebootRequired == nil || !*health.RebootRequired {
		t.Fatal("utracono flage reboot required")
	}
	if health.PendingUpdates == nil || *health.PendingUpdates != 12 {
		t.Fatalf("pending updates = %v, oczekiwano 12", health.PendingUpdates)
	}
	if health.PendingSecurityUpdates == nil || *health.PendingSecurityUpdates != 4 {
		t.Fatalf("security updates = %v, oczekiwano 4", health.PendingSecurityUpdates)
	}
	if health.UptimeSeconds == 0 {
		t.Fatal("nie odczytano uptime z /proc")
	}
}

// Regresja: agent raportowal zero i falsz tam, gdzie odczyt sie nie powiodl.
// Nieustalony stan musi zostac nieustalony przez cala droge do heartbeatu.
func TestReadHealthNiePrzeksztalcaNiewiedzyWZero(t *testing.T) {
	// Adapter pakietow zawiodl, systemd nie zostal odpytany, restart nieznany.
	cached := Facts{
		FailedUnitsKnown: false,
		RebootRequired:   nil,
		Packages:         Packages{Manager: "dnf", UnavailableReason: "kod 1: permission denied"},
	}

	health := ReadHealth(cached)
	if health.FailedUnits != nil {
		t.Fatalf("nieustalona liczba failed units stala sie %d", *health.FailedUnits)
	}
	if health.RebootRequired != nil {
		t.Fatalf("nieustalony reboot required stal sie %v", *health.RebootRequired)
	}
	if health.PendingUpdates != nil {
		t.Fatalf("nieustalona liczba aktualizacji stala sie %d", *health.PendingUpdates)
	}
	if health.PendingSecurityUpdates != nil {
		t.Fatalf("nieustalona liczba aktualizacji bezpieczenstwa stala sie %d",
			*health.PendingSecurityUpdates)
	}
}

func uintPtr(value uint32) *uint32 { return &value }
