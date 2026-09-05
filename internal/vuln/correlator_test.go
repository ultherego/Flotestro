package vuln

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/packages"
)

var teraz = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func snapshotDebiana(wydania ...string) Snapshot {
	return Snapshot{
		Provider: "debian", Digest: "abc123", Releases: wydania,
		FetchedAt: teraz.Add(-time.Hour), Active: true,
	}
}

func wejscieDebiana(pakiety ...packages.InstalledPackage) Wejscie {
	return Wejscie{
		HostID: "host-1", Hostname: "web-01", Distribution: "debian", Release: "trixie",
		Packages: pakiety, InventoryDigest: "lista-1",
	}
}

func pakietDeb(nazwa, wersja, zrodlo string) packages.InstalledPackage {
	if zrodlo == "" {
		zrodlo = nazwa
	}
	return packages.InstalledPackage{
		Name: nazwa, Version: wersja, Architecture: "amd64", SourceName: zrodlo,
	}
}

// TestBrakDanychNieJestBrakiemPodatnosci pilnuje wlasciwosci, dla ktorej ten
// modul w ogole ma sens: panel nie moze powiedziec "bezpieczny", gdy naprawde
// znaczy "nie wiem".
func TestBrakDanychNieJestBrakiemPodatnosci(t *testing.T) {
	pakiety := []packages.InstalledPackage{pakietDeb("openssl", "3.0.11-1", "openssl")}

	przypadki := map[string]struct {
		wejscie  Wejscie
		snapshot Snapshot
		powod    string
	}{
		"brak listy pakietow": {
			wejscie: func() Wejscie {
				w := wejscieDebiana(pakiety...)
				w.BrakListy = true
				return w
			}(),
			snapshot: snapshotDebiana("trixie"),
			powod:    RodzajBrakListy,
		},
		"brak feedu": {
			wejscie: wejscieDebiana(pakiety...), snapshot: Snapshot{Provider: "debian"},
			powod: RodzajBrakFeedu,
		},
		"wydanie spoza feedu": {
			wejscie: wejscieDebiana(pakiety...), snapshot: snapshotDebiana("bookworm"),
			powod: RodzajWydanieNieobslugiwane,
		},
	}
	for nazwa, przypadek := range przypadki {
		ocena := Ocen(przypadek.wejscie, przypadek.snapshot, nil, 6*time.Hour, teraz)
		if ocena.Stan.CoverageReason != przypadek.powod {
			t.Errorf("%s: powod pokrycia = %q, oczekiwano %q",
				nazwa, ocena.Stan.CoverageReason, przypadek.powod)
		}
		if len(ocena.Findings) != 0 {
			t.Errorf("%s: ocena bez danych zwrocila %d ustalen", nazwa, len(ocena.Findings))
		}
		if ocena.Stan.PackagesCovered != 0 {
			t.Errorf("%s: pokrycie %d pakietow bez danych", nazwa, ocena.Stan.PackagesCovered)
		}
	}
}

func TestFeedNieswiezyNieZatrzymujeOcenyAleJestWidoczny(t *testing.T) {
	snapshot := snapshotDebiana("trixie")
	snapshot.FetchedAt = teraz.Add(-48 * time.Hour)
	ustalenia := map[string][]Advisory{
		"openssl": {{
			Provider: "debian", AdvisoryID: "CVE-2026-1000", CVEIDs: []string{"CVE-2026-1000"},
			Distribution: "debian", Release: "trixie", SourcePackage: "openssl",
			FixedVersion: "3.0.15-1", Status: StatusNaprawione, VendorSeverity: "high",
		}},
	}
	ocena := Ocen(wejscieDebiana(pakietDeb("openssl", "3.0.11-1", "openssl")),
		snapshot, ustalenia, 6*time.Hour, teraz)

	// Dane sprzed dwoch dob sa lepsze niz ich brak, ale operator ma wiedziec,
	// ze patrzy na wczorajszy obraz.
	if ocena.Stan.CoverageReason != RodzajFeedNieswiezy {
		t.Fatalf("powod pokrycia = %q", ocena.Stan.CoverageReason)
	}
	if ocena.Stan.Affected != 1 {
		t.Fatalf("ocena nieswiezym feedem nie wykryla podatnosci: %+v", ocena.Stan)
	}
}

func TestOcenaRozstrzygaWersjaProducenta(t *testing.T) {
	ustalenia := map[string][]Advisory{
		"openssl": {{
			Provider: "debian", AdvisoryID: "CVE-2026-1000", CVEIDs: []string{"CVE-2026-1000"},
			Distribution: "debian", Release: "trixie", SourcePackage: "openssl",
			FixedVersion: "3.0.11-1~deb13u2", Status: StatusNaprawione, VendorSeverity: "high",
		}},
	}

	// Wersja z poprawka backportowana wyglada wedlug numeracji upstream tak
	// samo jak podatna - i tylko regula dystrybucji je rozroznia.
	podatny := Ocen(wejscieDebiana(pakietDeb("openssl", "3.0.11-1~deb13u1", "openssl")),
		snapshotDebiana("trixie"), ustalenia, 6*time.Hour, teraz)
	if podatny.Stan.Affected != 1 || len(podatny.Findings) != 1 {
		t.Fatalf("host z podatna wersja: %+v", podatny.Stan)
	}
	if podatny.Findings[0].State != StateAffected {
		t.Fatalf("stan = %q", podatny.Findings[0].State)
	}
	if podatny.Findings[0].ComparatorVersion != WersjaKomparatora {
		t.Error("ustalenie nie mowi, ktora regula porownania je rozstrzygnela")
	}

	naprawiony := Ocen(wejscieDebiana(pakietDeb("openssl", "3.0.11-1~deb13u2", "openssl")),
		snapshotDebiana("trixie"), ustalenia, 6*time.Hour, teraz)
	if naprawiony.Stan.Affected != 0 || len(naprawiony.Findings) != 0 {
		t.Fatalf("host z wersja naprawiona: %+v", naprawiony)
	}
	// Pakiet nie dotyczy oceny - ale nadal jest objety feedem.
	if naprawiony.Stan.PackagesCovered != 1 {
		t.Fatalf("pokrycie = %d", naprawiony.Stan.PackagesCovered)
	}
}

func TestStatusyProducentaMajaOsobneZnaczenia(t *testing.T) {
	przypadki := map[string]struct {
		status  string
		stan    AssessmentState
		powod   string
		naprawa RemediationState
	}{
		"nie dotyczy":          {StatusNieDotyczy, StateNotAffected, "", RemediationUnknown},
		"badane":               {StatusBadane, StateUnknown, RodzajProducentBada, RemediationUnknown},
		"otwarte bez poprawki": {StatusOtwarte, StateAffected, "", RemediationUnavailable},
		"odroczone":            {StatusOdroczone, StateAffected, "", RemediationUnavailable},
	}
	for nazwa, przypadek := range przypadki {
		ustalenia := map[string][]Advisory{
			"openssl": {{
				Provider: "debian", AdvisoryID: "CVE-2026-2000", Distribution: "debian",
				Release: "trixie", SourcePackage: "openssl", Status: przypadek.status,
			}},
		}
		ocena := Ocen(wejscieDebiana(pakietDeb("openssl", "3.0.11-1", "openssl")),
			snapshotDebiana("trixie"), ustalenia, 6*time.Hour, teraz)
		if przypadek.stan == StateNotAffected {
			if len(ocena.Findings) != 0 {
				t.Errorf("%s: ustalenie 'nie dotyczy' trafilo na liste", nazwa)
			}
			continue
		}
		if len(ocena.Findings) != 1 {
			t.Fatalf("%s: %d ustalen", nazwa, len(ocena.Findings))
		}
		ustalenie := ocena.Findings[0]
		if ustalenie.State != przypadek.stan {
			t.Errorf("%s: stan = %q", nazwa, ustalenie.State)
		}
		if ustalenie.ReasonCode != przypadek.powod {
			t.Errorf("%s: powod = %q, oczekiwano %q", nazwa, ustalenie.ReasonCode, przypadek.powod)
		}
		if ustalenie.State == StateUnknown && ustalenie.ReasonCode == "" {
			t.Errorf("%s: stan nieustalony bez kodu powodu", nazwa)
		}
		if ustalenie.Remediation != przypadek.naprawa {
			t.Errorf("%s: naprawa = %q", nazwa, ustalenie.Remediation)
		}
	}
}

func TestPakietSpozaDystrybucjiJestNieznany(t *testing.T) {
	// RPM przebudowany lokalnie albo z obcego repozytorium ma wersje, ktorej
	// producent nie zna. Udawanie, ze jego ustalenia tego dotycza, dawaloby
	// falszywe "bezpieczny".
	wlasny := packages.InstalledPackage{
		Name: "docker-ce", Version: "27.1.1", Release: "1.fc42", Architecture: "x86_64",
		SourceName: "docker-ce", Vendor: "Docker Inc.",
	}
	fedorowy := packages.InstalledPackage{
		Name: "openssl", Epoch: "1", Version: "3.2.6", Release: "4.fc42",
		Architecture: "x86_64", SourceName: "openssl", Vendor: "Fedora Project",
	}
	wejscie := Wejscie{
		HostID: "host-2", Distribution: "fedora", Release: "42",
		Packages: []packages.InstalledPackage{wlasny, fedorowy}, InventoryDigest: "lista-2",
	}
	snapshot := Snapshot{Provider: "fedora", Digest: "f1", Releases: []string{"42"},
		FetchedAt: teraz.Add(-time.Hour)}

	ocena := Ocen(wejscie, snapshot, nil, 6*time.Hour, teraz)
	if ocena.Stan.PackagesCovered != 1 {
		t.Fatalf("pokrycie = %d z %d", ocena.Stan.PackagesCovered, ocena.Stan.PackagesTotal)
	}
	if len(ocena.Findings) != 1 || ocena.Findings[0].BinaryPackage != "docker-ce" {
		t.Fatalf("ustalenia = %+v", ocena.Findings)
	}
	if ocena.Findings[0].ReasonCode != RodzajPochodzenieNieznane {
		t.Errorf("powod = %q", ocena.Findings[0].ReasonCode)
	}
	if ocena.Stan.Unknown != 1 {
		t.Errorf("licznik nieustalonych = %d", ocena.Stan.Unknown)
	}
}

func TestOcenaRPMUwzgledniaEpoke(t *testing.T) {
	// Bez epoki "3.2.6" i "1:3.2.6" wygladaja tak samo, a znacza co innego.
	pakiet := packages.InstalledPackage{
		Name: "openssl", Epoch: "1", Version: "3.2.6", Release: "4.fc42",
		Architecture: "x86_64", SourceName: "openssl", Vendor: "Fedora Project",
	}
	ustalenia := map[string][]Advisory{
		"openssl": {{
			Provider: "fedora", AdvisoryID: "FEDORA-2026-abc", Distribution: "fedora",
			Release: "42", SourcePackage: "openssl", FixedVersion: "1:3.2.7-1.fc42",
			Status: StatusNaprawione, VendorSeverity: "important",
		}},
	}
	wejscie := Wejscie{
		HostID: "host-3", Distribution: "fedora", Release: "42",
		Packages: []packages.InstalledPackage{pakiet}, InventoryDigest: "lista-3",
	}
	snapshot := Snapshot{Provider: "fedora", Digest: "f1", Releases: []string{"42"},
		FetchedAt: teraz.Add(-time.Hour)}

	ocena := Ocen(wejscie, snapshot, ustalenia, 6*time.Hour, teraz)
	if ocena.Stan.Affected != 1 {
		t.Fatalf("stan = %+v", ocena.Stan)
	}
	if ocena.Findings[0].InstalledVersion != "1:3.2.6-4.fc42" {
		t.Fatalf("wersja zainstalowana = %q", ocena.Findings[0].InstalledVersion)
	}
}

func TestUstalenieDlaInnejArchitekturyNieDotyczyPakietu(t *testing.T) {
	// Producent wydaje osobne pakiety dla kazdej architektury; ustalenie dla
	// i686 nie naprawia pakietu x86_64 - a przypisane do niego dawaloby dwa
	// ustalenia o tym samym pakiecie.
	pakiet := packages.InstalledPackage{
		Name: "openssh", Version: "9.9p1", Release: "13.fc42", Architecture: "x86_64",
		SourceName: "openssh", Vendor: "Fedora Project",
	}
	ustalenia := map[string][]Advisory{
		"openssh": {
			{Provider: "fedora", AdvisoryID: "FEDORA-2026-a", SourcePackage: "openssh",
				BinaryPackage: "openssh", Architecture: "i686", FixedVersion: "9.9p1-14.fc42",
				Status: StatusNaprawione, FromHostRepositories: true},
			{Provider: "fedora", AdvisoryID: "FEDORA-2026-a", SourcePackage: "openssh",
				BinaryPackage: "openssh", Architecture: "x86_64", FixedVersion: "9.9p1-14.fc42",
				Status: StatusNaprawione, FromHostRepositories: true},
		},
	}
	wejscie := Wejscie{
		HostID: "host-4", Distribution: "fedora", Release: "42",
		Packages: []packages.InstalledPackage{pakiet}, InventoryDigest: "lista-4",
	}
	snapshot := Snapshot{Provider: "fedora", Digest: "f1", Releases: []string{"42"},
		FetchedAt: teraz.Add(-time.Hour)}

	ocena := Ocen(wejscie, snapshot, ustalenia, 6*time.Hour, teraz)
	if len(ocena.Findings) != 1 {
		t.Fatalf("odczytano %d ustalen: %+v", len(ocena.Findings), ocena.Findings)
	}
	// Ustalenie z metadanych hosta znaczy, ze poprawka lezy w repozytorium,
	// z ktorego host bierze pakiety - i to jest odpowiedz, a nie domysl.
	if ocena.Findings[0].Remediation != RemediationAvailable {
		t.Fatalf("naprawa = %q", ocena.Findings[0].Remediation)
	}
}
