package packages

import (
	"strings"
	"testing"
)

// wyjscieUsunieciaDNF5 jest prawdziwym wyjsciem "dnf remove --assumeno"
// z Fedory 42: tabela transakcji przerwanej przed wykonaniem.
const wyjscieUsunieciaDNF5 = `Package      Arch   Version       Repository      Size
Removing:
 restic      x86_64 0.18.1-1.fc42 updates     45.3 MiB
Removing unused dependencies:
 fuse        x86_64 2.9.9-23.fc42 fedora     222.5 KiB
 fuse-common x86_64 3.16.2-6.fc42 updates     38.0   B

Transaction Summary:
 Removing:           3 packages

After this operation, 46 MiB will be freed (install 0 B, remove 46 MiB).
Operation aborted by the user.
`

// wyjscieUsunieciaDNF4 ma inne naglowki i inne podsumowanie.
const wyjscieUsunieciaDNF4 = `Dependencies resolved.
================================================================================
 Package              Arch        Version            Repository           Size
================================================================================
Removing:
 httpd                x86_64      2.4.62-1.el9       @appstream          4.9 M
Removing dependent packages:
 mod_ssl              x86_64      1:2.4.62-1.el9     @appstream          256 k
Removing unused dependencies:
 apr                  x86_64      1.7.0-12.el9       @appstream          290 k

Transaction Summary
================================================================================
Remove  3 Packages

Freed space: 5.4 M
Operation aborted.
`

func TestParsujPlanUsunieciaDNFCzytaWszystkieSekcje(t *testing.T) {
	usuwane, zapowiedziane, err := ParsujPlanUsunieciaDNF(wyjscieUsunieciaDNF5)
	if err != nil {
		t.Fatalf("ParsujPlanUsunieciaDNF: %v", err)
	}
	if len(usuwane) != 3 {
		t.Fatalf("odczytano %d pakietow: %v", len(usuwane), usuwane)
	}
	// Pakiet wskazany i pakiet, ktory zostaje bez uzytkownika, znacza dla
	// czlowieka co innego - ale oba znikaja, wiec oba musza byc na liscie.
	oczekiwane := map[string]bool{"restic": true, "fuse": true, "fuse-common": true}
	for _, nazwa := range usuwane {
		if !oczekiwane[nazwa] {
			t.Errorf("nieoczekiwany pakiet %q", nazwa)
		}
	}
	if zapowiedziane != 3 {
		t.Errorf("dnf zapowiedzial %d pakietow", zapowiedziane)
	}
}

func TestParsujPlanUsunieciaDNFCzytaTakzeStarszyFormat(t *testing.T) {
	usuwane, zapowiedziane, err := ParsujPlanUsunieciaDNF(wyjscieUsunieciaDNF4)
	if err != nil {
		t.Fatalf("ParsujPlanUsunieciaDNF: %v", err)
	}
	if len(usuwane) != 3 {
		t.Fatalf("odczytano %d pakietow: %v", len(usuwane), usuwane)
	}
	// Pakiet zalezny jest tu najwazniejszy: to on zamienia usuniecie jednej
	// rzeczy w usuniecie czegos, o czym nikt nie myslal.
	znaleziony := false
	for _, nazwa := range usuwane {
		if nazwa == "mod_ssl" {
			znaleziony = true
		}
	}
	if !znaleziony {
		t.Errorf("pakiet zalezny nie trafil na liste: %v", usuwane)
	}
	// Liczba z podsumowania jest jedynym zabezpieczeniem przed niepelnym
	// odczytem, wiec musi byc odczytana takze w starszym formacie - tam
	// wiersz brzmi "Remove  3 Packages", bez dwukropka.
	if zapowiedziane != 3 {
		t.Fatalf("dnf4 zapowiedzial %d pakietow", zapowiedziane)
	}
}

func TestBrakPakietuDNFNieJestBledem(t *testing.T) {
	// "Nie ma czego usuwac" jest odpowiedzia, a nie awaria planu.
	if !BrakPakietuDNF("No match for argument: nie-ma-takiego\nNothing to do.") {
		t.Fatal("brak pakietu uznany za blad")
	}
	if BrakPakietuDNF(wyjscieUsunieciaDNF5) {
		t.Fatal("poprawny plan uznany za brak pakietu")
	}
}

func TestParsujPlanInstalacjiDNF(t *testing.T) {
	wyjscie := `Package        Arch   Version         Repository  Size
Installing:
 nginx         x86_64 1.26.2-1.fc42   updates    1.6 MiB
Installing dependencies:
 nginx-core    x86_64 1.26.2-1.fc42   updates    1.4 MiB
 nginx-filesystem noarch 1.26.2-1.fc42 updates   1.0 KiB

Transaction Summary:
 Installing:         3 packages
`
	zmiany := ParsujPlanInstalacjiDNF(wyjscie)
	if len(zmiany) != 3 {
		t.Fatalf("odczytano %d zmian: %+v", len(zmiany), zmiany)
	}
	if zmiany[0].Name != "nginx" {
		t.Errorf("pierwsza zmiana = %+v", zmiany[0])
	}
}

func TestParsujVersionlockCzytaObaFormaty(t *testing.T) {
	dnf5 := "# Added by 'versionlock add' command on 2026-09-05 16:14:05\n" +
		"Package name: restic\nevr = 0.18.1-1.fc42\n"
	if nazwy := ParsujVersionlock(dnf5); len(nazwy) != 1 || nazwy[0] != "restic" {
		t.Fatalf("dnf5: odczytano %v", nazwy)
	}

	// Wiersz o metadanych nie jest blokada. Pokazany jako nazwa pakietu
	// mowilby operatorowi, ze wstrzymano cos, czego nie ma.
	dnf4 := "Last metadata expiration check: 0:00:12 ago on Sat 05 Sep 2026.\n" +
		"restic-0:0.18.1-1.fc42.*\nkernel-0:6.11.4-201.fc41.*\n"
	nazwy := ParsujVersionlock(dnf4)
	if len(nazwy) != 2 {
		t.Fatalf("dnf4: odczytano %v, oczekiwano dokladnie dwoch blokad", nazwy)
	}
	if nazwy[0] != "restic" || nazwy[1] != "kernel" {
		t.Fatalf("dnf4: odczytano %v", nazwy)
	}

	// Nazwa z myslnikiem i pakiet bez epoki tez sa poprawnymi wpisami.
	zlozone := ParsujVersionlock("python3-dnf-plugin-versionlock-0:4.5.0-1.fc42.*\n" +
		"tree-2.2.1-1.fc42.*\n")
	if len(zlozone) != 2 || zlozone[0] != "python3-dnf-plugin-versionlock" || zlozone[1] != "tree" {
		t.Fatalf("odczytano %v", zlozone)
	}
}

func TestPlanInstalacjiNieMilczyOOdmowie(t *testing.T) {
	// Pakiet, ktorego nie ma w zadnym zrodle, nie moze skonczyc sie planem
	// pustym: pusty plan czyta sie jako "nic nie trzeba dokladac".
	if !BrakPakietuDNF("Unable to find a match: nie-ma-takiego-pakietu") {
		t.Fatal("brak pakietu nie zostal rozpoznany")
	}
	// Za to "nothing to do" przy instalacji znaczy, ze wszystko juz jest.
	if !CalaTransakcjaGotowa("Package tree-2.2.1-1.fc42.x86_64 is already installed.\nNothing to do.") {
		t.Fatal("gotowa transakcja nie zostala rozpoznana")
	}
	if CalaTransakcjaGotowa(wyjscieUsunieciaDNF5) {
		t.Fatal("zwykla tabela transakcji uznana za gotowa")
	}
}

func TestNierozwiazywalnaTransakcjaNieJestPustymPlanem(t *testing.T) {
	// Prawdziwa odpowiedz dnf5 na probe usuniecia systemd z Fedory 42.
	wyjscie := `Failed to resolve the transaction:
Problem: installed package kernel-core-6.17.4-200.fc42.x86_64 requires systemd >= 200, but none of the providers can be installed
  - conflicting requests
  - problem with installed package
`
	powod := NierozwiazywalneDNF(wyjscie)
	if powod == "" {
		t.Fatal("odmowa dnf zostala odczytana jako plan pusty")
	}
	if !strings.Contains(powod, "kernel-core") {
		t.Errorf("powod nie mowi, czego nie da sie pogodzic: %q", powod)
	}
	// Poprawna tabela transakcji nie moze byc uznana za odmowe.
	if NierozwiazywalneDNF(wyjscieUsunieciaDNF5) != "" {
		t.Fatal("poprawny plan uznany za odmowe")
	}
}
