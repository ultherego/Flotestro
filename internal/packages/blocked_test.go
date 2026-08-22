package packages

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStanPakietowZBazyDpkg pilnuje rozpoznawania pakietow, ktore zablokuja
// kazda kolejna transakcje. Typowy przypadek z floty: pakiet rozpakowany, ale
// nieskonfigurowany, bo jego pytanie konfiguracyjne nie ma odpowiedzi. Dopoki
// tak stoi, aktualizacje na tym hoscie nie przechodza - takze wtedy, gdy nie
// ma nic do zaktualizowania.
func TestStanPakietowZBazyDpkg(t *testing.T) {
	sciezka := filepath.Join(t.TempDir(), "status")
	zawartosc := `Package: bash
Status: install ok installed
Version: 5.2

Package: grub-pc
Status: install ok unpacked
Version: 2.12

Package: cpp
Status: deinstall ok config-files
Version: 4:14.2

Package: libfoo
Status: install ok half-configured
Version: 1.0

Package: bar
Status: purge ok not-installed

Package: uszkodzony
Version: bez statusu
`
	if err := os.WriteFile(sciezka, []byte(zawartosc), 0o644); err != nil {
		t.Fatal(err)
	}

	blocked := blockedFromStatusFile(sciezka)
	nazwy := map[string]string{}
	for _, pakiet := range blocked {
		nazwy[pakiet.Name] = pakiet.Status
	}

	if len(blocked) != 2 {
		t.Fatalf("rozpoznano %d pakietow blokujacych: %v", len(blocked), nazwy)
	}
	if nazwy["grub-pc"] != "install ok unpacked" {
		t.Errorf("grub-pc: status %q", nazwy["grub-pc"])
	}
	if _, jest := nazwy["libfoo"]; !jest {
		t.Error("pakiet w stanie half-configured musi byc rozpoznany")
	}
	// Pakiet w pelni zainstalowany i pakiet po usunieciu niczego nie blokuja.
	for _, spokojny := range []string{"bash", "cpp", "bar"} {
		if _, jest := nazwy[spokojny]; jest {
			t.Errorf("pakiet %s nie blokuje niczego", spokojny)
		}
	}

	// Brak pliku nie moze udawac, ze wszystko jest w porzadku ani wywracac
	// odczytu: zwracamy pusta liste i idziemy dalej.
	if blocked := blockedFromStatusFile(filepath.Join(t.TempDir(), "nie-ma")); blocked != nil {
		t.Errorf("brak pliku dal %v", blocked)
	}
}
