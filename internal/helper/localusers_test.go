package helper

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSemantykaShadow pilnuje rozdzielenia blokady od braku hasla. Konto
// zalozone przez panel nie ma hasla i loguje sie kluczem SSH; pokazanie go
// jako zablokowanego bylo by falszywa informacja o odcieciu dostepu.
func TestSemantykaShadow(t *testing.T) {
	sciezka := filepath.Join(t.TempDir(), "shadow")
	zawartosc := "" +
		"zwykly:$y$j9T$sol$hash:20000:0:99999:7:::\n" +
		"zablokowany:!$y$j9T$sol$hash:20000:0:99999:7:::\n" +
		"tylkoklucz:*:20000:0:99999:7:::\n" +
		"zablokowany_bez_hasla:!:20000:0:99999:7:::\n" +
		"pusty::20000:0:99999:7:::\n"
	if err := os.WriteFile(sciezka, []byte(zawartosc), 0o600); err != nil {
		t.Fatal(err)
	}

	states, err := parseShadow(sciezka)
	if err != nil {
		t.Fatal(err)
	}

	przypadki := map[string]shadowState{
		"zwykly":                {locked: false, passwordSet: true},
		"zablokowany":           {locked: true, passwordSet: true},
		"tylkoklucz":            {locked: false, passwordSet: false},
		"zablokowany_bez_hasla": {locked: true, passwordSet: false},
		"pusty":                 {locked: false, passwordSet: false},
	}
	for nazwa, oczekiwany := range przypadki {
		got, known := states[nazwa]
		if !known {
			t.Errorf("%s: brak wpisu", nazwa)
			continue
		}
		if got != oczekiwany {
			t.Errorf("%s: odczytano %+v, oczekiwano %+v", nazwa, got, oczekiwany)
		}
	}

	if _, err := parseShadow(filepath.Join(t.TempDir(), "nie-istnieje")); err == nil {
		t.Error("brak pliku musi byc bledem, a nie pusta mapa kont bez hasel")
	}
}

func TestWalidacjaKluczaPublicznego(t *testing.T) {
	klucz := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 jan@stacja"
	if err := validatePublicKey(klucz); err != nil {
		t.Fatalf("poprawny klucz odrzucony: %v", err)
	}

	// Znak nowej linii pozwolilby dopisac drugi klucz do authorized_keys.
	for nazwa, wartosc := range map[string]string{
		"klucz prywatny": "-----BEGIN OPENSSH PRIVATE KEY-----",
		"nowa linia":     klucz + "\nssh-rsa AAAAB3Nz obcy@stacja",
		"powrot karetki": klucz + "\rssh-rsa AAAAB3Nz obcy@stacja",
		"typ wycofany":   "ssh-dss AAAAB3NzaC1kc3M jan@stacja",
		"bez materialu":  "ssh-ed25519",
		"pusty":          "   ",
	} {
		if err := validatePublicKey(wartosc); err == nil {
			t.Errorf("%s: klucz powinien zostac odrzucony", nazwa)
		}
	}
}

func TestNazwaKontaLokalnego(t *testing.T) {
	for _, nazwa := range []string{"kowalski", "_uslugowe", "jan-nowak", "maszyna$"} {
		if !localUserNamePattern.MatchString(nazwa) {
			t.Errorf("nazwa %q powinna byc dozwolona", nazwa)
		}
	}
	// Nazwa jest wstawiana do polecen systemowych i do sciezki katalogu
	// domowego, wiec ograniczenie jest granica bezpieczenstwa, nie kosmetyka.
	for _, nazwa := range []string{"Kowalski", "../root", "jan nowak", "root;rm", "", "jan/nowak"} {
		if localUserNamePattern.MatchString(nazwa) {
			t.Errorf("nazwa %q nie powinna byc dozwolona", nazwa)
		}
	}
}
