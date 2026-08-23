package files

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Panel, ktory potrafi zapisac dowolna sciezke, potrafi podmienic /etc/shadow
// i klucze prywatne. Zakaz jest sprawdzany przed allowlista i nie da sie go
// obejsc wpisem administratora.
func TestZakazaneSciezkiSaOdrzucaneMimoAllowlisty(t *testing.T) {
	allowlista := Allowlist{Wzorce: []string{"/etc/*", "/etc/ssh/*", "/root/*"}, Zrodlo: "test"}

	for _, sciezka := range []string{
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/sudoers.d/90-admin",
		"/etc/ssh/ssh_host_ed25519_key",
		"/etc/ssh/sshd_config",
		"/root/.ssh/authorized_keys",
		"/etc/pam.d/sshd",
	} {
		err := allowlista.Dopuszcza(sciezka)
		if !errors.Is(err, ErrZakazana) {
			t.Errorf("sciezka %q: %v", sciezka, err)
		}
	}
}

func TestSciezkaSpozaAllowlistyJestOdrzucana(t *testing.T) {
	allowlista := Allowlist{Wzorce: []string{"/etc/motd", "/opt/flotestro/etc/*"}, Zrodlo: "test"}

	for _, sciezka := range []string{"/etc/hosts", "/var/lib/x", "etc/motd", "/etc/../etc/motd"} {
		if err := allowlista.Dopuszcza(sciezka); err == nil {
			t.Errorf("przyjeto sciezke %q", sciezka)
		}
	}
	for _, sciezka := range []string{"/etc/motd", "/opt/flotestro/etc/app.conf"} {
		if err := allowlista.Dopuszcza(sciezka); err != nil {
			t.Errorf("odrzucono sciezke %q: %v", sciezka, err)
		}
	}
}

// Prawa i wlasciciel sa ustawiane na nowym pliku, zanim zajmie on miejsce
// starego: inaczej zostaje okno, w ktorym plik stoi juz na miejscu z prawami
// domyslnymi.
func TestZapisAtomowyUstawiaPrawaPrzedPodmiana(t *testing.T) {
	katalog := t.TempDir()
	sciezka := filepath.Join(katalog, "app.conf")

	if err := ZapiszAtomowo(sciezka, []byte("a=1\n"), 0o640, -1, -1); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(sciezka)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("prawa = %04o", info.Mode().Perm())
	}
	// Po zapisie nie zostaje plik tymczasowy: katalog konfiguracji zbiera
	// smieci szybciej niz ktokolwiek je zauwazy.
	wpisy, err := os.ReadDir(katalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(wpisy) != 1 {
		t.Errorf("w katalogu zostalo %d plikow", len(wpisy))
	}

	// Zapis bez podanych praw zachowuje prawa istniejacego pliku: zmiana
	// tresci nie jest decyzja o dostepie.
	if err := ZapiszAtomowo(sciezka, []byte("a=2\n"), 0, -1, -1); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(sciezka)
	if info.Mode().Perm() != 0o640 {
		t.Errorf("prawa po zapisie bez trybu = %04o", info.Mode().Perm())
	}
}

func TestPrawaZapisuSaSprawdzane(t *testing.T) {
	for _, tryb := range []string{"777", "666", "4755", "2755", "999", "1234567"} {
		if _, err := WalidujTryb(tryb); err == nil {
			t.Errorf("przyjeto prawa %q", tryb)
		}
	}
	for _, tryb := range []string{"", "644", "600", "0640", "755"} {
		if _, err := WalidujTryb(tryb); err != nil {
			t.Errorf("odrzucono prawa %q: %v", tryb, err)
		}
	}
}

func TestTrescPlikuJestSprawdzana(t *testing.T) {
	if err := WalidujTresc("klucz = wartosc\n"); err != nil {
		t.Errorf("odrzucono poprawna tresc: %v", err)
	}
	if err := WalidujTresc("a\x00b"); err == nil {
		t.Error("przyjeto tresc z bajtem zerowym")
	}
	if err := WalidujTresc(strings.Repeat("a", MaksymalnyRozmiar+1)); err == nil {
		t.Error("przyjeto tresc wieksza niz granica modulu")
	}
}

func TestWalidatorJestDobieranyDoPliku(t *testing.T) {
	walidator, ma, err := WybierzWalidator("/etc/app/config.json", "")
	if err != nil || !ma || walidator.Nazwa != "json" {
		t.Errorf("walidator = %+v, %v, %v", walidator, ma, err)
	}
	if err := walidator.Wbudowany(`{"a": 1}`); err != nil {
		t.Errorf("odrzucono poprawny JSON: %v", err)
	}
	if err := walidator.Wbudowany(`{"a": }`); err == nil {
		t.Error("przyjeto bledny JSON")
	}

	if _, _, err := WybierzWalidator("/etc/motd", "nie-ma-takiego"); err == nil {
		t.Error("przyjeto nieznany walidator")
	}
	// Plik, dla ktorego panel nie zna sprawdzenia, nie dostaje go na sile.
	if _, ma, _ := WybierzWalidator("/etc/motd", ""); ma {
		t.Error("dobrano walidator do pliku tekstowego")
	}

	uklad, _, _ := WybierzWalidator("/etc/systemd/system/app.service", "")
	if uklad.Nazwa != "systemd-unit" || len(uklad.Polecenie) == 0 {
		t.Errorf("walidator jednostki = %+v", uklad)
	}
}

func TestOdciskTresciJestStabilny(t *testing.T) {
	if Odcisk([]byte("a")) != Odcisk([]byte("a")) {
		t.Error("odcisk tej samej tresci sie rozni")
	}
	if Odcisk([]byte("a")) == Odcisk([]byte("b")) {
		t.Error("odcisk roznych tresci jest taki sam")
	}
	if len(Odcisk(nil)) != 64 {
		t.Errorf("odcisk pustej tresci = %q", Odcisk(nil))
	}
}
