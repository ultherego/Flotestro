package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dobraKonfiguracja = `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  state_dir: "/var/lib/flotestro-agent"
`

func plikKonfiguracji(t *testing.T, tresc string, prawa os.FileMode) string {
	t.Helper()
	sciezka := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(sciezka, []byte(tresc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sciezka, prawa); err != nil {
		t.Fatal(err)
	}
	return sciezka
}

func TestKodyWyjscia(t *testing.T) {
	przypadki := []struct {
		nazwa     string
		argumenty []string
		kod       int
	}{
		{"bez polecenia", nil, 2},
		{"nieznane polecenie", []string{"polec"}, 2},
		{"wersja", []string{"version"}, 0},
		{"pomoc", []string{"help"}, 0},
		{"config bez podpolecenia", []string{"config"}, 2},
		{"config z nieznanym podpoleceniem", []string{"config", "napraw"}, 2},
	}
	for _, przypadek := range przypadki {
		t.Run(przypadek.nazwa, func(t *testing.T) {
			var wyjscie, bledy bytes.Buffer
			if kod := uruchom(przypadek.argumenty, &wyjscie, &bledy); kod != przypadek.kod {
				t.Fatalf("kod = %d, chcemy %d (%s%s)", kod, przypadek.kod,
					wyjscie.String(), bledy.String())
			}
		})
	}
}

func TestConfigValidatePrzepuszczaPoprawnyPlik(t *testing.T) {
	sciezka := plikKonfiguracji(t, dobraKonfiguracja, 0o640)
	var wyjscie, bledy bytes.Buffer
	if kod := uruchom([]string{"config", "validate", "--config", sciezka}, &wyjscie, &bledy); kod != 0 {
		t.Fatalf("kod = %d, bledy: %s", kod, bledy.String())
	}
	if !strings.Contains(wyjscie.String(), "poprawny") {
		t.Fatalf("wyjscie = %q", wyjscie.String())
	}
}

func TestConfigValidateZglaszaBlad(t *testing.T) {
	zly := plikKonfiguracji(t, "schema_version: 2\n", 0o640)
	var wyjscie, bledy bytes.Buffer
	if kod := uruchom([]string{"config", "validate", "--config", zly}, &wyjscie, &bledy); kod != 1 {
		t.Fatalf("kod = %d", kod)
	}
	// Kod bledu jest czescia kontraktu: to on trafia do zgloszenia z hosta,
	// ktory nie rozmawia jeszcze z panelem.
	if !strings.Contains(bledy.String(), "config_schema_unsupported") {
		t.Fatalf("bledy = %q", bledy.String())
	}
}

func TestConfigValidatePilnujePrawDoPliku(t *testing.T) {
	// Prawo zapisu do konfiguracji jest prawem przekierowania hosta na cudzy
	// panel: plik poprawny skladniowo, ale otwarty dla wszystkich, nie moze
	// przejsc jako poprawny.
	otwarty := plikKonfiguracji(t, dobraKonfiguracja, 0o666)
	var wyjscie, bledy bytes.Buffer
	if kod := uruchom([]string{"config", "validate", "--config", otwarty}, &wyjscie, &bledy); kod != 1 {
		t.Fatalf("kod = %d, wyjscie: %s", kod, wyjscie.String())
	}
	if !strings.Contains(bledy.String(), "zapisywalny") {
		t.Fatalf("bledy = %q", bledy.String())
	}
}

func TestConfigShowNiePokazujeSekretow(t *testing.T) {
	sciezka := plikKonfiguracji(t, dobraKonfiguracja, 0o640)
	var wyjscie, bledy bytes.Buffer
	if kod := uruchom([]string{"config", "show", "--config", sciezka}, &wyjscie, &bledy); kod != 0 {
		t.Fatalf("kod = %d, bledy: %s", kod, bledy.String())
	}
	tresc := wyjscie.String()
	for _, zakazane := range []string{"token", "TOKEN", "secret", "password"} {
		if strings.Contains(tresc, zakazane) {
			t.Fatalf("wyjscie niesie %q: %s", zakazane, tresc)
		}
	}
	if !strings.Contains(tresc, "https://gw.example.com:8443") {
		t.Fatalf("wyjscie bez adresu bramy: %s", tresc)
	}
}

func TestStatusMowiOBrakuTozsamosci(t *testing.T) {
	katalog := t.TempDir()
	sciezka := filepath.Join(katalog, "agent.yaml")
	tresc := strings.Replace(dobraKonfiguracja, `  state_dir: "/var/lib/flotestro-agent"`,
		`  state_dir: "`+katalog+`"`, 1)
	if err := os.WriteFile(sciezka, []byte(tresc), 0o640); err != nil {
		t.Fatal(err)
	}
	var wyjscie, bledy bytes.Buffer
	// Host bez tozsamosci to problem do naprawy, a nie blad uzycia.
	if kod := uruchom([]string{"status", "--config", sciezka}, &wyjscie, &bledy); kod != 1 {
		t.Fatalf("kod = %d, wyjscie: %s", kod, wyjscie.String())
	}
	if !strings.Contains(wyjscie.String(), "Identity:     brak") {
		t.Fatalf("wyjscie = %q", wyjscie.String())
	}
}

func TestEnrollOdmawiaGdyTozsamoscJestWazna(t *testing.T) {
	// Rejestracja hosta, ktory juz jest we flocie, byla by cicha wymiana
	// tozsamosci. To jest osobna decyzja i idzie przez zamowienie w panelu.
	katalog := t.TempDir()
	sciezka := filepath.Join(katalog, "agent.yaml")
	tresc := strings.Replace(dobraKonfiguracja, `  state_dir: "/var/lib/flotestro-agent"`,
		`  state_dir: "`+katalog+`"`, 1)
	if err := os.WriteFile(sciezka, []byte(tresc), 0o640); err != nil {
		t.Fatal(err)
	}
	// Bez tozsamosci polecenie ma pytac o token, a nie odmawiac - wiec
	// podajemy pusty, zeby sprawdzic sama sciezke bledu.
	var wyjscie, bledy bytes.Buffer
	kod := uruchomZWejsciem([]string{"enroll", "--config", sciezka},
		strings.NewReader(""), &wyjscie, &bledy)
	if kod != 1 {
		t.Fatalf("kod = %d, wyjscie: %s %s", kod, wyjscie.String(), bledy.String())
	}
	if !strings.Contains(bledy.String(), "token enrollmentu jest pusty") {
		t.Fatalf("bledy = %q", bledy.String())
	}
}

func TestEnrollNiePrzyjmujeTokenuWArgumencie(t *testing.T) {
	// Argument wiersza polecenia widzi kazdy uzytkownik hosta w liscie
	// procesow, wiec takiej flagi nie ma i nie moze byc.
	var wyjscie, bledy bytes.Buffer
	kod := uruchomZWejsciem([]string{"enroll", "--token", "flt_cokolwiek"},
		strings.NewReader(""), &wyjscie, &bledy)
	if kod != 2 {
		t.Fatalf("kod = %d - flaga z tokenem zostala przyjeta", kod)
	}
}
