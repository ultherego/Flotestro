package agentconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const przykladPelny = `
schema_version: 1

connection:
  enrollment_url: "https://enroll.flotestro.example.com"
  gateway_urls:
    - "https://relay-waw-01.example.com:8453"
    - "https://relay-waw-02.example.com:8453"
  connect_timeout: "15s"
  reconnect_min: "2s"
  reconnect_max: "2m"

agent:
  state_dir: "/var/lib/flotestro-agent"
  inventory_interval: "15m"
  max_concurrent_tasks: 2
  mode: "full"

helper:
  socket: "/run/flotestro/helper.sock"
`

func TestPelnyPlikPrzechodzi(t *testing.T) {
	cfg, err := Czytaj(strings.NewReader(przykladPelny))
	if err != nil {
		t.Fatalf("konfiguracja odrzucona: %v", err)
	}
	if len(cfg.Connection.GatewayURLs) != 2 {
		t.Fatalf("bram = %v", cfg.Connection.GatewayURLs)
	}
	if cfg.Connection.ConnectTimeout != 15*time.Second ||
		cfg.Connection.ReconnectMax != 2*time.Minute {
		t.Fatalf("czasy = %s / %s", cfg.Connection.ConnectTimeout, cfg.Connection.ReconnectMax)
	}
	if cfg.Agent.InventoryInterval != 15*time.Minute {
		t.Fatalf("odstep inwentarza = %s", cfg.Agent.InventoryInterval)
	}
}

func TestBrakujacePolaBioraDomyslne(t *testing.T) {
	minimalny := `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
`
	cfg, err := Czytaj(strings.NewReader(minimalny))
	if err != nil {
		t.Fatalf("konfiguracja odrzucona: %v", err)
	}
	domyslne := Domyslne()
	if cfg.Agent.StateDir != domyslne.Agent.StateDir ||
		cfg.Agent.MaxConcurrentTasks != domyslne.Agent.MaxConcurrentTasks ||
		cfg.Agent.Mode != domyslne.Agent.Mode ||
		cfg.Helper.Socket != domyslne.Helper.Socket ||
		cfg.Agent.InventoryInterval != domyslne.Agent.InventoryInterval {
		t.Fatalf("domyslne nie uzupelnione: %+v", cfg)
	}
}

// TestPlikOdrzucaBledy przechodzi przez przypadki z dokumentu. Kazdy z nich
// kiedys konczyl sie cichym startem z innym ustawieniem, niz operator
// zapisal - a to jest gorsze niz host, ktory nie wstaje.
func TestPlikOdrzucaBledy(t *testing.T) {
	przypadki := []struct {
		nazwa   string
		plik    string
		oczekuj error
	}{
		{"nieznane pole", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_url: "https://gw.example.com:8443"
`, ErrDekodowanie},
		{"http zamiast https", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["http://gw.example.com:8443"]
`, nil},
		{"poswiadczenia w adresie", `
schema_version: 1
connection:
  enrollment_url: "https://uzytkownik:haslo@enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
`, nil},
		{"drugi dokument", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
---
schema_version: 1
`, ErrWieleDokumentow},
		{"limit zadan zero", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  max_concurrent_tasks: 0
`, ErrLimitZadan},
		{"limit zadan tysiac", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  max_concurrent_tasks: 1000
`, ErrLimitZadan},
		{"duplikat bramy", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443", "https://gw.example.com:8443"]
`, ErrDuplikatBramy},
		{"nieznany schemat", `
schema_version: 2
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
`, ErrSchemat},
		{"brak bramy", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
`, ErrBrakBramy},
		{"nieznany tryb", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  mode: "polowicznie"
`, ErrTryb},
		{"odstep inwentarza minuta", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  inventory_interval: "1m"
`, nil},
		{"ponowienia odwrotnie", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
  reconnect_min: "5m"
  reconnect_max: "10s"
`, ErrKolejnoscPonowien},
		{"katalog stanu wzgledny", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  state_dir: "stan"
`, ErrKatalogStanu},
	}

	for _, przypadek := range przypadki {
		t.Run(przypadek.nazwa, func(t *testing.T) {
			_, err := Czytaj(strings.NewReader(przypadek.plik))
			if err == nil {
				t.Fatal("plik przeszedl, choc nie powinien")
			}
			if przypadek.oczekuj != nil && !errors.Is(err, przypadek.oczekuj) {
				t.Fatalf("blad = %v, chcemy %v", err, przypadek.oczekuj)
			}
		})
	}

	// Brak wpisu to co innego niz jawne zero: pierwsze bierze wartosc
	// domyslna, drugie jest bledem.
	cfg, err := Czytaj(strings.NewReader(`
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
`))
	if err != nil {
		t.Fatalf("plik bez limitu odrzucony: %v", err)
	}
	if cfg.Agent.MaxConcurrentTasks != Domyslne().Agent.MaxConcurrentTasks {
		t.Fatalf("limit zadan po uzupelnieniu = %d", cfg.Agent.MaxConcurrentTasks)
	}
}

func TestBootstrapCAMusiBycZwyklymPlikiem(t *testing.T) {
	katalog := t.TempDir()
	plik := filepath.Join(katalog, "ca.pem")
	if err := os.WriteFile(plik, []byte("-----BEGIN CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Domyslne()
	cfg.Connection.BootstrapCA = plik
	if err := cfg.SprawdzBootstrapCA(); err != nil {
		t.Fatalf("zwykly plik odrzucony: %v", err)
	}

	// Dowiazanie moze wskazywac katalog zapisywalny przez kogos innego,
	// a podmiana bundla CA to podmiana calego zaufania hosta.
	dowiazanie := filepath.Join(katalog, "ca-link.pem")
	if err := os.Symlink(plik, dowiazanie); err != nil {
		t.Fatal(err)
	}
	cfg.Connection.BootstrapCA = dowiazanie
	if err := cfg.SprawdzBootstrapCA(); !errors.Is(err, ErrBootstrapCA) {
		t.Fatalf("dowiazanie przeszlo: %v", err)
	}

	zapisywalny := filepath.Join(katalog, "ca-otwarty.pem")
	if err := os.WriteFile(zapisywalny, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Prawa ustawiamy po zapisie: umask procesu i tak przycialby tryb
	// podany przy tworzeniu, a test ma sprawdzic plik naprawde otwarty.
	if err := os.Chmod(zapisywalny, 0o666); err != nil {
		t.Fatal(err)
	}
	cfg.Connection.BootstrapCA = zapisywalny
	if err := cfg.SprawdzBootstrapCA(); !errors.Is(err, ErrBootstrapCA) {
		t.Fatalf("plik zapisywalny dla wszystkich przeszedl: %v", err)
	}
}

func TestWczytajZPliku(t *testing.T) {
	katalog := t.TempDir()
	sciezka := filepath.Join(katalog, "agent.yaml")
	if err := os.WriteFile(sciezka, []byte(przykladPelny), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Wczytaj(sciezka); err != nil {
		t.Fatalf("plik odrzucony: %v", err)
	}
	if _, err := Wczytaj(filepath.Join(katalog, "nie-ma.yaml")); !errors.Is(err, ErrOtwarcie) {
		t.Fatalf("brak pliku = %v", err)
	}
}
