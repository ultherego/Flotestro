package relayconfig

import (
	"errors"
	"strings"
	"testing"
)

const poprawny = `
schema_version: 1
relay:
  name: "relay-waw-01"
  site: "warsaw"
  listen: "0.0.0.0:8453"
  advertised_names:
    - "relay-waw-01.example.com"
  state_dir: "/var/lib/flotestro-relay"
  buffer_max_bytes: 268435456
upstream:
  enrollment_url: "https://enroll.flotestro.example.com"
  gateway_urls:
    - "https://gateway-a.flotestro.example.com:8443"
    - "https://gateway-b.flotestro.example.com:8443"
  bootstrap_ca_file: "/etc/flotestro/bootstrap-ca.pem"
`

func TestPoprawnaKonfiguracjaPrzechodzi(t *testing.T) {
	cfg, err := Czytaj(strings.NewReader(poprawny))
	if err != nil {
		t.Fatalf("konfiguracja z dokumentu odrzucona: %v", err)
	}
	if cfg.Relay.Name != "relay-waw-01" || cfg.Relay.Site != "warsaw" {
		t.Fatalf("odczytano %+v", cfg.Relay)
	}
	if len(cfg.Upstream.GatewayURLs) != 2 {
		t.Fatalf("bramy = %v", cfg.Upstream.GatewayURLs)
	}
	if cfg.Bufor() != 268435456 {
		t.Fatalf("bufor = %d", cfg.Bufor())
	}
}

// TestLiterowkaNieJestDrobiazgiem pilnuje wlasciwosci, dla ktorej ten parser
// jest rygorystyczny: relay wstajacy mimo nierozpoznanego pola wyglada na
// skonfigurowanego, a dziala inaczej niz plik mowi.
func TestLiterowkaNieJestDrobiazgiem(t *testing.T) {
	_, err := Czytaj(strings.NewReader(strings.Replace(poprawny,
		"gateway_urls:", "gateway_url:", 1)))
	if !errors.Is(err, ErrDekodowanie) {
		t.Fatalf("literowka w nazwie pola dala %v", err)
	}
}

func TestKonfiguracjaOdrzucaBledy(t *testing.T) {
	przypadki := []struct {
		nazwa string
		zmien func(string) string
		kod   error
	}{
		{"inna wersja schematu", func(s string) string {
			return strings.Replace(s, "schema_version: 1", "schema_version: 2", 1)
		}, ErrSchemat},
		{"brak nazwy", func(s string) string {
			return strings.Replace(s, `  name: "relay-waw-01"`, `  name: ""`, 1)
		}, ErrBrakNazwy},
		{"port uprzywilejowany", func(s string) string {
			return strings.Replace(s, "0.0.0.0:8453", "0.0.0.0:443", 1)
		}, ErrPortUprzywilej},
		{"nasluch bez portu", func(s string) string {
			return strings.Replace(s, `"0.0.0.0:8453"`, `"0.0.0.0"`, 1)
		}, ErrNasluch},
		{"bez nazwy sieciowej", func(s string) string {
			return strings.Replace(s, `    - "relay-waw-01.example.com"`, "", 1)
		}, ErrBrakNazwSieci},
		{"katalog wzgledny", func(s string) string {
			return strings.Replace(s, `"/var/lib/flotestro-relay"`, `"stan"`, 1)
		}, ErrKatalogStanu},
		{"bufor ponad limit", func(s string) string {
			return strings.Replace(s, "buffer_max_bytes: 268435456",
				"buffer_max_bytes: 999999999999", 1)
		}, ErrBufor},
		{"dwie te same bramy", func(s string) string {
			return strings.Replace(s,
				`    - "https://gateway-b.flotestro.example.com:8443"`,
				`    - "https://gateway-a.flotestro.example.com:8443"`, 1)
		}, ErrDuplikatBramy},
	}
	for _, przypadek := range przypadki {
		t.Run(przypadek.nazwa, func(t *testing.T) {
			_, err := Czytaj(strings.NewReader(przypadek.zmien(poprawny)))
			if !errors.Is(err, przypadek.kod) {
				t.Fatalf("blad = %v, oczekiwano %v", err, przypadek.kod)
			}
		})
	}
}

// TestBrakBuforaJestWyborem pilnuje roznicy miedzy "nie wpisano" a "wpisano
// zero": relay bez bufora gubi wyniki na czas awarii lacza i to ma byc
// decyzja operatora, a nie skutek pominiecia wpisu.
func TestBrakBuforaJestWyborem(t *testing.T) {
	bez := strings.Replace(poprawny, "  buffer_max_bytes: 268435456\n", "", 1)
	cfg, err := Czytaj(strings.NewReader(bez))
	if err != nil {
		t.Fatalf("konfiguracja bez bufora odrzucona: %v", err)
	}
	if cfg.Bufor() != BuforDomyslny {
		t.Fatalf("bufor bez wpisu = %d, oczekiwano %d", cfg.Bufor(), BuforDomyslny)
	}

	zero := strings.Replace(poprawny, "buffer_max_bytes: 268435456", "buffer_max_bytes: 0", 1)
	cfg, err = Czytaj(strings.NewReader(zero))
	if err != nil {
		t.Fatalf("jawne zero odrzucone: %v", err)
	}
	if cfg.Bufor() != 0 {
		t.Fatalf("jawne zero dalo bufor %d", cfg.Bufor())
	}
}

func TestDrugiDokumentJestBledem(t *testing.T) {
	_, err := Czytaj(strings.NewReader(poprawny + "\n---\nschema_version: 1\n"))
	if !errors.Is(err, ErrWieleDokumentow) {
		t.Fatalf("drugi dokument dal %v", err)
	}
}
