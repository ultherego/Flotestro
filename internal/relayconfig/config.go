// Package relayconfig czyta konfiguracje relaya z pliku YAML.
//
// Relay jest osobna granica zaufania i ma osobny plik. Wspolny plik z agentem
// wygladalby oszczedniej, a znaczylby, ze jedno ustawienie opisuje dwie role
// o roznych uprawnieniach - i ze pomylka w jednej z nich dotyka drugiej.
//
// Parser jest rygorystyczny tak samo jak parser agenta: literowka w nazwie
// pola nie moze skonczyc sie cichym startem z ustawieniem domyslnym.
// Relay, ktory nasluchuje na innym porcie niz mysli operator, jest gorszy niz
// relay, ktory nie wstal.
//
// Czego w tym pliku nie ma: tokenu enrollmentu i tozsamosci. Token jest
// sekretem jednorazowym i nie moze przezyc aktualizacji pakietu; tozsamosc
// relaya bierze sie z certyfikatu, a nie z tekstu w pliku.
package relayconfig

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SciezkaDomyslna wskazuje kanoniczny plik konfiguracji relaya.
const SciezkaDomyslna = "/etc/flotestro/relay.yaml"

// WersjaSchematu jest jedyna wersja, ktora ten parser rozumie.
const WersjaSchematu = 1

// MaksymalnyRozmiar ogranicza odczyt pliku konfiguracji.
const MaksymalnyRozmiar = 1 << 20

// Config jest pelna konfiguracja relaya.
type Config struct {
	SchemaVersion int      `yaml:"schema_version"`
	Relay         Relay    `yaml:"relay"`
	Upstream      Upstream `yaml:"upstream"`
}

// Relay opisuje sam wezel lokalizacji.
type Relay struct {
	Name string `yaml:"name"`
	// Site jest wartoscia oczekiwana, a nie nadana: zakres relaya nadaje
	// token enrollmentu i to on rozstrzyga. Rozjazd miedzy plikiem
	// a certyfikatem jest bledem konfiguracji i ma byc widoczny.
	Site            string   `yaml:"site"`
	Listen          string   `yaml:"listen"`
	AdvertisedNames []string `yaml:"advertised_names"`
	StateDir        string   `yaml:"state_dir"`
	// BufferMaxBytes jest wskaznikiem, zeby odroznic brak wpisu od jawnego
	// zera. Zero znaczy "nie buforuj nic" i jest wyborem, a nie brakiem:
	// relay bez bufora gubi kazdy wynik na czas awarii lacza.
	BufferMaxBytes *int64 `yaml:"buffer_max_bytes"`
}

// Upstream opisuje droge relaya do centrali.
type Upstream struct {
	EnrollmentURL string   `yaml:"enrollment_url"`
	GatewayURLs   []string `yaml:"gateway_urls"`
	BootstrapCA   string   `yaml:"bootstrap_ca_file"`
}

// Kody bledow konfiguracji relaya. Tak samo jak u agenta sa czescia kontraktu
// z operatorem: to one pokazuja sie na maszynie bez polaczenia z panelem.
var (
	ErrOtwarcie        = errors.New("relay_config_open")
	ErrDekodowanie     = errors.New("relay_config_decode")
	ErrWieleDokumentow = errors.New("relay_config_multiple_documents")
	ErrSchemat         = errors.New("relay_config_schema_unsupported")
	ErrBrakNazwy       = errors.New("relay_config_name_missing")
	ErrNasluch         = errors.New("relay_config_listen_invalid")
	ErrPortUprzywilej  = errors.New("relay_config_listen_privileged")
	ErrBrakNazwSieci   = errors.New("relay_config_advertised_missing")
	ErrNazwaSieci      = errors.New("relay_config_advertised_invalid")
	ErrKatalogStanu    = errors.New("relay_config_state_dir_invalid")
	ErrBrakBramy       = errors.New("relay_config_gateway_missing")
	ErrDuplikatBramy   = errors.New("relay_config_gateway_duplicate")
	ErrBufor           = errors.New("relay_config_buffer_out_of_range")
)

// Granice bufora. Dol jest zerem swiadomie: relay bez bufora tez jest
// wyborem. Gora chroni maszyne lokalizacji - bufor rosnacy bez konca
// zamienia awarie lacza w awarie relaya.
const (
	BuforDomyslny   int64 = 256 << 20
	BuforMaksymalny int64 = 4 << 30
)

// Domyslne zwraca ustawienia, ktore obowiazuja bez wpisu w pliku.
func Domyslne() Config {
	bufor := BuforDomyslny
	return Config{
		SchemaVersion: WersjaSchematu,
		Relay: Relay{
			Listen:         "0.0.0.0:8453",
			StateDir:       "/var/lib/flotestro-relay",
			BufferMaxBytes: &bufor,
		},
	}
}

// Wczytaj czyta i sprawdza konfiguracje z pliku.
func Wczytaj(sciezka string) (Config, error) {
	plik, err := os.Open(filepath.Clean(sciezka))
	if err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrOtwarcie, err)
	}
	defer plik.Close()
	return Czytaj(plik)
}

// Czytaj czyta konfiguracje ze strumienia.
func Czytaj(zrodlo io.Reader) (Config, error) {
	dekoder := yaml.NewDecoder(io.LimitReader(zrodlo, MaksymalnyRozmiar))
	dekoder.KnownFields(true)

	var cfg Config
	if err := dekoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrDekodowanie, err)
	}
	var nadmiar any
	if err := dekoder.Decode(&nadmiar); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, ErrWieleDokumentow
		}
		return Config{}, fmt.Errorf("%w: %v", ErrDekodowanie, err)
	}

	uzupelnij(&cfg)
	if err := cfg.Sprawdz(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// uzupelnij wstawia wartosci domyslne tam, gdzie plik milczy.
func uzupelnij(cfg *Config) {
	domyslne := Domyslne()
	if cfg.Relay.Listen == "" {
		cfg.Relay.Listen = domyslne.Relay.Listen
	}
	if cfg.Relay.StateDir == "" {
		cfg.Relay.StateDir = domyslne.Relay.StateDir
	}
	if cfg.Relay.BufferMaxBytes == nil {
		bufor := BuforDomyslny
		cfg.Relay.BufferMaxBytes = &bufor
	}
}

// Bufor zwraca limit bufora wynikow.
func (c Config) Bufor() int64 {
	if c.Relay.BufferMaxBytes == nil {
		return BuforDomyslny
	}
	return *c.Relay.BufferMaxBytes
}

// Sprawdz pilnuje kontraktu pliku konfiguracji relaya.
func (c Config) Sprawdz() error {
	if c.SchemaVersion != WersjaSchematu {
		return fmt.Errorf("%w: %d", ErrSchemat, c.SchemaVersion)
	}
	if strings.TrimSpace(c.Relay.Name) == "" {
		return ErrBrakNazwy
	}
	if err := nasluch(c.Relay.Listen); err != nil {
		return err
	}
	// Bez nazwy, pod ktora relay jest widoczny, jego certyfikat serwerowy nie
	// ma czego poswiadczyc i agenci odrzuca polaczenie na nieznana nazwe.
	// Lepiej powiedziec to przy starcie niz kazdym agentem z osobna.
	if len(c.Relay.AdvertisedNames) == 0 {
		return ErrBrakNazwSieci
	}
	widziane := map[string]bool{}
	for _, nazwa := range c.Relay.AdvertisedNames {
		if err := nazwaSieci(nazwa); err != nil {
			return err
		}
		if widziane[nazwa] {
			return fmt.Errorf("%w: %s podana dwa razy", ErrNazwaSieci, nazwa)
		}
		widziane[nazwa] = true
	}
	if !filepath.IsAbs(c.Relay.StateDir) {
		return fmt.Errorf("%w: %s", ErrKatalogStanu, c.Relay.StateDir)
	}
	if err := adresHTTPS("enrollment", c.Upstream.EnrollmentURL); err != nil {
		return err
	}
	if len(c.Upstream.GatewayURLs) == 0 {
		return ErrBrakBramy
	}
	bramy := map[string]bool{}
	for _, adres := range c.Upstream.GatewayURLs {
		if err := adresHTTPS("gateway", adres); err != nil {
			return err
		}
		if bramy[adres] {
			return fmt.Errorf("%w: %s", ErrDuplikatBramy, adres)
		}
		bramy[adres] = true
	}
	if bufor := c.Bufor(); bufor < 0 || bufor > BuforMaksymalny {
		return fmt.Errorf("%w: %d", ErrBufor, bufor)
	}
	return nil
}

// nasluch pilnuje, ze adres nasluchu jest adresem, a port nie wymaga roota.
//
// Relay dziala bez uprawnien roota i ma tak zostac: proces terminujacy TLS
// calej lokalizacji nie jest miejscem na dodatkowe uprawnienia.
func nasluch(adres string) error {
	host, port, err := net.SplitHostPort(adres)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNasluch, adres)
	}
	if host != "" && net.ParseIP(host) == nil {
		return fmt.Errorf("%w: %s nie jest adresem IP", ErrNasluch, host)
	}
	numer, err := net.LookupPort("tcp", port)
	if err != nil || numer == 0 {
		return fmt.Errorf("%w: %s", ErrNasluch, adres)
	}
	if numer < 1024 {
		return fmt.Errorf("%w: %d", ErrPortUprzywilej, numer)
	}
	return nil
}

// nazwaSieci przyjmuje nazwe DNS albo adres IP.
func nazwaSieci(nazwa string) error {
	if nazwa == "" {
		return fmt.Errorf("%w: pusta nazwa", ErrNazwaSieci)
	}
	if net.ParseIP(nazwa) != nil {
		return nil
	}
	if strings.ContainsAny(nazwa, " \t/:") || strings.HasPrefix(nazwa, ".") ||
		strings.HasSuffix(nazwa, ".") {
		return fmt.Errorf("%w: %s", ErrNazwaSieci, nazwa)
	}
	for _, etykieta := range strings.Split(nazwa, ".") {
		if etykieta == "" || len(etykieta) > 63 {
			return fmt.Errorf("%w: %s", ErrNazwaSieci, nazwa)
		}
	}
	return nil
}

// adresHTTPS pilnuje, ze adres centrali jest tym, na co wyglada.
func adresHTTPS(nazwa, surowy string) error {
	adres, err := url.Parse(surowy)
	if err != nil || adres.Scheme != "https" || adres.Host == "" {
		return fmt.Errorf("%s_invalid_url: %s", nazwa, surowy)
	}
	if adres.User != nil || adres.RawQuery != "" || adres.Fragment != "" {
		return fmt.Errorf("%s_forbidden_url_parts: %s", nazwa, surowy)
	}
	return nil
}
