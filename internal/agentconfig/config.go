// Package agentconfig czyta konfiguracje agenta z pliku YAML.
//
// Plik jest kanonicznym zrodlem ustawien hosta. Zmienne srodowiskowe i flagi
// zostaja wylacznie jako ograniczony override dla obrazow i testow.
//
// Parser jest rygorystyczny celowo. Literowka w nazwie pola nie moze skonczyc
// sie cichym startem z ustawieniem domyslnym: host wygladalby wtedy na
// skonfigurowanego, a laczylby sie gdzie indziej albo wcale. Kazdy blad ma
// swoj kod, bo to on trafia do diagnostyki na hoscie bez panelu.
//
// Czego w tym pliku nie ma i nie bedzie: tokenu enrollmentu i tozsamosci.
// Token jest sekretem jednorazowym i nie moze lezec w pliku, ktory przezywa
// aktualizacje pakietu; tozsamosc hosta bierze sie z certyfikatu, a nie
// z tekstu, ktory kazdy moze przepisac.
package agentconfig

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// SciezkaDomyslna wskazuje kanoniczny plik konfiguracji.
const SciezkaDomyslna = "/etc/flotestro/agent.yaml"

// WersjaSchematu jest jedyna wersja, ktora ten parser rozumie.
const WersjaSchematu = 1

// MaksymalnyRozmiar ogranicza odczyt pliku konfiguracji.
const MaksymalnyRozmiar = 1 << 20

// Config jest pelna konfiguracja agenta.
type Config struct {
	SchemaVersion int        `yaml:"schema_version"`
	Connection    Connection `yaml:"connection"`
	Agent         Agent      `yaml:"agent"`
	Helper        Helper     `yaml:"helper"`
}

// Connection opisuje, gdzie i jak agent sie laczy.
type Connection struct {
	EnrollmentURL string   `yaml:"enrollment_url"`
	GatewayURLs   []string `yaml:"gateway_urls"`
	BootstrapCA   string   `yaml:"bootstrap_ca_file"`
	// Czasy przychodza jako tekst ("15s"), bo tak sa czytelne w pliku.
	ConnectRaw      string `yaml:"connect_timeout"`
	ReconnectMinRaw string `yaml:"reconnect_min"`
	ReconnectMaxRaw string `yaml:"reconnect_max"`

	ConnectTimeout time.Duration `yaml:"-"`
	ReconnectMin   time.Duration `yaml:"-"`
	ReconnectMax   time.Duration `yaml:"-"`
}

// Agent opisuje zachowanie samego agenta.
type Agent struct {
	StateDir     string `yaml:"state_dir"`
	InventoryRaw string `yaml:"inventory_interval"`
	// MaxRaw jest wskaznikiem, zeby odroznic "nie ma wpisu" od "wpisano
	// zero". Brak wpisu bierze wartosc domyslna, a jawne zero jest bledem:
	// agent, ktory nie wykona zadnego zadania, nie jest agentem.
	MaxRaw *int `yaml:"max_concurrent_tasks"`
	// Mode "read_only" nie uruchamia helpera: host jest wtedy obserwowany,
	// a nie zarzadzany.
	Mode string `yaml:"mode"`

	MaxConcurrentTasks int           `yaml:"-"`
	InventoryInterval  time.Duration `yaml:"-"`
}

// Helper opisuje polaczenie z czescia uprzywilejowana.
type Helper struct {
	Socket string `yaml:"socket"`
}

// Tryby pracy agenta.
const (
	TrybPelny   = "full"
	TrybOdczytu = "read_only"
)

// Kody bledow konfiguracji. Sa czescia kontraktu z operatorem: to one
// pokazuja sie na hoscie, ktory nie ma jeszcze polaczenia z panelem.
var (
	ErrOtwarcie          = errors.New("config_open")
	ErrDekodowanie       = errors.New("config_decode")
	ErrWieleDokumentow   = errors.New("config_multiple_documents")
	ErrSchemat           = errors.New("config_schema_unsupported")
	ErrBrakBramy         = errors.New("config_gateway_missing")
	ErrDuplikatBramy     = errors.New("config_gateway_duplicate")
	ErrLimitZadan        = errors.New("config_task_limit_out_of_range")
	ErrTryb              = errors.New("config_mode_invalid")
	ErrKatalogStanu      = errors.New("config_state_dir_invalid")
	ErrGniazdoHelpera    = errors.New("config_helper_socket_invalid")
	ErrCzasPolaczenia    = errors.New("config_connect_timeout_out_of_range")
	ErrCzasyPonowien     = errors.New("config_reconnect_out_of_range")
	ErrKolejnoscPonowien = errors.New("config_reconnect_order")
	ErrBootstrapCA       = errors.New("bootstrap_ca_unsafe")
)

// Domyslne zwraca ustawienia, ktore obowiazuja bez wpisu w pliku.
func Domyslne() Config {
	return Config{
		SchemaVersion: WersjaSchematu,
		Connection: Connection{
			ConnectTimeout: 15 * time.Second,
			ReconnectMin:   2 * time.Second,
			ReconnectMax:   2 * time.Minute,
		},
		Agent: Agent{
			StateDir:           "/var/lib/flotestro-agent",
			InventoryInterval:  15 * time.Minute,
			MaxConcurrentTasks: 2,
			Mode:               TrybPelny,
		},
		Helper: Helper{Socket: "/run/flotestro/helper.sock"},
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
	// Nieznane pole jest bledem, a nie drobiazgiem: "gateway_url" zamiast
	// "gateway_urls" zostawiloby agenta bez adresu i bez slowa.
	dekoder.KnownFields(true)

	var cfg Config
	if err := dekoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrDekodowanie, err)
	}
	// Drugi dokument w pliku znaczy, ze ktos dopisal konfiguracje po "---"
	// i jest przekonany, ze dziala. Nie dziala - i musi to zobaczyc.
	var nadmiar any
	if err := dekoder.Decode(&nadmiar); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, ErrWieleDokumentow
		}
		return Config{}, fmt.Errorf("%w: %v", ErrDekodowanie, err)
	}

	uzupelnij(&cfg)
	if err := czasy(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Sprawdz(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// uzupelnij wstawia wartosci domyslne tam, gdzie plik milczy.
func uzupelnij(cfg *Config) {
	domyslne := Domyslne()
	if cfg.Agent.StateDir == "" {
		cfg.Agent.StateDir = domyslne.Agent.StateDir
	}
	if cfg.Agent.MaxRaw == nil {
		cfg.Agent.MaxConcurrentTasks = domyslne.Agent.MaxConcurrentTasks
	} else {
		cfg.Agent.MaxConcurrentTasks = *cfg.Agent.MaxRaw
	}
	if cfg.Agent.Mode == "" {
		cfg.Agent.Mode = domyslne.Agent.Mode
	}
	if cfg.Helper.Socket == "" {
		cfg.Helper.Socket = domyslne.Helper.Socket
	}
}

// czasy zamienia zapisy tekstowe na czasy i pilnuje ich zakresow.
func czasy(cfg *Config) error {
	domyslne := Domyslne()
	var err error
	if cfg.Connection.ConnectTimeout, err = czas(cfg.Connection.ConnectRaw,
		domyslne.Connection.ConnectTimeout); err != nil {
		return err
	}
	if cfg.Connection.ReconnectMin, err = czas(cfg.Connection.ReconnectMinRaw,
		domyslne.Connection.ReconnectMin); err != nil {
		return err
	}
	if cfg.Connection.ReconnectMax, err = czas(cfg.Connection.ReconnectMaxRaw,
		domyslne.Connection.ReconnectMax); err != nil {
		return err
	}
	if cfg.Agent.InventoryInterval, err = czas(cfg.Agent.InventoryRaw,
		domyslne.Agent.InventoryInterval); err != nil {
		return err
	}
	return nil
}

func czas(zapis string, domyslny time.Duration) (time.Duration, error) {
	if zapis == "" {
		return domyslny, nil
	}
	wartosc, err := time.ParseDuration(zapis)
	if err != nil {
		return 0, fmt.Errorf("%w: %q nie jest czasem", ErrDekodowanie, zapis)
	}
	return wartosc, nil
}

// Sprawdz pilnuje kontraktu pliku konfiguracji.
func Sprawdz(cfg Config) error { return cfg.Sprawdz() }

// Sprawdz pilnuje kontraktu pliku konfiguracji.
func (c Config) Sprawdz() error {
	if c.SchemaVersion != WersjaSchematu {
		return fmt.Errorf("%w: %d", ErrSchemat, c.SchemaVersion)
	}
	if err := adresHTTPS("enrollment", c.Connection.EnrollmentURL); err != nil {
		return err
	}
	if len(c.Connection.GatewayURLs) == 0 {
		return ErrBrakBramy
	}
	widziane := map[string]bool{}
	for _, adres := range c.Connection.GatewayURLs {
		if err := adresHTTPS("gateway", adres); err != nil {
			return err
		}
		if widziane[adres] {
			return fmt.Errorf("%w: %s", ErrDuplikatBramy, adres)
		}
		widziane[adres] = true
	}
	if !filepath.IsAbs(c.Agent.StateDir) {
		return fmt.Errorf("%w: %s", ErrKatalogStanu, c.Agent.StateDir)
	}
	if !filepath.IsAbs(c.Helper.Socket) {
		return fmt.Errorf("%w: %s", ErrGniazdoHelpera, c.Helper.Socket)
	}
	if c.Agent.MaxConcurrentTasks < 1 || c.Agent.MaxConcurrentTasks > 16 {
		return fmt.Errorf("%w: %d", ErrLimitZadan, c.Agent.MaxConcurrentTasks)
	}
	if c.Agent.Mode != TrybPelny && c.Agent.Mode != TrybOdczytu {
		return fmt.Errorf("%w: %s", ErrTryb, c.Agent.Mode)
	}
	if c.Connection.ConnectTimeout < time.Second || c.Connection.ConnectTimeout > 2*time.Minute {
		return fmt.Errorf("%w: %s", ErrCzasPolaczenia, c.Connection.ConnectTimeout)
	}
	if err := zakresPonowien(c.Connection.ReconnectMin); err != nil {
		return err
	}
	if err := zakresPonowien(c.Connection.ReconnectMax); err != nil {
		return err
	}
	if c.Connection.ReconnectMin > c.Connection.ReconnectMax {
		return fmt.Errorf("%w: %s > %s", ErrKolejnoscPonowien,
			c.Connection.ReconnectMin, c.Connection.ReconnectMax)
	}
	if c.Agent.InventoryInterval < 5*time.Minute || c.Agent.InventoryInterval > 24*time.Hour {
		return fmt.Errorf("%w: %s", ErrDekodowanie, c.Agent.InventoryInterval)
	}
	return nil
}

func zakresPonowien(wartosc time.Duration) error {
	if wartosc < time.Second || wartosc > 15*time.Minute {
		return fmt.Errorf("%w: %s", ErrCzasyPonowien, wartosc)
	}
	return nil
}

// adresHTTPS pilnuje, ze adres jest tym, na co wyglada.
//
// Bez HTTPS caly bootstrap zaufania jest pozorny, a userinfo, query
// i fragment w adresie panelu nie znacza nic poza tym, ze ktos wkleil nie to,
// co chcial - albo probuje przemycic poswiadczenia do logow.
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

// SprawdzBootstrapCA pilnuje, ze wskazany bundle CA jest zwyklym plikiem.
//
// Osobno od reszty walidacji, bo dotyka systemu plikow: parser konfiguracji
// ma dzialac takze wtedy, gdy sprawdzamy plik z innej maszyny. Symlink
// prowadzacy do katalogu zapisywalnego przez kogokolwiek jest tu grozny:
// podmiana bundla CA to podmiana calego zaufania hosta.
func (c Config) SprawdzBootstrapCA() error {
	if c.Connection.BootstrapCA == "" {
		return nil
	}
	sciezka := c.Connection.BootstrapCA
	if !filepath.IsAbs(sciezka) {
		return fmt.Errorf("%w: %s nie jest sciezka bezwzgledna", ErrBootstrapCA, sciezka)
	}
	info, err := os.Lstat(sciezka)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBootstrapCA, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s jest dowiazaniem", ErrBootstrapCA, sciezka)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s nie jest zwyklym plikiem", ErrBootstrapCA, sciezka)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s jest zapisywalny dla grupy albo innych", ErrBootstrapCA, sciezka)
	}
	return nil
}
