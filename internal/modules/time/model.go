// Package czas opisuje czas hosta i jego synchronizacje.
//
// Nazwa pakietu rozni sie od katalogu celowo: katalog nazywa modul tak, jak
// nazywa go dokument (internal/modules/time), a pakiet nie moze nazywac sie
// "time", bo przeslonilby biblioteke standardowa w kazdym pliku, ktory go
// uzywa - lacznie z tym.
//
// Czas jest zalozeniem, na ktorym stoi reszta panelu: Kerberos odrzuca bilety
// spoza okna, mTLS odrzuca certyfikaty jeszcze niewazne, a dziennik z hosta
// z przesunietym zegarem uklada sie w zla kolejnosc. Dlatego modul mierzy
// przesuniecie, a nie tylko pokazuje, ze demon czasu dziala.
package czas

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Sciezki narzedzi i konfiguracji.
const (
	SciezkaTimedatectl = "/usr/bin/timedatectl"
	SciezkaChronyc     = "/usr/bin/chronyc"
	KatalogStref       = "/usr/share/zoneinfo"

	// KatalogTimesyncd trzyma ustawienia panelu dla systemd-timesyncd.
	KatalogTimesyncd = "/etc/systemd/timesyncd.conf.d"
	PlikTimesyncd    = KatalogTimesyncd + "/90-flotestro.conf"

	// KatalogZrodelPanelu to katalog, ktory panel zaklada na hoscie, gdzie
	// chrony nie wlacza zadnego wlasnego. Katalog zrodel, a nie konfiguracji:
	// przyjmuje wylacznie serwery, wiec plik panelu nie moze zmienic o
	// chronym niczego innego.
	KatalogZrodelPanelu = "/etc/chrony/sources.d"
	// NaglowekWlaczenia oznacza wiersz dopisany przez panel do glownego pliku.
	NaglowekWlaczenia = "# Dodane przez Flotestro: katalog zrodel czasu zarzadzany przez panel."

	// NaglowekPliku oznacza plik panelu. Bez niego kolejna operacja nie
	// wiedzialaby, ktore serwery ustawil panel, a ktore administrator hosta.
	NaglowekPliku = "# Zarzadzane przez Flotestro. Recznych zmian nie zachowa kolejna operacja."
)

// Nazwy demonow czasu. Nazwa mowi, kto na tym hoscie trzyma zegar.
const (
	DemonChrony    = "chrony"
	DemonTimesyncd = "systemd-timesyncd"
)

// Rodzaje katalogu wlaczanego przez chrony. Roznica nie jest kosmetyczna:
// do katalogu konfiguracji wolno wpisac dowolna dyrektywe i trzeba przeladowac
// demona, a katalog zrodel przyjmuje wylacznie serwery i da sie go przeladowac
// bez zrywania synchronizacji.
const (
	RodzajKonfiguracji = "confdir"
	RodzajZrodel       = "sourcedir"
)

// GlowneKonfiguracjeChrony wylicza miejsca, w ktorych dystrybucje trzymaja
// glowny plik chrony. Panel go nie przepisuje - czyta, zeby dowiedziec sie,
// ktory katalog demon naprawde wlacza.
var GlowneKonfiguracjeChrony = []string{
	"/etc/chrony/chrony.conf",
	"/etc/chrony.conf",
}

// LimitSerwerow ogranicza liczbe serwerow w jednej zmianie. Kilka zrodel daje
// odpornosc na jedno zle; kilkadziesiat nie daje juz nic poza ruchem.
const LimitSerwerow = 8

// ProgSkokuSekund wyznacza przesuniecie, ktore panel traktuje jako skok czasu.
//
// Sekunda jest granica praktyczna, a nie teoretyczna: ponizej niej demony
// czasu koryguja zegar plynnie, a powyzej przestawiaja go skokiem - i wtedy
// bazy danych, tokeny oraz certyfikaty widza czas, ktory sie cofnal.
const ProgSkokuSekund = 1.0

// Zrodlo to jeden serwer czasu widziany przez demona.
type Zrodlo struct {
	Address string `json:"address"`
	// Mode rozroznia serwer, peera i zegar sprzetowy.
	Mode string `json:"mode,omitempty"`
	// State mowi, czy demon uzywa tego zrodla, czy je odrzucil.
	State string `json:"state,omitempty"`
	// Puste pola oznaczaja pomiar, ktorego nie ma - nie zero.
	Stratum       *uint32  `json:"stratum"`
	PollSeconds   *int     `json:"poll_seconds"`
	Reachability  string   `json:"reachability,omitempty"`
	LastRxSeconds *int64   `json:"last_rx_seconds"`
	OffsetSeconds *float64 `json:"offset_seconds"`
	ErrorSeconds  *float64 `json:"error_seconds"`
}

// Serwer to wpis konfiguracyjny, a nie zrodlo dzialajace.
//
// Rozroznienie jest istotne przy diagnozie: serwer wpisany do konfiguracji,
// ktory nie odpowiada, nie pojawi sie na liscie zrodel demona - i bez tej
// listy wygladalby na nieistniejacy zamiast na nieosiagalny.
type Serwer struct {
	Address string `json:"address"`
	// Source nazywa plik, z ktorego wpis pochodzi.
	Source string `json:"source,omitempty"`
	// Pool oznacza wpis rozwijany na wiele adresow.
	Pool bool `json:"pool,omitempty"`
	// Managed oznacza wpis zapisany przez panel.
	Managed bool `json:"managed"`
}

// Pomiar to wynik jednego zapytania SNTP zadanego przez panel.
type Pomiar struct {
	Server string `json:"server"`
	// Address jest adresem, pod ktorym serwer odpowiedzial.
	Address       string   `json:"address,omitempty"`
	Reachable     bool     `json:"reachable"`
	Stratum       *uint32  `json:"stratum"`
	OffsetSeconds *float64 `json:"offset_seconds"`
	DelaySeconds  *float64 `json:"delay_seconds"`
	LeapStatus    string   `json:"leap_status,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// Snapshot to obraz czasu hosta.
type Snapshot struct {
	// Now jest czasem hosta odczytanym w chwili zbierania. Panel porownuje go
	// z wlasnym zegarem, wiec musi pochodzic z hosta, a nie z serwera.
	Now      time.Time `json:"now"`
	Timezone string    `json:"timezone,omitempty"`
	// UTCOffsetSeconds jest przesunieciem strefy, nie bledem zegara.
	UTCOffsetSeconds *int `json:"utc_offset_seconds"`
	// RTCInLocalTime oznacza zegar sprzetowy w czasie lokalnym. Taki host po
	// zmianie czasu letniego wstaje z blednym zegarem.
	RTCInLocalTime *bool `json:"rtc_in_local_time"`
	NTPEnabled     *bool `json:"ntp_enabled"`
	Synchronized   *bool `json:"synchronized"`
	// Service nazywa demona czasu, Unit - jego jednostke systemd.
	Service       string `json:"service,omitempty"`
	Unit          string `json:"unit,omitempty"`
	ServiceActive *bool  `json:"service_active"`

	ReferenceName         string     `json:"reference_name,omitempty"`
	Stratum               *uint32    `json:"stratum"`
	OffsetSeconds         *float64   `json:"offset_seconds"`
	RootDelaySeconds      *float64   `json:"root_delay_seconds"`
	RootDispersionSeconds *float64   `json:"root_dispersion_seconds"`
	FrequencyPPM          *float64   `json:"frequency_ppm"`
	LeapStatus            string     `json:"leap_status,omitempty"`
	LastSyncAt            *time.Time `json:"last_sync_at,omitempty"`

	Sources    []Zrodlo `json:"sources,omitempty"`
	Configured []Serwer `json:"configured_servers,omitempty"`
	Probes     []Pomiar `json:"probes,omitempty"`

	// Managed jest trescia pliku panelu, ManagedPath jego sciezka. Pusta
	// sciezka oznacza host, na ktorym panel nie ma gdzie zapisac zmiany.
	Managed     string `json:"managed_config,omitempty"`
	ManagedPath string `json:"managed_path,omitempty"`
	// WriteReason mowi, dlaczego panel nie zmieni tu konfiguracji czasu.
	WriteReason string `json:"write_reason,omitempty"`
	// ConfigPath jest glownym plikiem demona. Panel go nie przepisuje;
	// pokazuje, zeby operator wiedzial, czego zmiana nie dotyczy.
	ConfigPath string `json:"config_path,omitempty"`
	// CanAddSourceDir mowi, ze host da sie doprowadzic do stanu zapisywalnego
	// jednym dopisanym wierszem - ale dopiero za jawna zgoda operatora.
	CanAddSourceDir bool `json:"can_add_source_dir,omitempty"`

	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// Zsynchronizowany mowi, czy host jest zsynchronizowany. Nieznany stan nie
// jest tu falszem: brak odpowiedzi demona to inna sytuacja niz jego "nie".
func (s Snapshot) Zsynchronizowany() bool {
	return s.Synchronized != nil && *s.Synchronized
}

var nazwaStrefy = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+_-]*(/[A-Za-z0-9+_.-]+){0,2}$`)
var nazwaHosta = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)

// WalidujStrefe sprawdza nazwe strefy czasowej.
//
// Nazwa trafia do polecenia i do sciezki w /usr/share/zoneinfo, wiec nie moze
// byc sciezka wzgledna ani zawierac czegokolwiek poza nazwa strefy.
func WalidujStrefe(strefa string) error {
	if strefa == "" {
		return fmt.Errorf("strefa czasowa jest pusta")
	}
	if len(strefa) > 64 {
		return fmt.Errorf("nazwa strefy jest dluzsza niz 64 znaki")
	}
	if strings.Contains(strefa, "..") {
		return fmt.Errorf("nazwa strefy %q wychodzi poza katalog stref", strefa)
	}
	if !nazwaStrefy.MatchString(strefa) {
		return fmt.Errorf("nieprawidlowa nazwa strefy %q", strefa)
	}
	return nil
}

// SciezkaStrefy zwraca plik strefy w katalogu stref.
func SciezkaStrefy(strefa string) string {
	return KatalogStref + "/" + strefa
}

// WalidujSerwer sprawdza adres serwera czasu.
//
// Adres trafia do pliku konfiguracyjnego jako calosc wiersza, wiec nie moze
// zawierac bialych znakow ani nowej linii: wpis "a\niburst offline" byl by
// juz inna dyrektywa niz ta, ktora operator zatwierdzil.
func WalidujSerwer(adres string) error {
	if adres == "" {
		return fmt.Errorf("adres serwera czasu jest pusty")
	}
	if len(adres) > 253 {
		return fmt.Errorf("adres %q jest dluzszy niz 253 znaki", adres)
	}
	if net.ParseIP(adres) != nil {
		return nil
	}
	if !nazwaHosta.MatchString(adres) {
		return fmt.Errorf("%q nie jest adresem IP ani nazwa hosta", adres)
	}
	return nil
}

// WalidujSerwery sprawdza cala liste serwerow.
func WalidujSerwery(serwery []string) error {
	if len(serwery) == 0 {
		return fmt.Errorf("zmiana nie wskazuje zadnego serwera czasu")
	}
	if len(serwery) > LimitSerwerow {
		return fmt.Errorf("panel przyjmuje najwyzej %d serwerow czasu", LimitSerwerow)
	}
	widziane := map[string]bool{}
	for _, serwer := range serwery {
		if err := WalidujSerwer(serwer); err != nil {
			return err
		}
		if widziane[serwer] {
			return fmt.Errorf("serwer %q powtarza sie na liscie", serwer)
		}
		widziane[serwer] = true
	}
	return nil
}

// SkladajTimesyncd sklada plik ustawien dla systemd-timesyncd.
func SkladajTimesyncd(serwery []string) (string, error) {
	if err := WalidujSerwery(serwery); err != nil {
		return "", err
	}
	return NaglowekPliku + "\n[Time]\nNTP=" + strings.Join(serwery, " ") + "\n", nil
}

// SkladajChrony sklada plik z serwerami dla chrony.
//
// Katalog zrodel przyjmuje wylacznie dyrektywy serwerow, wiec naglowka tam nie
// piszemy: wlascicielem pliku jest wtedy jego nazwa, a nie komentarz.
func SkladajChrony(serwery []string, rodzaj string) (string, error) {
	if err := WalidujSerwery(serwery); err != nil {
		return "", err
	}
	wiersze := make([]string, 0, len(serwery)+1)
	if rodzaj != RodzajZrodel {
		wiersze = append(wiersze, NaglowekPliku)
	}
	for _, serwer := range serwery {
		// iburst skraca pierwsza synchronizacje z kilkunastu minut do kilku
		// sekund; bez niego operator patrzy na "not synchronised" i nie wie,
		// czy zmiana zadzialala.
		wiersze = append(wiersze, "server "+serwer+" iburst")
	}
	return strings.Join(wiersze, "\n") + "\n", nil
}

// WpisWlaczenia sklada wiersze, ktore panel dopisuje do glownego pliku
// chronyego, gdy host nie ma zadnego katalogu wlaczanego.
//
// To jedyne miejsce, w ktorym panel dotyka cudzej konfiguracji, i dotyka jej
// wylacznie dopisaniem: nie zmienia ani nie usuwa niczego, co juz tam jest,
// a dopisany katalog przyjmuje same serwery. Operator musi sie na to zgodzic
// osobno - bez zgody host zostaje tylko do odczytu i mowi dlaczego.
func WpisWlaczenia() string {
	return "\n" + NaglowekWlaczenia + "\nsourcedir " + KatalogZrodelPanelu + "\n"
}

// MaWpisWlaczenia mowi, czy panel dopisal juz swoj katalog.
func MaWpisWlaczenia(konfiguracja string) bool {
	katalog, _ := KatalogDropIn(konfiguracja)
	return katalog == KatalogZrodelPanelu
}

// NazwaPlikuChrony zwraca nazwe pliku panelu w katalogu danego rodzaju.
func NazwaPlikuChrony(rodzaj string) string {
	if rodzaj == RodzajZrodel {
		return "flotestro.sources"
	}
	return "90-flotestro.conf"
}
