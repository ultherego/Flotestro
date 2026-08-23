// Package dns opisuje resolver hosta.
//
// Modul dotyczy wylacznie tego, jak host rozwiazuje nazwy. Rekordy w katalogu
// to osobny zakres i osobne uprawnienia: wpis w strefie FreeIPA widza wszyscy
// klienci domeny, a resolver hosta - tylko ten host.
package dns

import "time"

// Wlasciciele pliku resolv.conf. Wlasciciel rozstrzyga, czy panel w ogole
// moze cos zmienic: plik zarzadzany przez usluge zostanie i tak nadpisany,
// wiec zapis w nim byloby zmiana, ktora znika przy nastepnym zdarzeniu sieci.
const (
	WlascicielResolved = "systemd-resolved"
	WlascicielNM       = "networkmanager"
	WlascicielDHCP     = "dhcp-client"
	WlascicielReczny   = "manual"
	WlascicielNieznany = ""
)

// Tryby pracy resolvera.
const (
	TrybStub    = "stub"
	TrybStatic  = "static"
	TrybUplink  = "uplink"
	TrybPlikowy = "file"
)

// Link opisuje resolver przypisany jednemu interfejsowi.
//
// Per-link DNS jest tu istotny: host w domenie ma zwykle serwer katalogu na
// jednym interfejsie i serwer dostawcy na drugim, a pytanie "ktory z nich
// odpowie" ma inna odpowiedz dla kazdej nazwy.
type Link struct {
	Name    string   `json:"name"`
	Index   int      `json:"index,omitempty"`
	Servers []string `json:"servers,omitempty"`
	Domains []string `json:"domains,omitempty"`
	// DefaultRoute mowi, czy ten link obsluguje nazwy spoza swoich domen.
	DefaultRoute *bool  `json:"default_route,omitempty"`
	DNSSEC       string `json:"dnssec,omitempty"`
	DNSOverTLS   string `json:"dns_over_tls,omitempty"`
}

// Snapshot to stan resolvera hosta.
type Snapshot struct {
	// Owner mowi, kto pisze resolv.conf. Pusty oznacza wlasciciela
	// nieustalonego, a nie brak wlasciciela.
	Owner string `json:"owner,omitempty"`
	Mode  string `json:"mode,omitempty"`
	// ResolvConf i ResolvConfTarget opisuja sam plik: operator ma wiedziec,
	// czy patrzy na plik, czy na dowiazanie do stubu.
	ResolvConf       string   `json:"resolv_conf,omitempty"`
	ResolvConfTarget string   `json:"resolv_conf_target,omitempty"`
	Servers          []string `json:"servers,omitempty"`
	SearchDomains    []string `json:"search_domains,omitempty"`
	Links            []Link   `json:"links,omitempty"`
	DNSSEC           string   `json:"dnssec,omitempty"`
	DNSOverTLS       string   `json:"dns_over_tls,omitempty"`
	// Writable mowi, czy panel potrafi tu cokolwiek zmienic i dlaczego nie.
	Writable          bool      `json:"writable"`
	WriteAdapter      string    `json:"write_adapter,omitempty"`
	ReadOnlyReason    string    `json:"read_only_reason,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// WynikZapytania opisuje pojedynczy test rozwiazywania nazwy.
//
// Test jest faktem z hosta, a nie z panelu: panel siedzi w innej sieci i jego
// odpowiedz nie mowi nic o tym, co zobaczy host.
type WynikZapytania struct {
	Name string `json:"name"`
	// Addresses jest pusta lista, gdy nazwa nie ma adresu - i wtedy Error
	// mowi dlaczego. Pusta lista bez powodu bylaby cisza.
	Addresses  []string `json:"addresses,omitempty"`
	Server     string   `json:"server,omitempty"`
	Error      string   `json:"error,omitempty"`
	TookMillis int64    `json:"took_millis"`
}
