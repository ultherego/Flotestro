// Package firewall opisuje reguly zapory hosta.
//
// Modul czyta stan jadra, a nie pliki konfiguracyjne uslug: to, co host
// naprawde filtruje, i to, co ktos wpisal do konfiguracji, potrafi sie
// rozjechac - a pakiet odbija sie od pierwszego.
package firewall

import "time"

// Adaptery zapory. Nazwa mowi, kto na tym hoscie trzyma reguly.
const (
	AdapterNftables  = "nftables"
	AdapterFirewalld = "firewalld"
	AdapterUFW       = "ufw"
)

// Pochodzenie reguly. Panel nie udaje, ze wszystko na hoscie jest jego.
const (
	SourceManaged = "managed"
	SourceManual  = "manual"
	// SourceForeign oznacza tablice nalezaca do innego programu: docker,
	// firewalld albo iptables-nft. Panel jej nie dotyka.
	SourceForeign = "foreign"
)

// TabelaFlotestro jest jedyna tablica, ktora panel zaklada i zmienia.
//
// Reguly panelu zyja we wlasnej tablicy, bo zapora hosta zwykle nalezy juz
// do kogos: docker przepisuje swoje lancuchy przy kazdym starcie kontenera,
// a firewalld przy kazdym przeladowaniu. Wchodzenie w cudze lancuchy konczy
// sie regula, ktora znika bez sladu.
const (
	RodzinaFlotestro = "inet"
	TabelaFlotestro  = "flotestro"
)

// Rule to jedna regula w postaci, w jakiej pokazuje ja nft.
//
// Tresc jest tekstem od nft, a nie zlozona przez panel: operator zna ten
// zapis z wiersza polecen, a wlasne renderowanie rozjechaloby sie z tym,
// co host naprawde ma.
type Rule struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Chain  string `json:"chain"`
	Handle int    `json:"handle"`
	Text   string `json:"text"`
	Source string `json:"source"`
	// Comment niesie znacznik panelu, gdy regula nalezy do Flotestro.
	Comment string `json:"comment,omitempty"`
	// Packets i Bytes sa licznikami reguly. Brak wartosci oznacza regule
	// bez licznika, a nie regule, przez ktora nic nie przeszlo.
	Packets *uint64 `json:"packets,omitempty"`
	Bytes   *uint64 `json:"bytes,omitempty"`
}

// Chain to lancuch wraz z zaczepieniem i polityka.
type Chain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	// Type, Hook i Priority sa puste dla lancuchow zwyklych: nie kazdy
	// lancuch jest zaczepiony w sciezce pakietu.
	Type     string `json:"type,omitempty"`
	Hook     string `json:"hook,omitempty"`
	Priority string `json:"priority,omitempty"`
	// Policy dotyczy wylacznie lancuchow bazowych. Puste oznacza brak
	// polityki, a nie polityke "accept".
	Policy string `json:"policy,omitempty"`
	Source string `json:"source"`
}

// Table to tablica regul wraz z jej wlascicielem.
type Table struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	Source string `json:"source"`
	// Owner niesie ostrzezenie nft o tablicy nalezacej do innego programu.
	Owner string `json:"owner,omitempty"`
}

// Zone opisuje strefe firewalld.
type Zone struct {
	Name       string   `json:"name"`
	Active     bool     `json:"active"`
	Default    bool     `json:"default"`
	Target     string   `json:"target,omitempty"`
	Interfaces []string `json:"interfaces,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	Services   []string `json:"services,omitempty"`
	Ports      []string `json:"ports,omitempty"`
}

// Snapshot to obraz zapory hosta w jednej chwili.
type Snapshot struct {
	// Adapter nazywa mechanizm, ktory na tym hoscie trzyma reguly.
	Adapter string `json:"adapter,omitempty"`
	// Hash jest odciskiem calego zestawu regul. Zmiana zlecona wobec innego
	// zestawu nie jest ta sama zmiana, ktora operator ogladal.
	Hash   string  `json:"hash,omitempty"`
	Tables []Table `json:"tables,omitempty"`
	Chains []Chain `json:"chains,omitempty"`
	Rules  []Rule  `json:"rules,omitempty"`
	Zones  []Zone  `json:"zones,omitempty"`
	// Writable mowi, czy panel potrafi tu cokolwiek zmienic i dlaczego nie.
	Writable       bool      `json:"writable"`
	ReadOnlyReason string    `json:"read_only_reason,omitempty"`
	ObservedAt     time.Time `json:"observed_at"`
	// UnavailableReason mowi, dlaczego stanu nie udalo sie ustalic. Host bez
	// regul i host nieodpytany to dwie rozne odpowiedzi.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}
