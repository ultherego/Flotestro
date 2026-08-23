// Package network inwentaryzuje interfejsy, adresy i trasy hosta.
//
// Modul czyta stan jadra, a nie pliki konfiguracyjne: to, co host naprawde ma
// podniesione, i to, co ktos kiedys wpisal do konfiguracji, potrafi sie
// rozjechac - a operator patrzacy na panel pyta o pierwsze.
package network

import "time"

// Rodzaje adresow.
const (
	FamilyIPv4 = "inet"
	FamilyIPv6 = "inet6"
)

// Address to jeden adres przypisany interfejsowi.
type Address struct {
	Family string `json:"family"`
	// Address jest zapisany razem z maska (10.0.2.15/24): sam adres bez
	// prefiksu nie mowi, jaka siec host uwaza za lokalna.
	Address string `json:"address"`
	Scope   string `json:"scope"`
	// Source mowi, skad adres pochodzi, o ile jadro to podaje: dynamiczny
	// z DHCP zachowuje sie inaczej niz statyczny, a operator ma to widziec
	// przed zmiana konfiguracji.
	Source string `json:"source,omitempty"`
	// Permanent jest falszem dla adresow z czasem zycia. Adres, ktory za
	// godzine zniknie, nie jest tym samym co adres na stale.
	Permanent bool `json:"permanent"`
}

// Interface opisuje jeden interfejs sieciowy.
type Interface struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
	// Kind rozroznia interfejs fizyczny od mostu, veth czy tunelu: host
	// z dockerem ma ich kilkanascie i tylko czesc z nich cokolwiek znaczy.
	Kind string `json:"kind,omitempty"`
	MAC  string `json:"mac,omitempty"`
	MTU  int    `json:"mtu"`
	// OperState jest stanem z jadra (up, down, unknown). "unknown" zostaje
	// slowem "unknown", bo tak wlasnie raportuja interfejsy wirtualne.
	OperState string `json:"oper_state"`
	// Carrier mowi o nosnej. Nieznana zostaje nieznana: brak wartosci to nie
	// to samo co brak kabla.
	Carrier *bool `json:"carrier,omitempty"`
	// SpeedMbps podaje jadro tylko dla czesci sterownikow. Zero znaczyloby
	// "lacze o zerowej przepustowosci", wiec nieznane jest pustym wskaznikiem.
	SpeedMbps *int      `json:"speed_mbps,omitempty"`
	Driver    string    `json:"driver,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
	// Management zaznacza interfejs, przez ktory host rozmawia z panelem.
	// Zmiana wlasnie tego interfejsu jest zmiana galezi, na ktorej siedzimy.
	Management bool `json:"management"`
}

// Route to jedna trasa z tablicy routingu.
type Route struct {
	// Destination "default" jest zapisane tak, jak podaje je jadro.
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Source      string `json:"source,omitempty"`
	// Protocol mowi, kto trase zalozyl (kernel, dhcp, static, ra).
	Protocol string `json:"protocol,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Metric   int    `json:"metric"`
	Family   string `json:"family"`
	Table    string `json:"table,omitempty"`
}

// Snapshot to obraz sieci hosta w jednej chwili.
type Snapshot struct {
	Interfaces []Interface `json:"interfaces"`
	Routes     []Route     `json:"routes"`
	// ManagementInterface i ManagementAddress opisuja kanal do panelu.
	// Panel nie zgaduje adresu z pierwszej pozycji listy: to host wie,
	// ktorym interfejsem wyszlo jego polaczenie.
	ManagementInterface string `json:"management_interface,omitempty"`
	ManagementAddress   string `json:"management_address,omitempty"`
	// WriteAdapter nazywa mechanizm, ktorym da sie zmieniac konfiguracje.
	// Pusty oznacza host, na ktorym panel potrafi tylko czytac.
	WriteAdapter string    `json:"write_adapter,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
	// UnavailableReason mowi, dlaczego stanu nie udalo sie ustalic.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// Interfejs zwraca interfejs o podanej nazwie albo nil.
func (s Snapshot) Interfejs(nazwa string) *Interface {
	for i := range s.Interfaces {
		if s.Interfaces[i].Name == nazwa {
			return &s.Interfaces[i]
		}
	}
	return nil
}
