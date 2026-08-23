package network

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SciezkaNmcli wskazuje narzedzie NetworkManagera. Sciezka jest stala,
// a nie szukana w PATH: helper uruchamia wylacznie znane binaria.
const SciezkaNmcli = "/usr/bin/nmcli"

// MTUAuto oznacza wartosc domyslna sterownika. "auto" i konkretna liczba to
// dwie rozne rzeczy, wiec zero nie moze udawac zadnej z nich.
const MTUAuto = "auto"

// Polaczenie to profil NetworkManagera przypisany urzadzeniu.
type Polaczenie struct {
	Nazwa      string
	UUID       string
	Urzadzenie string
	Typ        string
	Stan       string
}

// Profil opisuje ustawienia jednego polaczenia w zakresie, ktorym zarzadza
// panel. Pola puste oznaczaja "NetworkManager nic tu nie ma", a nie "wyczysc".
type Profil struct {
	Polaczenie string   `json:"connection"`
	Interfejs  string   `json:"interface,omitempty"`
	Metoda     string   `json:"method,omitempty"`
	Adresy     []string `json:"addresses,omitempty"`
	Brama      string   `json:"gateway,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	Trasy      []string `json:"routes,omitempty"`
	// MTU jest tekstem, bo "auto" jest tu rownoprawna wartoscia.
	MTU string `json:"mtu,omitempty"`
}

// PolaProfilu wylicza ustawienia, o ktore panel pyta NetworkManagera.
var PolaProfilu = []string{
	"connection.id", "connection.interface-name", "ipv4.method",
	"ipv4.addresses", "ipv4.gateway", "ipv4.dns", "ipv4.routes",
	"802-3-ethernet.mtu",
}

// ParsujPolaczenia czyta wyjscie "nmcli -t -f NAME,UUID,DEVICE,TYPE,STATE con show".
func ParsujPolaczenia(wyjscie string) []Polaczenie {
	var polaczenia []Polaczenie
	for _, linia := range strings.Split(wyjscie, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" {
			continue
		}
		pola := strings.Split(linia, ":")
		if len(pola) < 5 {
			continue
		}
		polaczenia = append(polaczenia, Polaczenie{
			Nazwa: pola[0], UUID: pola[1], Urzadzenie: pola[2],
			Typ: pola[3], Stan: pola[4],
		})
	}
	return polaczenia
}

// PolaczenieUrzadzenia zwraca profil aktywny na danym interfejsie.
func PolaczenieUrzadzenia(polaczenia []Polaczenie, interfejs string) *Polaczenie {
	for i := range polaczenia {
		if polaczenia[i].Urzadzenie == interfejs {
			return &polaczenia[i]
		}
	}
	return nil
}

// ParsujProfil czyta wyjscie "nmcli -t -f <pola> con show <nazwa>".
//
// Wartosc jest wszystkim po pierwszym dwukropku: adresy IPv6 zawieraja
// dwukropki i podzial po kazdym z nich rozbilby je na kawalki.
func ParsujProfil(wyjscie string) Profil {
	profil := Profil{}
	for _, linia := range strings.Split(wyjscie, "\n") {
		linia = strings.TrimSpace(linia)
		podzial := strings.Index(linia, ":")
		if podzial < 0 {
			continue
		}
		klucz, wartosc := linia[:podzial], strings.TrimSpace(linia[podzial+1:])
		if wartosc == "--" {
			wartosc = ""
		}
		switch klucz {
		case "connection.id":
			profil.Polaczenie = wartosc
		case "connection.interface-name":
			profil.Interfejs = wartosc
		case "ipv4.method":
			profil.Metoda = wartosc
		case "ipv4.addresses":
			profil.Adresy = listaWartosci(wartosc)
		case "ipv4.gateway":
			profil.Brama = wartosc
		case "ipv4.dns":
			profil.DNS = listaWartosci(wartosc)
		case "ipv4.routes":
			profil.Trasy = listaWartosci(wartosc)
		case "802-3-ethernet.mtu":
			profil.MTU = wartosc
		}
	}
	return profil
}

func listaWartosci(wartosc string) []string {
	if wartosc == "" {
		return nil
	}
	var wynik []string
	for _, element := range strings.Split(wartosc, ",") {
		element = strings.TrimSpace(element)
		if element != "" {
			wynik = append(wynik, element)
		}
	}
	return wynik
}

// ArgumentyMTU sklada zmiane MTU profilu.
//
// Zmiana idzie przez profil, a nie przez "ip link set": wartosc ustawiona
// wprost na urzadzeniu znika przy pierwszym przelaczeniu polaczenia, a
// operator zobaczylby zmiane, ktora host zapomni po restarcie.
func ArgumentyMTU(polaczenie, mtu string) ([][]string, error) {
	if err := WalidujMTU(mtu); err != nil {
		return nil, err
	}
	return [][]string{
		{SciezkaNmcli, "connection", "modify", polaczenie, "802-3-ethernet.mtu", mtu},
		{SciezkaNmcli, "connection", "up", polaczenie},
	}, nil
}

// ArgumentyTras zapisuje pelna liste tras profilu.
//
// Lista jest stanem docelowym, a nie dopiskiem: operator widzial w planie
// konkretny zestaw tras i to on ma zostac na hoscie.
func ArgumentyTras(polaczenie string, trasy []string) ([][]string, error) {
	for _, trasa := range trasy {
		if err := WalidujTrase(trasa); err != nil {
			return nil, err
		}
	}
	return [][]string{
		{SciezkaNmcli, "connection", "modify", polaczenie, "ipv4.routes", strings.Join(trasy, ",")},
		{SciezkaNmcli, "connection", "up", polaczenie},
	}, nil
}

// ArgumentyProfilu sklada zapis calego profilu adresowego.
func ArgumentyProfilu(profil Profil) ([][]string, error) {
	if profil.Polaczenie == "" {
		return nil, fmt.Errorf("profil bez nazwy polaczenia")
	}
	switch profil.Metoda {
	case "auto", "manual", "disabled", "link-local", "shared":
	default:
		return nil, fmt.Errorf("nieobslugiwana metoda %q", profil.Metoda)
	}
	// Metoda manual bez adresu zostawilaby interfejs bez adresu, a wiec
	// odcielaby host - to nie jest konfiguracja, tylko pomylka.
	if profil.Metoda == "manual" && len(profil.Adresy) == 0 {
		return nil, fmt.Errorf("metoda manual wymaga co najmniej jednego adresu")
	}
	for _, adres := range profil.Adresy {
		if err := WalidujAdres(adres); err != nil {
			return nil, err
		}
	}
	if profil.Brama != "" {
		if err := WalidujAdresIP(profil.Brama); err != nil {
			return nil, fmt.Errorf("brama: %w", err)
		}
	}
	for _, serwer := range profil.DNS {
		if err := WalidujAdresIP(serwer); err != nil {
			return nil, fmt.Errorf("serwer DNS: %w", err)
		}
	}
	for _, trasa := range profil.Trasy {
		if err := WalidujTrase(trasa); err != nil {
			return nil, err
		}
	}

	modyfikacja := []string{SciezkaNmcli, "connection", "modify", profil.Polaczenie,
		"ipv4.method", profil.Metoda,
		"ipv4.addresses", strings.Join(profil.Adresy, ","),
		"ipv4.gateway", profil.Brama,
		"ipv4.dns", strings.Join(profil.DNS, ","),
		"ipv4.routes", strings.Join(profil.Trasy, ",")}
	if profil.MTU != "" {
		modyfikacja = append(modyfikacja, "802-3-ethernet.mtu", profil.MTU)
	}
	return [][]string{modyfikacja, {SciezkaNmcli, "connection", "up", profil.Polaczenie}}, nil
}

// WalidujMTU sprawdza wartosc MTU.
func WalidujMTU(mtu string) error {
	if mtu == MTUAuto {
		return nil
	}
	wartosc, err := strconv.Atoi(mtu)
	if err != nil {
		return fmt.Errorf("MTU %q nie jest liczba ani wartoscia auto", mtu)
	}
	// Ponizej 1280 nie przejdzie IPv6, a ponizej 68 nie przejdzie IPv4.
	// Gorna granica jest granica jadra dla ramek jumbo.
	if wartosc < 1280 || wartosc > 65536 {
		return fmt.Errorf("MTU %d jest poza zakresem 1280-65536", wartosc)
	}
	return nil
}

// WalidujAdres sprawdza adres z maska.
func WalidujAdres(adres string) error {
	if _, _, err := net.ParseCIDR(adres); err != nil {
		return fmt.Errorf("adres %q nie jest adresem z maska", adres)
	}
	return nil
}

// WalidujAdresIP sprawdza sam adres.
func WalidujAdresIP(adres string) error {
	if net.ParseIP(adres) == nil {
		return fmt.Errorf("%q nie jest adresem IP", adres)
	}
	return nil
}

// WalidujTrase sprawdza trase w postaci "siec/maska [brama]".
func WalidujTrase(trasa string) error {
	pola := strings.Fields(trasa)
	if len(pola) == 0 || len(pola) > 2 {
		return fmt.Errorf("trasa %q ma miec postac \"siec/maska [brama]\"", trasa)
	}
	if err := WalidujAdres(pola[0]); err != nil {
		return fmt.Errorf("cel trasy: %w", err)
	}
	if len(pola) == 2 {
		if err := WalidujAdresIP(pola[1]); err != nil {
			return fmt.Errorf("brama trasy: %w", err)
		}
	}
	return nil
}
