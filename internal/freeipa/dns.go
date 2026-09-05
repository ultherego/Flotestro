package freeipa

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// DNS katalogowy jest osobnym zakresem niz resolver hosta: tam panel mowi
// hostowi, kogo ma pytac, a tutaj - co katalog ma odpowiadac calej sieci.
// Rekord wskazujacy na zly adres psuje nie jeden host, tylko wszystkich,
// ktorzy o niego zapytaja.

// Typy rekordow, ktore panel potrafi zapisac.
//
// Lista jest zamknieta i krotka celowo. Rekordy NS, SOA i DNSSEC zmieniaja
// sposob dzialania samej strefy, a nie jej zawartosc - i nie sa czyms, co
// dopisuje sie z panelu zarzadzania flota.
const (
	RekordA     = "A"
	RekordAAAA  = "AAAA"
	RekordCNAME = "CNAME"
	RekordTXT   = "TXT"
	RekordSRV   = "SRV"
	RekordPTR   = "PTR"
)

// atrybutRekordu tlumaczy typ rekordu na nazwe pola w katalogu.
var atrybutRekordu = map[string]string{
	RekordA:     "arecord",
	RekordAAAA:  "aaaarecord",
	RekordCNAME: "cnamerecord",
	RekordTXT:   "txtrecord",
	RekordSRV:   "srvrecord",
	RekordPTR:   "ptrrecord",
}

var (
	nazwaStrefy  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.?$`)
	nazwaRekordu = regexp.MustCompile(`^(\*|@|[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?)(\.[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?)*$`)
)

// Strefa jest strefa DNS w katalogu.
type Strefa struct {
	Name string `json:"name"`
	// Reverse oznacza strefe odwrotna (in-addr.arpa albo ip6.arpa).
	Reverse bool `json:"reverse"`
}

// Rekord jest jednym wpisem w strefie.
type Rekord struct {
	Zone   string   `json:"zone"`
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Values []string `json:"values"`
	TTL    int      `json:"ttl,omitempty"`
}

// FQDN sklada pelna nazwe rekordu.
func (r Rekord) FQDN() string {
	if r.Name == "@" || r.Name == "" {
		return strings.TrimSuffix(r.Zone, ".")
	}
	return strings.TrimSuffix(r.Name, ".") + "." + strings.TrimSuffix(r.Zone, ".")
}

// RecordSpec opisuje rekord zlecony przez panel.
type RecordSpec struct {
	Zone  string
	Name  string
	Type  string
	Value string
	TTL   int
}

// Validate sprawdza rekord, zanim cokolwiek pojdzie do katalogu.
func (s RecordSpec) Validate() error {
	if !nazwaStrefy.MatchString(s.Zone) {
		return fmt.Errorf("nieprawidlowa nazwa strefy %q", s.Zone)
	}
	if !nazwaRekordu.MatchString(s.Name) {
		return fmt.Errorf("nieprawidlowa nazwa rekordu %q", s.Name)
	}
	if _, znany := atrybutRekordu[s.Type]; !znany {
		return fmt.Errorf("panel nie zapisuje rekordow typu %q", s.Type)
	}
	if s.TTL < 0 || s.TTL > 604800 {
		return fmt.Errorf("TTL %d jest poza zakresem 0-604800", s.TTL)
	}
	wartosc := strings.TrimSpace(s.Value)
	if wartosc == "" {
		return fmt.Errorf("rekord wymaga wartosci")
	}
	if strings.ContainsAny(wartosc, "\n\r") {
		return fmt.Errorf("wartosc rekordu zawiera znak nowej linii")
	}
	switch s.Type {
	case RekordA:
		adres := net.ParseIP(wartosc)
		if adres == nil || adres.To4() == nil {
			return fmt.Errorf("%q nie jest adresem IPv4", wartosc)
		}
	case RekordAAAA:
		adres := net.ParseIP(wartosc)
		if adres == nil || adres.To4() != nil {
			return fmt.Errorf("%q nie jest adresem IPv6", wartosc)
		}
	case RekordCNAME, RekordPTR:
		if !nazwaStrefy.MatchString(strings.TrimSuffix(wartosc, ".")) {
			return fmt.Errorf("%q nie jest nazwa domenowa", wartosc)
		}
	case RekordSRV:
		// Format: priorytet waga port cel.
		pola := strings.Fields(wartosc)
		if len(pola) != 4 {
			return fmt.Errorf("rekord SRV ma postac \"priorytet waga port cel\"")
		}
		for _, pole := range pola[:3] {
			liczba, err := strconv.Atoi(pole)
			if err != nil || liczba < 0 || liczba > 65535 {
				return fmt.Errorf("nieprawidlowa liczba %q w rekordzie SRV", pole)
			}
		}
	case RekordTXT:
		if len(wartosc) > 255 {
			return fmt.Errorf("wartosc rekordu TXT jest dluzsza niz 255 znakow")
		}
	}
	return nil
}

// Zones zwraca strefy DNS katalogu.
func (c *Client) Zones(ctx context.Context) ([]Strefa, error) {
	return cached(ctx, c, "dns-zones", func() ([]Strefa, error) {
		records, err := c.findRecords(ctx, "dnszone_find")
		if err != nil {
			return nil, err
		}
		strefy := make([]Strefa, 0, len(records))
		for _, record := range records {
			nazwa := strings.TrimSuffix(first(record, "idnsname"), ".")
			if nazwa == "" {
				continue
			}
			strefy = append(strefy, Strefa{
				Name:    nazwa,
				Reverse: strings.HasSuffix(nazwa, ".in-addr.arpa") || strings.HasSuffix(nazwa, ".ip6.arpa"),
			})
		}
		return strefy, nil
	})
}

// Records zwraca rekordy jednej strefy.
//
// Nie cache'ujemy ich: rekord jest tym, co zmienia sie w odpowiedzi na
// operacje panelu, a lista sprzed minuty pokazywalaby stan sprzed zmiany.
func (c *Client) Records(ctx context.Context, zone string) ([]Rekord, error) {
	if !nazwaStrefy.MatchString(zone) {
		return nil, fmt.Errorf("nieprawidlowa nazwa strefy %q", zone)
	}
	result, err := c.call(ctx, "dnsrecord_find", []string{zone}, map[string]any{
		"all": true, "sizelimit": 0,
	})
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Result    []map[string]any `json:"result"`
		Truncated bool             `json:"truncated"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, fmt.Errorf("odpowiedz dnsrecord_find: %w", err)
	}
	if decoded.Truncated {
		return nil, fmt.Errorf("katalog obcial liste rekordow strefy %s", zone)
	}

	var rekordy []Rekord
	for _, record := range decoded.Result {
		nazwa := first(record, "idnsname")
		for typ, atrybut := range atrybutRekordu {
			wartosci := strings_(record, atrybut)
			if len(wartosci) == 0 {
				continue
			}
			rekord := Rekord{Zone: strings.TrimSuffix(zone, "."), Name: nazwa, Type: typ, Values: wartosci}
			if ttl := first(record, "dnsttl"); ttl != "" {
				rekord.TTL, _ = strconv.Atoi(ttl)
			}
			rekordy = append(rekordy, rekord)
		}
	}
	return rekordy, nil
}

// EnsureRecord dopisuje rekord do strefy.
//
// Katalog dodaje wartosc do rekordu, a nie zastepuje calego wpisu: nazwa
// z dwoma adresami zostaje nazwa z dwoma adresami. Panel nie usuwa niczego
// przy zapisie - usuniecie jest osobna operacja o wyzszym ryzyku.
func (c *Client) EnsureRecord(ctx context.Context, spec RecordSpec) (Rekord, error) {
	if err := spec.Validate(); err != nil {
		return Rekord{}, err
	}
	options := map[string]any{
		atrybutRekordu[spec.Type]: []string{spec.Value},
	}
	if spec.TTL > 0 {
		options["dnsttl"] = spec.TTL
	}
	if _, err := c.call(ctx, "dnsrecord_add",
		[]string{spec.Zone, spec.Name}, options); err != nil {
		return Rekord{}, err
	}
	return Rekord{
		Zone: strings.TrimSuffix(spec.Zone, "."), Name: spec.Name,
		Type: spec.Type, Values: []string{spec.Value}, TTL: spec.TTL,
	}, nil
}

// RemoveRecord usuwa jedna wartosc rekordu.
func (c *Client) RemoveRecord(ctx context.Context, spec RecordSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	_, err := c.call(ctx, "dnsrecord_del", []string{spec.Zone, spec.Name}, map[string]any{
		atrybutRekordu[spec.Type]: []string{spec.Value},
	})
	return err
}

// PelnaNazwa sklada pelna nazwe rekordu ze strefy i nazwy wzglednej.
//
// Wpis w korzeniu strefy zapisuje sie jako "@" i nie moze dac nazwy
// zaczynajacej sie od tego znaku: cel PTR "@.example.test." nie wskazuje
// niczego, a wyglada jak poprawny rekord.
func PelnaNazwa(zone, name string) string {
	strefa := strings.TrimSuffix(zone, ".")
	if name == "" || name == "@" {
		return strefa
	}
	return strings.TrimSuffix(name, ".") + "." + strefa
}

// NazwaWStrefie liczy nazwe wzgledna rekordu PTR w podanej strefie odwrotnej.
//
// Strefa odwrotna nie musi obejmowac calego /24 ani /64: instalacja moze miec
// podzial waskiej, wskazany wprost w zleceniu. Wtedy nazwa wzgledna jest
// dluzsza niz jeden czlon - a policzenie jej dla /24 dawalo rekord dla zupelnie
// innego adresu. Dlatego liczymy pelna nazwe arpa i odejmujemy od niej strefe,
// zamiast zakladac szerokosc podzialu.
func NazwaWStrefie(adres, strefa string) (string, error) {
	pelna, err := PelnaNazwaOdwrotna(adres)
	if err != nil {
		return "", err
	}
	oczyszczona := strings.TrimSuffix(strings.TrimSpace(strefa), ".")
	if oczyszczona == "" {
		return "", fmt.Errorf("nie wskazano strefy odwrotnej")
	}
	if !strings.HasSuffix(pelna, "."+oczyszczona) {
		return "", fmt.Errorf("adres %s nie nalezy do strefy %s", adres, oczyszczona)
	}
	return strings.TrimSuffix(pelna, "."+oczyszczona), nil
}

// PelnaNazwaOdwrotna liczy pelna nazwe arpa dla adresu.
func PelnaNazwaOdwrotna(adres string) (string, error) {
	strefa, nazwa, err := StrefaOdwrotna(adres)
	if err != nil {
		return "", err
	}
	return nazwa + "." + strefa, nil
}

// StrefaOdwrotna liczy strefe i nazwe rekordu PTR dla adresu.
//
// Rekord odwrotny jest osobnym, widocznym elementem planu: to on decyduje,
// co odpowie zapytanie o adres - a zapominanie o nim jest najczestszym bledem
// przy dopisywaniu hostow.
func StrefaOdwrotna(adres string) (strefa, nazwa string, err error) {
	ip := net.ParseIP(adres)
	if ip == nil {
		return "", "", fmt.Errorf("%q nie jest adresem IP", adres)
	}
	if czworka := ip.To4(); czworka != nil {
		// Strefa /24 jest tym, co FreeIPA zaklada domyslnie przy tworzeniu
		// stref odwrotnych; wezsze podzialy wymagaja wskazania strefy wprost.
		return fmt.Sprintf("%d.%d.%d.in-addr.arpa", czworka[2], czworka[1], czworka[0]),
			strconv.Itoa(int(czworka[3])), nil
	}
	// IPv6: nazwa to szesnastkowe polbajty w odwrotnej kolejnosci; strefa
	// obejmuje pierwsze 64 bity adresu.
	rozwiniety := ip.To16()
	var polbajty []string
	for i := len(rozwiniety) - 1; i >= 0; i-- {
		polbajty = append(polbajty,
			strconv.FormatUint(uint64(rozwiniety[i]&0x0f), 16),
			strconv.FormatUint(uint64(rozwiniety[i]>>4), 16))
	}
	return strings.Join(polbajty[16:], ".") + ".ip6.arpa",
		strings.Join(polbajty[:16], "."), nil
}
