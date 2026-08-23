package firewall

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Lancuchy panelu. Panel trzyma dwa: dla ruchu przychodzacego i wychodzacego.
// Wiecej nie jest potrzebne, a kazdy dodatkowy to kolejne miejsce, w ktorym
// kolejnosc regul decyduje o dostepie do hosta.
const (
	LancuchWejscie = "wejscie"
	LancuchWyjscie = "wyjscie"
)

// Dozwolone dzialania reguly.
const (
	DzialanieAccept = "accept"
	DzialanieDrop   = "drop"
	DzialanieReject = "reject"
)

// PrefiksKomentarza znakuje reguly panelu. Komentarz jest jedynym trwalym
// znacznikiem wlasnosci: uchwyt nadaje jadro i zmienia sie przy kazdym
// przeladowaniu tablicy.
const PrefiksKomentarza = "flotestro:"

// RuleSpec opisuje regule w postaci, ktora panel potrafi zlozyc i cofnac.
//
// Panel nie przyjmuje surowego zapisu nft: tekst reguly jest jezykiem, a
// przyjmowanie jezyka od operatora znaczyloby, ze host wykona wszystko, co da
// sie w nim zapisac. Kreator sklada regule z pol, ktore panel rozumie.
type RuleSpec struct {
	// ID jest nazwa reguly nadana przez operatora. Trafia do komentarza,
	// wiec regule da sie odnalezc po przeladowaniu tablicy.
	ID    string `json:"id"`
	Chain string `json:"chain"`
	// Action rozstrzyga, co dzieje sie z pasujacym pakietem.
	Action string `json:"action"`
	// Protocol pusty oznacza dowolny protokol.
	Protocol string `json:"protocol,omitempty"`
	// Ports sa portami docelowymi: pojedynczymi albo zakresami "1000-2000".
	Ports []string `json:"ports,omitempty"`
	// Sources sa adresami zrodlowymi z maska.
	Sources   []string `json:"sources,omitempty"`
	Interface string   `json:"interface,omitempty"`
	Comment   string   `json:"comment,omitempty"`
}

var (
	identyfikatorReguly = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	zakresPortow        = regexp.MustCompile(`^(\d{1,5})(?:-(\d{1,5}))?$`)
	nazwaInterfejsu     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)
)

// Waliduj sprawdza regule przed zlozeniem polecenia.
func (r RuleSpec) Waliduj() error {
	if !identyfikatorReguly.MatchString(r.ID) {
		return fmt.Errorf("nieprawidlowa nazwa reguly %q", r.ID)
	}
	if r.Chain != LancuchWejscie && r.Chain != LancuchWyjscie {
		return fmt.Errorf("regula moze trafic tylko do lancucha %q albo %q",
			LancuchWejscie, LancuchWyjscie)
	}
	switch r.Action {
	case DzialanieAccept, DzialanieDrop, DzialanieReject:
	default:
		return fmt.Errorf("nieobslugiwane dzialanie %q", r.Action)
	}
	switch r.Protocol {
	case "", "tcp", "udp", "icmp":
	default:
		return fmt.Errorf("nieobslugiwany protokol %q", r.Protocol)
	}
	if len(r.Ports) > 0 && r.Protocol != "tcp" && r.Protocol != "udp" {
		return fmt.Errorf("porty maja sens tylko dla tcp i udp")
	}
	for _, port := range r.Ports {
		if err := walidujPort(port); err != nil {
			return err
		}
	}
	for _, zrodlo := range r.Sources {
		if _, _, err := net.ParseCIDR(zrodlo); err != nil {
			return fmt.Errorf("zrodlo %q nie jest adresem z maska", zrodlo)
		}
	}
	if r.Interface != "" && !nazwaInterfejsu.MatchString(r.Interface) {
		return fmt.Errorf("nieprawidlowa nazwa interfejsu %q", r.Interface)
	}
	if strings.ContainsAny(r.Comment, `"\`+"\n") {
		return fmt.Errorf("komentarz nie moze zawierac cudzyslowu ani znaku nowej linii")
	}
	// Regula bez jakiegokolwiek dopasowania obejmuje caly ruch. Blokada
	// calego ruchu jest osobna decyzja, a nie skutkiem pustego formularza.
	if r.Protocol == "" && len(r.Ports) == 0 && len(r.Sources) == 0 && r.Interface == "" {
		return fmt.Errorf("regula bez zadnego dopasowania obejmuje caly ruch")
	}
	return nil
}

func walidujPort(port string) error {
	pola := zakresPortow.FindStringSubmatch(port)
	if pola == nil {
		return fmt.Errorf("port %q nie jest numerem ani zakresem", port)
	}
	od, _ := strconv.Atoi(pola[1])
	if od < 1 || od > 65535 {
		return fmt.Errorf("port %d jest poza zakresem 1-65535", od)
	}
	if pola[2] != "" {
		do, _ := strconv.Atoi(pola[2])
		if do < 1 || do > 65535 || do <= od {
			return fmt.Errorf("zakres portow %q jest pusty albo poza zakresem", port)
		}
	}
	return nil
}

// Komentarz sklada znacznik wlasnosci reguly.
func (r RuleSpec) Komentarz() string {
	if r.Comment == "" {
		return PrefiksKomentarza + " " + r.ID
	}
	return PrefiksKomentarza + " " + r.ID + " - " + r.Comment
}

// Wyrazenie sklada tresc reguly w jezyku nft.
//
// Zwracamy pola osobno, a nie jeden napis, zeby polecenie szlo jako lista
// argumentow: tekst sklejony w jeden argument musialby przejsc przez powloke.
func (r RuleSpec) Wyrazenie() []string {
	var czesci []string
	if r.Interface != "" {
		klucz := "iifname"
		if r.Chain == LancuchWyjscie {
			klucz = "oifname"
		}
		czesci = append(czesci, klucz, `"`+r.Interface+`"`)
	}
	if len(r.Sources) > 0 {
		// Rodzina inet obsluguje oba protokoly, wiec wybor slowa kluczowego
		// zalezy od tego, czym jest adres.
		czesci = append(czesci, slowoAdresu(r.Sources[0]), "saddr", zbior(r.Sources))
	}
	if r.Protocol == "icmp" {
		czesci = append(czesci, "meta", "l4proto", "icmp")
	} else if r.Protocol != "" && len(r.Ports) > 0 {
		czesci = append(czesci, r.Protocol, "dport", zbior(r.Ports))
	} else if r.Protocol != "" {
		czesci = append(czesci, "meta", "l4proto", r.Protocol)
	}
	// Licznik jest zawsze: regula bez licznika nie odpowiada na pytanie
	// "czy cokolwiek przez nia przeszlo".
	czesci = append(czesci, "counter", r.Action, "comment", `"`+r.Komentarz()+`"`)
	return czesci
}

func slowoAdresu(adres string) string {
	if strings.Contains(adres, ":") {
		return "ip6"
	}
	return "ip"
}

// zbior sklada liste wartosci w postaci zbioru nft. Jeden element zapisujemy
// wprost, bo zbior jednoelementowy nft i tak rozwija.
func zbior(wartosci []string) string {
	if len(wartosci) == 1 {
		return wartosci[0]
	}
	return "{ " + strings.Join(wartosci, ", ") + " }"
}

// ArgumentyZalozeniaTablicy sklada polecenia tworzace tablice panelu.
//
// Tablica jest wlasna, bo zapora hosta zwykle nalezy juz do kogos: docker
// przepisuje swoje lancuchy przy kazdym starcie kontenera, a firewalld przy
// przeladowaniu. Polityka lancuchow zostaje "accept": tablica panelu dodaje
// jawne reguly, a nie odcina hosta domyslnie.
func ArgumentyZalozeniaTablicy() [][]string {
	return [][]string{
		{SciezkaNft, "add", "table", RodzinaFlotestro, TabelaFlotestro},
		{SciezkaNft, "add", "chain", RodzinaFlotestro, TabelaFlotestro, LancuchWejscie,
			"{ type filter hook input priority 0 ; policy accept ; }"},
		{SciezkaNft, "add", "chain", RodzinaFlotestro, TabelaFlotestro, LancuchWyjscie,
			"{ type filter hook output priority 0 ; policy accept ; }"},
	}
}

// ArgumentyReguly sklada polecenie dodania reguly.
func ArgumentyReguly(regula RuleSpec) ([]string, error) {
	if err := regula.Waliduj(); err != nil {
		return nil, err
	}
	polecenie := []string{SciezkaNft, "add", "rule", RodzinaFlotestro, TabelaFlotestro, regula.Chain}
	return append(polecenie, regula.Wyrazenie()...), nil
}

// ArgumentyUsuniecia sklada polecenie usuniecia reguly po uchwycie.
func ArgumentyUsuniecia(lancuch string, uchwyt int) ([]string, error) {
	if lancuch != LancuchWejscie && lancuch != LancuchWyjscie {
		return nil, fmt.Errorf("panel usuwa reguly wylacznie z wlasnych lancuchow")
	}
	if uchwyt <= 0 {
		return nil, fmt.Errorf("nieprawidlowy uchwyt reguly %d", uchwyt)
	}
	return []string{SciezkaNft, "delete", "rule", RodzinaFlotestro, TabelaFlotestro,
		lancuch, "handle", strconv.Itoa(uchwyt)}, nil
}

// ChroniKanalZarzadzania sprawdza, czy regula nie odetnie panelu od hosta.
//
// To jedyna regula, ktorej nie wolno stracic: bez niej host przestaje
// odpowiadac i nie ma czym cofnac zmiany. Sprawdzenie jest zachowawcze -
// przy watpliwosci odmawiamy, bo koszt falszywej odmowy to jedno klikniecie,
// a koszt falszywej zgody to wyjazd do serwerowni.
func ChroniKanalZarzadzania(regula RuleSpec, adresPanelu string, portAgenta int) error {
	if regula.Action == DzialanieAccept {
		return nil
	}
	if regula.Chain == LancuchWejscie && pasujePort(regula, portAgenta) {
		return fmt.Errorf("regula obejmuje port %d, ktorym host rozmawia z panelem", portAgenta)
	}
	if adresPanelu != "" && pasujeAdres(regula, adresPanelu) {
		return fmt.Errorf("regula obejmuje adres %s, ktorym host rozmawia z panelem", adresPanelu)
	}
	// Regula bez zawezenia adresu i portu obejmuje takze kanal zarzadzania.
	if len(regula.Sources) == 0 && len(regula.Ports) == 0 && regula.Interface == "" {
		return fmt.Errorf("regula bez zawezenia obejmuje takze polaczenie z panelem")
	}
	return nil
}

func pasujePort(regula RuleSpec, port int) bool {
	if len(regula.Ports) == 0 {
		// Brak portow oznacza caly protokol, a wiec takze ten port.
		return regula.Protocol == "" || regula.Protocol == "tcp"
	}
	for _, wpis := range regula.Ports {
		pola := zakresPortow.FindStringSubmatch(wpis)
		if pola == nil {
			continue
		}
		od, _ := strconv.Atoi(pola[1])
		do := od
		if pola[2] != "" {
			do, _ = strconv.Atoi(pola[2])
		}
		if port >= od && port <= do {
			return true
		}
	}
	return false
}

func pasujeAdres(regula RuleSpec, adres string) bool {
	if len(regula.Sources) == 0 {
		return false
	}
	adresIP := net.ParseIP(adres)
	if adresIP == nil {
		return false
	}
	for _, zrodlo := range regula.Sources {
		_, siec, err := net.ParseCIDR(zrodlo)
		if err == nil && siec.Contains(adresIP) {
			return true
		}
	}
	return false
}
