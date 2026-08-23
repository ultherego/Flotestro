package dns

import (
	"strconv"
	"strings"
)

// ParsujResolvConf czyta klasyczny plik resolvera.
func ParsujResolvConf(tresc string) (serwery, domeny []string) {
	for _, linia := range strings.Split(tresc, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || strings.HasPrefix(linia, "#") || strings.HasPrefix(linia, ";") {
			continue
		}
		pola := strings.Fields(linia)
		switch pola[0] {
		case "nameserver":
			if len(pola) > 1 {
				serwery = append(serwery, pola[1])
			}
		case "search":
			domeny = append(domeny, pola[1:]...)
		case "domain":
			// "domain" jest starsza forma pojedynczej domeny wyszukiwania.
			if len(pola) > 1 {
				domeny = append(domeny, pola[1])
			}
		}
	}
	return serwery, domeny
}

// WlascicielResolvConf rozstrzyga, kto pisze plik resolvera.
//
// Wlasciciel decyduje o tym, czy panel moze cokolwiek zmienic: plik nalezacy
// do uslugi zostanie nadpisany przy nastepnym zdarzeniu sieci, wiec zapis
// w nim bylby zmiana, ktora znika sama.
func WlascicielResolvConf(celDowiazania, tresc string) string {
	switch {
	case strings.Contains(celDowiazania, "/systemd/resolve/"):
		return WlascicielResolved
	case strings.Contains(celDowiazania, "/NetworkManager/"):
		return WlascicielNM
	}
	naglowek := strings.ToLower(pierwszeLinie(tresc, 5))
	switch {
	case strings.Contains(naglowek, "systemd-resolved"):
		return WlascicielResolved
	case strings.Contains(naglowek, "networkmanager"):
		return WlascicielNM
	case strings.Contains(naglowek, "dhcpcd"), strings.Contains(naglowek, "dhclient"),
		strings.Contains(naglowek, "resolvconf"):
		return WlascicielDHCP
	case tresc == "":
		// Pusty plik nie mowi nic o wlascicielu, a zgadywanie "reczny"
		// zachecaloby panel do pisania po czyms, czego nie rozumie.
		return WlascicielNieznany
	}
	return WlascicielReczny
}

func pierwszeLinie(tresc string, ile int) string {
	linie := strings.Split(tresc, "\n")
	if len(linie) > ile {
		linie = linie[:ile]
	}
	return strings.Join(linie, "\n")
}

// ParsujResolvectl czyta wyjscie "resolvectl status".
//
// Format jest przeznaczony dla czlowieka, wiec parser trzyma sie wylacznie
// etykiet, ktore systemd wypisuje od lat, i nie zaklada kolejnosci sekcji.
// Wartosci, ktorych nie rozumie, po prostu pomija - lepiej pokazac mniej niz
// zmyslic per-link DNS, na ktory operator sie potem powola.
func ParsujResolvectl(wyjscie string) Snapshot {
	snapshot := Snapshot{}
	var biezacy *Link

	for _, linia := range strings.Split(wyjscie, "\n") {
		bezWciecia := strings.TrimSpace(linia)
		if bezWciecia == "" {
			continue
		}
		if bezWciecia == "Global" {
			biezacy = nil
			continue
		}
		if strings.HasPrefix(bezWciecia, "Link ") {
			snapshot.Links = append(snapshot.Links, parsujNaglowekLinku(bezWciecia))
			biezacy = &snapshot.Links[len(snapshot.Links)-1]
			continue
		}

		klucz, wartosc, ok := strings.Cut(bezWciecia, ":")
		if !ok {
			// Kontynuacja poprzedniego wiersza: systemd lamie liste
			// protokolow na dwa wiersze, gdy jest dluga.
			if strings.Contains(bezWciecia, "DNSSEC=") {
				if biezacy != nil {
					przypiszProtokoly(biezacy, bezWciecia)
				} else {
					snapshot.DNSSEC, snapshot.DNSOverTLS = zProtokolow(bezWciecia, snapshot.DNSSEC, snapshot.DNSOverTLS)
				}
			}
			continue
		}
		klucz = strings.TrimSpace(klucz)
		wartosc = strings.TrimSpace(wartosc)

		switch klucz {
		case "Protocols":
			if biezacy != nil {
				przypiszProtokoly(biezacy, wartosc)
			} else {
				snapshot.DNSSEC, snapshot.DNSOverTLS = zProtokolow(wartosc, snapshot.DNSSEC, snapshot.DNSOverTLS)
			}
		case "resolv.conf mode":
			snapshot.Mode = wartosc
		case "DNS Servers":
			if biezacy != nil {
				biezacy.Servers = append(biezacy.Servers, strings.Fields(wartosc)...)
			} else {
				snapshot.Servers = append(snapshot.Servers, strings.Fields(wartosc)...)
			}
		case "Current DNS Server":
			// Serwer biezacy jest jednym z listy; nie dopisujemy go drugi raz.
		case "DNS Domain":
			domeny := strings.Fields(wartosc)
			if biezacy != nil {
				biezacy.Domains = append(biezacy.Domains, domeny...)
			} else {
				snapshot.SearchDomains = append(snapshot.SearchDomains, domeny...)
			}
		case "Default Route":
			if biezacy != nil {
				wartoscLogiczna := wartosc == "yes"
				biezacy.DefaultRoute = &wartoscLogiczna
			}
		}
	}
	return snapshot
}

func parsujNaglowekLinku(linia string) Link {
	// Format: "Link 2 (enp0s3)".
	link := Link{}
	pola := strings.Fields(linia)
	if len(pola) >= 2 {
		if numer, err := strconv.Atoi(pola[1]); err == nil {
			link.Index = numer
		}
	}
	if start := strings.Index(linia, "("); start >= 0 {
		if koniec := strings.Index(linia[start:], ")"); koniec > 0 {
			link.Name = linia[start+1 : start+koniec]
		}
	}
	return link
}

func przypiszProtokoly(link *Link, wartosc string) {
	if link == nil {
		return
	}
	link.DNSSEC, link.DNSOverTLS = zProtokolow(wartosc, link.DNSSEC, link.DNSOverTLS)
}

// zProtokolow wyluskuje stan DNSSEC i DNS-over-TLS z wiersza protokolow.
//
// systemd zapisuje je jako "DNSSEC=no/unsupported" i "-DNSOverTLS" albo
// "+DNSOverTLS". Minus i plus to wylaczone i wlaczone; brak wpisu zostawia
// stan nieustalony, bo starsze wersje nie wypisuja go wcale.
func zProtokolow(wartosc, dnssec, dot string) (string, string) {
	for _, pole := range strings.Fields(wartosc) {
		switch {
		case strings.HasPrefix(pole, "DNSSEC="):
			dnssec = strings.TrimPrefix(pole, "DNSSEC=")
		case pole == "+DNSOverTLS":
			dot = "yes"
		case pole == "-DNSOverTLS":
			dot = "no"
		case strings.HasPrefix(pole, "DNSOverTLS="):
			dot = strings.TrimPrefix(pole, "DNSOverTLS=")
		}
	}
	return dnssec, dot
}

// PoprawnaNazwaDoTestu sprawdza nazwe zlecona do rozwiazania.
//
// Nazwa idzie do polecenia jako argument, wiec musi byc nazwa, a nie
// czymkolwiek: adres, flaga i sciezka nie sa tu zapytaniem.
func PoprawnaNazwaDoTestu(nazwa string) bool {
	if nazwa == "" || len(nazwa) > 253 || strings.HasPrefix(nazwa, "-") {
		return false
	}
	etykiety := strings.Split(strings.TrimSuffix(nazwa, "."), ".")
	for _, etykieta := range etykiety {
		if etykieta == "" || len(etykieta) > 63 {
			return false
		}
		for _, znak := range etykieta {
			czyDozwolony := (znak >= 'a' && znak <= 'z') || (znak >= 'A' && znak <= 'Z') ||
				(znak >= '0' && znak <= '9') || znak == '-' || znak == '_'
			if !czyDozwolony {
				return false
			}
		}
	}
	return true
}
