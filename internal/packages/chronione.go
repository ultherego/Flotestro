package packages

import (
	"strings"
)

// Chronione pakiety to takie, ktorych usuniecie odcina host od zarzadzania
// albo uniemozliwia jego uruchomienie.
//
// Lista nie jest kompletna i nie ma byc: rozstrzygajaca jest flaga Essential
// z bazy pakietow, ktora dystrybucja utrzymuje lepiej niz my. Te nazwy
// dotyczaja rzeczy, ktorych dystrybucja za istotne nie uznaje, a ktore
// w zarzadzanej flocie sa nie mniej wazne: agent, ktory wykona naprawe,
// i dostep, przez ktory mozna wejsc, gdy panel zawiedzie.
var chronioneNazwy = []string{
	"flotestro-agent",
	"openssh-server",
	"systemd",
	"sudo",
}

// prefiksyChronione obejmuja rodziny pakietow, ktorych usuniecie zostawia
// host bez czegos, czym da sie go uruchomic albo zaktualizowac.
var prefiksyChronione = []string{
	"linux-image",
	"kernel",
	"grub",
	"apt",
	"dpkg",
	"dnf",
	"rpm",
	"systemd-",
}

// Chroniony mowi, czy pakiet nalezy do zbioru, ktorego nie wolno usunac bez
// swiadomego obejscia.
func Chroniony(nazwa string) bool {
	nazwa = strings.TrimSpace(strings.ToLower(nazwa))
	if nazwa == "" {
		return false
	}
	// Nazwa z architektura, np. "systemd:amd64", opisuje ten sam pakiet.
	if index := strings.IndexByte(nazwa, ':'); index > 0 {
		nazwa = nazwa[:index]
	}
	for _, chroniona := range chronioneNazwy {
		if nazwa == chroniona {
			return true
		}
	}
	for _, prefiks := range prefiksyChronione {
		if strings.HasPrefix(nazwa, prefiks) {
			return true
		}
	}
	return false
}

// ChronioneWZbiorze zwraca te z podanych pakietow, ktore sa chronione.
// Zwracamy liste, a nie samo "tak/nie": operator ma wiedziec, ktory pakiet
// blokuje operacje, a nie tylko ze cos ja blokuje.
func ChronioneWZbiorze(pakiety []string) []string {
	var wynik []string
	for _, pakiet := range pakiety {
		if Chroniony(pakiet) {
			wynik = append(wynik, pakiet)
		}
	}
	return wynik
}
