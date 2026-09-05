package certificates

import "time"

// Progi wygasania. Ocena powstaje w panelu z tego samego powodu, co ocena
// zgodnosci: to polityka, a nie fakt o hoscie. Host zglasza termin, panel
// mowi, czy ten termin jest juz problemem - i mowi to tak samo o kazdym
// hoscie floty, takze wtedy, gdy hosty maja rozne wersje agenta.
const (
	// ProgPilny to termin, przy ktorym odnowienie przestaje byc planem
	// na przyszly tydzien. Certyfikat wygasly w nocy zatrzymuje usluge rano.
	ProgPilny = 7 * 24 * time.Hour
	// ProgOstrzezenia to moment, w ktorym odnowienie da sie jeszcze zaplanowac
	// na spokojnie - razem z oknem serwisowym i zgoda drugiej osoby.
	ProgOstrzezenia = 30 * 24 * time.Hour
)

// MaksymalnyWiekOdczytu mowi, po jakim czasie obraz przestaje opisywac host.
//
// Metadane certyfikatow zbiera sie co kilka do kilkunastu godzin - termin
// waznosci nie zmienia sie sam. Zmienic moze sie jednak plik: certyfikat
// podmieniony recznie widac dopiero przy nastepnym odczycie, wiec obraz
// starszy niz doba z okladem opisujemy jako nieswiezy, a nie jako aktualny.
const MaksymalnyWiekOdczytu = 36 * time.Hour

// Stany certyfikatu widziane przez panel.
const (
	StanNieznany    = "unknown"
	StanWygasl      = "expired"
	StanPilny       = "critical"
	StanOstrzezenie = "warning"
	StanWazny       = "valid"
)

// Stan ocenia termin waznosci wzgledem chwili.
//
// Brak terminu jest stanem nieznanym, a nie waznym: certyfikat, ktorego nie
// udalo sie odczytac, nie jest certyfikatem w porzadku.
func Stan(notAfter *time.Time, teraz time.Time) string {
	if notAfter == nil {
		return StanNieznany
	}
	pozostalo := notAfter.Sub(teraz)
	switch {
	case pozostalo <= 0:
		return StanWygasl
	case pozostalo <= ProgPilny:
		return StanPilny
	case pozostalo <= ProgOstrzezenia:
		return StanOstrzezenie
	}
	return StanWazny
}

// waga porzadkuje stany od najgorszego. Nieznany stoi obok pilnego, a nie
// obok waznego: brak wiedzy o certyfikacie uslugi nie jest dobra wiadomoscia.
var waga = map[string]int{
	StanWygasl:      4,
	StanPilny:       3,
	StanNieznany:    2,
	StanOstrzezenie: 1,
	StanWazny:       0,
}

// Gorszy zwraca gorszy z dwoch stanow. Host opisuje jego najgorszy
// certyfikat: jeden wygasly wystarczy, zeby usluga przestala odpowiadac.
func Gorszy(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if waga[b] > waga[a] {
		return b
	}
	return a
}

// Nieswiezy mowi, czy obraz jest starszy, niz opisuje go polityka odczytu.
func Nieswiezy(obserwacja time.Time, teraz time.Time) bool {
	return obserwacja.IsZero() || teraz.Sub(obserwacja) > MaksymalnyWiekOdczytu
}
