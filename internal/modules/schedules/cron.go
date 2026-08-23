package schedules

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Wyrazenie crona ma piec pol: minuta, godzina, dzien miesiaca, miesiac,
// dzien tygodnia.
const polCrona = 5

// zakresy opisuja dopuszczalne wartosci kolejnych pol.
var zakresy = [polCrona]struct{ min, max int }{
	{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7},
}

// Wyrazenie to sparsowane wyrazenie crona.
type Wyrazenie struct {
	// dozwolone[i] zawiera wartosci dopuszczone w polu i.
	dozwolone [polCrona]map[int]bool
	// dzienMiesiacaGwiazdka i dzienTygodniaGwiazdka sa potrzebne, bo cron
	// traktuje te dwa pola inaczej niz reszte: gdy oba sa ograniczone,
	// zadanie uruchamia sie, gdy pasuje ktorekolwiek, a nie oba naraz.
	dzienMiesiacaGwiazdka bool
	dzienTygodniaGwiazdka bool
}

// Skroty przyjmowane przez crona zamiast pieciu pol.
var skroty = map[string]string{
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
	"@monthly":  "0 0 1 * *",
	"@weekly":   "0 0 * * 0",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@hourly":   "0 * * * *",
}

// ParsujWyrazenie czyta wyrazenie crona.
//
// Parser jest wlasny, bo wyrazenie trzeba sprawdzic przed zapisem na hoscie
// i policzyc z niego nastepne uruchomienia dla operatora. Wyrazenie, ktorego
// panel nie rozumie, nie zostaje zapisane: wpis, ktory nigdy sie nie
// uruchomi, jest gorszy niz jego brak, bo wyglada jak dzialajacy.
func ParsujWyrazenie(wyrazenie string) (Wyrazenie, error) {
	wyrazenie = strings.TrimSpace(wyrazenie)
	if rozwiniete, ok := skroty[strings.ToLower(wyrazenie)]; ok {
		wyrazenie = rozwiniete
	}
	if strings.HasPrefix(wyrazenie, "@") {
		// @reboot nie ma nastepnego uruchomienia w kalendarzu, wiec panel
		// nie potrafilby go pokazac ani zaplanowac.
		return Wyrazenie{}, fmt.Errorf("nieobslugiwane wyrazenie %q", wyrazenie)
	}

	pola := strings.Fields(wyrazenie)
	if len(pola) != polCrona {
		return Wyrazenie{}, fmt.Errorf("wyrazenie crona ma miec %d pol, ma %d", polCrona, len(pola))
	}

	var wynik Wyrazenie
	wynik.dzienMiesiacaGwiazdka = pola[2] == "*"
	wynik.dzienTygodniaGwiazdka = pola[4] == "*"
	for i, pole := range pola {
		dozwolone, err := parsujPole(pole, zakresy[i].min, zakresy[i].max)
		if err != nil {
			return Wyrazenie{}, fmt.Errorf("pole %d (%q): %w", i+1, pole, err)
		}
		wynik.dozwolone[i] = dozwolone
	}
	// Niedziela ma w cronie dwa numery. Bez tego "0" i "7" opisywalyby rozne
	// dni, choc oznaczaja ten sam.
	if wynik.dozwolone[4][7] {
		wynik.dozwolone[4][0] = true
	}
	return wynik, nil
}

// parsujPole czyta jedno pole: gwiazdke, liczbe, zakres, liste albo krok.
func parsujPole(pole string, min, max int) (map[int]bool, error) {
	dozwolone := map[int]bool{}
	for _, czesc := range strings.Split(pole, ",") {
		krok := 1
		if index := strings.Index(czesc, "/"); index >= 0 {
			wartosc, err := strconv.Atoi(czesc[index+1:])
			if err != nil || wartosc <= 0 {
				return nil, fmt.Errorf("nieprawidlowy krok %q", czesc[index+1:])
			}
			krok = wartosc
			czesc = czesc[:index]
		}

		od, do_ := min, max
		switch {
		case czesc == "*" || czesc == "":
		case strings.Contains(czesc, "-"):
			granice := strings.SplitN(czesc, "-", 2)
			poczatek, err1 := strconv.Atoi(granice[0])
			koniec, err2 := strconv.Atoi(granice[1])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("nieprawidlowy zakres %q", czesc)
			}
			od, do_ = poczatek, koniec
		default:
			wartosc, err := strconv.Atoi(czesc)
			if err != nil {
				return nil, fmt.Errorf("nieprawidlowa wartosc %q", czesc)
			}
			od, do_ = wartosc, wartosc
		}
		if od < min || do_ > max || od > do_ {
			return nil, fmt.Errorf("wartosc poza zakresem %d-%d", min, max)
		}
		for wartosc := od; wartosc <= do_; wartosc += krok {
			dozwolone[wartosc] = true
		}
	}
	if len(dozwolone) == 0 {
		return nil, fmt.Errorf("pole nie dopuszcza zadnej wartosci")
	}
	return dozwolone, nil
}

// maksymalneSzukanie ogranicza wyszukiwanie nastepnego uruchomienia.
// Wyrazenie w rodzaju "0 0 30 2 *" nigdy nie pasuje - zamiast szukac
// w nieskonczonosc, mowimy wprost, ze terminu nie ma.
const maksymalneSzukanie = 4 * 365 * 24 * time.Hour

// NastepneUruchomienia zwraca kolejne terminy po podanej chwili.
//
// Terminy sa liczone na hoscie i w jego strefie czasowej: panel nie zna ani
// jednej, ani drugiej, a "03:00" bez strefy nie znaczy nic konkretnego.
func (w Wyrazenie) NastepneUruchomienia(po time.Time, ile int) []time.Time {
	if ile <= 0 {
		ile = 1
	}
	var wyniki []time.Time
	chwila := po.Truncate(time.Minute)
	koniec := po.Add(maksymalneSzukanie)

	for len(wyniki) < ile && chwila.Before(koniec) {
		chwila = chwila.Add(time.Minute)
		if w.pasuje(chwila) {
			wyniki = append(wyniki, chwila)
		}
	}
	return wyniki
}

// pasuje sprawdza, czy chwila spelnia wyrazenie.
func (w Wyrazenie) pasuje(chwila time.Time) bool {
	if !w.dozwolone[0][chwila.Minute()] || !w.dozwolone[1][chwila.Hour()] {
		return false
	}
	if !w.dozwolone[3][int(chwila.Month())] {
		return false
	}

	dzienMiesiaca := w.dozwolone[2][chwila.Day()]
	dzienTygodnia := w.dozwolone[4][int(chwila.Weekday())]

	// Cron traktuje oba pola dni inaczej niz reszte: gdy oba sa ograniczone,
	// zadanie uruchamia sie, gdy pasuje ktorekolwiek. Traktowanie ich jak
	// koniunkcji pomijaloby wiekszosc terminow.
	switch {
	case w.dzienMiesiacaGwiazdka && w.dzienTygodniaGwiazdka:
		return true
	case w.dzienMiesiacaGwiazdka:
		return dzienTygodnia
	case w.dzienTygodniaGwiazdka:
		return dzienMiesiaca
	default:
		return dzienMiesiaca || dzienTygodnia
	}
}
