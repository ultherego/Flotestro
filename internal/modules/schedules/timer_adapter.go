package schedules

import (
	"strings"
	"time"
)

// CzytajTimery sklada harmonogramy z wyjscia systemctl.
//
// Timery i cron sa dwoma mechanizmami tego samego: operator chce zobaczyc
// jedna tabele zadan cyklicznych, a nie dwie listy, ktore trzeba w glowie
// laczyc. Panel nie zaklada timerow - zarzadzane wpisy trafiaja do crona,
// bo tam jeden wpis to jeden plik, a timer wymaga dwoch jednostek i ich
// wzajemnej spojnosci.
func CzytajTimery(listaTimerow, listaJednostek, kalendarze string) []Schedule {
	nastepne := parsujListeTimerow(listaTimerow)
	stany := parsujStanyJednostek(listaJednostek)
	wyrazenia := parsujKalendarze(kalendarze)

	var wpisy []Schedule
	for nazwa, termin := range nastepne {
		wpis := Schedule{
			ID:     nazwa,
			Kind:   KindTimer,
			Source: SourceManual,
			// Timer aktywny to taki, ktory jest zaladowany i wlaczony.
			Enabled: stany[nazwa] != "" && stany[nazwa] != "inactive",
			// Timer bez OnCalendar chodzi wzgledem zdarzenia (OnBootSec,
			// OnUnitActiveSec). Nie znamy jego wyrazenia, wiec zostawiamy
			// puste zamiast wpisywac cokolwiek.
			Expression: wyrazenia[nazwa],
			// Timer nie uruchamia polecenia, tylko jednostke. To ona ma
			// ExecStart, ktorego ten modul nie czyta.
			CommandLine: strings.TrimSuffix(nazwa, ".timer") + ".service",
		}
		if !termin.IsZero() {
			kopia := termin
			wpis.NextRun = &kopia
		}
		wpisy = append(wpisy, wpis)
	}
	return wpisy
}

// parsujListeTimerow czyta wyjscie "systemctl list-timers --all".
//
// Kolumny sa oddzielone spacjami, a data zawiera spacje, wiec nazwa timera
// jest szukana po sufiksie, a nie po pozycji: format tej listy zmienial sie
// miedzy wersjami systemd.
func parsujListeTimerow(wyjscie string) map[string]time.Time {
	wynik := map[string]time.Time{}
	for _, linia := range strings.Split(wyjscie, "\n") {
		pola := strings.Fields(linia)
		var nazwa string
		var indeks int
		for i, pole := range pola {
			if strings.HasSuffix(pole, ".timer") {
				nazwa, indeks = pole, i
				break
			}
		}
		if nazwa == "" {
			continue
		}
		wynik[nazwa] = parsujDateTimera(pola[:indeks])
	}
	return wynik
}

// parsujDateTimera czyta pierwsza date z poczatku wiersza. Wartosc "-"
// oznacza timer bez zaplanowanego terminu i zostaje pustym czasem, a nie
// data zerowa udajaca konkretna chwile.
func parsujDateTimera(pola []string) time.Time {
	if len(pola) < 2 {
		return time.Time{}
	}
	// Format: "Sun 2026-08-23 03:10:00 UTC" - bierzemy date i godzine.
	for i := 0; i+1 < len(pola); i++ {
		if len(pola[i]) == 10 && strings.Count(pola[i], "-") == 2 {
			termin, err := time.Parse("2006-01-02 15:04:05", pola[i]+" "+pola[i+1])
			if err != nil {
				return time.Time{}
			}
			return termin
		}
	}
	return time.Time{}
}

// parsujStanyJednostek czyta wyjscie "systemctl list-units --type=timer".
func parsujStanyJednostek(wyjscie string) map[string]string {
	stany := map[string]string{}
	for _, linia := range strings.Split(wyjscie, "\n") {
		pola := strings.Fields(linia)
		if len(pola) < 3 || !strings.HasSuffix(pola[0], ".timer") {
			continue
		}
		stany[pola[0]] = pola[2]
	}
	return stany
}

// parsujKalendarze czyta wyjscie "systemctl show --property=Id
// --property=TimersCalendar '*.timer'".
//
// Wyrazenie OnCalendar jest tym, co operator zna z pliku jednostki. Bez niego
// wiersz timera mowilby tylko "kiedys" - a nastepne uruchomienie samo w sobie
// nie tlumaczy, co sie za nim kryje.
//
// Rekordy sa rozdzielone pusta linia, a kolejnosc wlasciwosci w rekordzie nie
// jest kolejnoscia pytania: systemd potrafi wypisac TimersCalendar przed Id.
// Czytanie linia po linii przypisaloby wiec kalendarz poprzedniemu timerowi.
func parsujKalendarze(wyjscie string) map[string]string {
	wynik := map[string]string{}
	for _, rekord := range strings.Split(wyjscie, "\n\n") {
		nazwa, wyrazenie := "", ""
		for _, linia := range strings.Split(rekord, "\n") {
			linia = strings.TrimSpace(linia)
			switch {
			case strings.HasPrefix(linia, "Id="):
				nazwa = strings.TrimPrefix(linia, "Id=")
			case strings.HasPrefix(linia, "TimersCalendar="):
				wyrazenie = onCalendar(strings.TrimPrefix(linia, "TimersCalendar="))
			}
		}
		// Timer bez OnCalendar chodzi wzgledem zdarzenia (OnBootSec,
		// OnUnitActiveSec) i naprawde nie ma wyrazenia kalendarzowego.
		if nazwa != "" && wyrazenie != "" {
			wynik[nazwa] = wyrazenie
		}
	}
	return wynik
}

// onCalendar wyluskuje wyrazenie z "{ OnCalendar=... ; next_elapse=... }".
func onCalendar(tresc string) string {
	poczatek := strings.Index(tresc, "OnCalendar=")
	if poczatek < 0 {
		return ""
	}
	tresc = tresc[poczatek+len("OnCalendar="):]
	if koniec := strings.Index(tresc, " ; "); koniec >= 0 {
		tresc = tresc[:koniec]
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(tresc), "}"))
}
