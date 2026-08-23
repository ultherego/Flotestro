package schedules

import (
	"testing"
	"time"
)

// Wyrazenie, ktorego panel nie rozumie, nie moze zostac zapisane: wpis, ktory
// nigdy sie nie uruchomi, jest gorszy niz jego brak, bo wyglada na dzialajacy.
func TestNieprawidloweWyrazeniaSaOdrzucane(t *testing.T) {
	zle := []string{
		"", "* * * *", "* * * * * *",
		"60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8",
		"a * * * *", "*/0 * * * *", "5-1 * * * *", "1-2-3 * * * *",
		"@reboot", "@nieznany",
	}
	for _, wyrazenie := range zle {
		if _, err := ParsujWyrazenie(wyrazenie); err == nil {
			t.Errorf("przyjeto wyrazenie %q", wyrazenie)
		}
	}
}

// Formaty, ktore cron rozumie, musza przejsc - inaczej panel odmawia pracy,
// ktora host wykonalby bez problemu.
func TestPoprawneWyrazeniaSaPrzyjmowane(t *testing.T) {
	dobre := []string{
		"* * * * *", "0 3 * * *", "*/15 * * * *", "0 0 1 1 *",
		"0 9-17 * * 1-5", "30 2,14 * * *", "0 0 * * 0", "0 0 * * 7",
		"@daily", "@hourly", "@weekly",
	}
	for _, wyrazenie := range dobre {
		if _, err := ParsujWyrazenie(wyrazenie); err != nil {
			t.Errorf("odrzucono wyrazenie %q: %v", wyrazenie, err)
		}
	}
}

// Kreator harmonogramu pokazuje kolejne wykonania, wiec musza byc policzone
// poprawnie, a nie w przyblizeniu.
func TestNastepneUruchomieniaSaDokladne(t *testing.T) {
	wyrazenie, err := ParsujWyrazenie("0 3 * * *")
	if err != nil {
		t.Fatal(err)
	}
	po := time.Date(2026, 8, 23, 15, 30, 0, 0, time.UTC)
	terminy := wyrazenie.NastepneUruchomienia(po, 3)

	oczekiwane := []time.Time{
		time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 25, 3, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 26, 3, 0, 0, 0, time.UTC),
	}
	if len(terminy) != 3 {
		t.Fatalf("terminow = %d: %v", len(terminy), terminy)
	}
	for i, termin := range terminy {
		if !termin.Equal(oczekiwane[i]) {
			t.Errorf("termin %d = %s, oczekiwano %s", i, termin, oczekiwane[i])
		}
	}
}

// Krok co 15 minut ma dawac cztery terminy w godzinie, a nie jeden.
func TestKrokDajeWszystkieTerminy(t *testing.T) {
	wyrazenie, err := ParsujWyrazenie("*/15 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	po := time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)
	terminy := wyrazenie.NastepneUruchomienia(po, 4)

	for i, oczekiwana := range []int{15, 30, 45, 0} {
		if terminy[i].Minute() != oczekiwana {
			t.Errorf("termin %d = %s, oczekiwano minuty %d", i, terminy[i], oczekiwana)
		}
	}
}

// Cron traktuje oba pola dni inaczej niz reszte: gdy oba sa ograniczone,
// zadanie uruchamia sie, gdy pasuje ktorekolwiek. Traktowanie ich jak
// koniunkcji pomijaloby wiekszosc terminow.
func TestDniSaSumowaneANiePrzecinane(t *testing.T) {
	// Pierwszy dzien miesiaca albo poniedzialek.
	wyrazenie, err := ParsujWyrazenie("0 0 1 * 1")
	if err != nil {
		t.Fatal(err)
	}
	// 2026-08-23 to niedziela; 24 sierpnia to poniedzialek, 1 wrzesnia wtorek.
	po := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	terminy := wyrazenie.NastepneUruchomienia(po, 2)

	if terminy[0].Day() != 24 {
		t.Errorf("pierwszy termin = %s, oczekiwano poniedzialku 24 sierpnia", terminy[0])
	}
	if terminy[1].Day() != 31 {
		t.Errorf("drugi termin = %s, oczekiwano poniedzialku 31 sierpnia", terminy[1])
	}
}

// Niedziela ma w cronie dwa numery i oba opisuja ten sam dzien.
func TestNiedzielaMaDwaNumery(t *testing.T) {
	zero, err := ParsujWyrazenie("0 0 * * 0")
	if err != nil {
		t.Fatal(err)
	}
	siedem, err := ParsujWyrazenie("0 0 * * 7")
	if err != nil {
		t.Fatal(err)
	}
	po := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	if !zero.NastepneUruchomienia(po, 1)[0].Equal(siedem.NastepneUruchomienia(po, 1)[0]) {
		t.Error("0 i 7 opisuja rozne dni tygodnia")
	}
}

// Wyrazenie, ktore nigdy nie pasuje, nie moze zawiesic wyszukiwania.
func TestWyrazenieBezTerminuNieZawiesza(t *testing.T) {
	// 30 lutego nie istnieje.
	wyrazenie, err := ParsujWyrazenie("0 0 30 2 *")
	if err != nil {
		t.Fatal(err)
	}
	if terminy := wyrazenie.NastepneUruchomienia(time.Now(), 1); len(terminy) != 0 {
		t.Errorf("znaleziono termin dla niemozliwej daty: %v", terminy)
	}
}
