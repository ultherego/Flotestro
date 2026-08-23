package agent

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/opspec"
)

// Limit tempa chroni lacze i baze powiadomien przed hostem, ktory wypisuje
// megabajty logow. Bez niego jeden host w petli bledow zalewalby panel.
func TestBudzetTempaOgraniczaPrzeplyw(t *testing.T) {
	budzet := nowyBudzetTempa(100)

	if !budzet.pozwala(80) {
		t.Fatal("pierwsze 80 bajtow nie zmiescilo sie w budzecie 100")
	}
	if !budzet.pozwala(20) {
		t.Fatal("kolejne 20 bajtow nie zmiescilo sie w budzecie")
	}
	if budzet.pozwala(50) {
		t.Error("budzet przepuscil dane ponad limit")
	}
}

// Budzet odbudowuje sie z czasem: podglad ma dzialac dalej, a nie zamknac
// sie po pierwszym wybuchu logow.
func TestBudzetTempaOdbudowujeSie(t *testing.T) {
	budzet := nowyBudzetTempa(1000)
	if !budzet.pozwala(1000) {
		t.Fatal("budzet nie przepuscil pelnej sekundy danych")
	}
	if budzet.pozwala(500) {
		t.Fatal("budzet przepuscil dane ponad limit")
	}

	// Po pol sekundzie wraca polowa budzetu.
	budzet.ostatnie = budzet.ostatnie.Add(-500 * time.Millisecond)
	if !budzet.pozwala(400) {
		t.Error("budzet nie odbudowal sie po uplywie czasu")
	}
}

// Budzet nie moze rosnac w nieskonczonosc podczas ciszy: host milczacy przez
// godzine nie dostaje prawa do wyslania godziny logow naraz.
func TestBudzetTempaNieKumulujeSieBezKonca(t *testing.T) {
	budzet := nowyBudzetTempa(100)
	budzet.ostatnie = budzet.ostatnie.Add(-time.Hour)
	if !budzet.pozwala(100) {
		t.Fatal("budzet nie przepuscil pelnej sekundy danych")
	}
	if budzet.pozwala(100) {
		t.Error("budzet skumulowal sie ponad limit sekundy")
	}
}

// Anulowanie dziala tam, gdzie zostalo zgloszone jako bezpieczne. Anulowanie
// zadania, ktore wlasnie sie skonczylo, nie jest bledem.
func TestAnulowanieDzialaTylkoDlaZarejestrowanych(t *testing.T) {
	tablica := nowaTablicaAnulowan()
	przerwane := false
	wyrejestruj := tablica.zarejestruj("zadanie-1", func() { przerwane = true })

	if !tablica.Anuluj("zadanie-1") {
		t.Error("nie znaleziono zarejestrowanego zadania")
	}
	if !przerwane {
		t.Error("zadanie nie zostalo przerwane")
	}
	if tablica.Anuluj("zadanie-nieznane") {
		t.Error("uznano nieznane zadanie za przerwane")
	}

	wyrejestruj()
	if tablica.Anuluj("zadanie-1") {
		t.Error("zadanie zostalo przerwane po wyrejestrowaniu")
	}
}

// Argumenty podgladu powstaja z pol typowanych, nigdy ze sklejonego ciagu.
func TestArgumentyPodgladuMajaLimity(t *testing.T) {
	priorytet := uint32(3)
	args := argumentyPodgladu(&opspec.JournalPayload{
		Unit: "cron.service", Lines: 0, MaxPriority: &priorytet,
	})

	czy := func(wartosc string) bool {
		for _, arg := range args {
			if arg == wartosc {
				return true
			}
		}
		return false
	}
	if !czy("--follow") || !czy("--lines") {
		t.Errorf("argumenty = %v", args)
	}
	// Zerowy backlog oznacza wartosc domyslna, a nie brak ograniczenia.
	if !czy("50") {
		t.Errorf("brak domyslnego limitu backlogu: %v", args)
	}
	if !czy("cron.service") || !czy("3") {
		t.Errorf("filtry nie trafily do argumentow: %v", args)
	}
}
