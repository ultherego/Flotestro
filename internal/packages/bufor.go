package packages

import (
	"strings"
	"sync"
)

// maksymalneWyjscie ogranicza zapamietane wyjscie narzedzia. Transakcja na
// kilkuset pakietach wypisuje megabajty; do wyniku i tak trafia tylko opis
// bledu, wiec reszta jest kosztem bez pozytku.
const maksymalneWyjscie = 256 << 10

// limitowanyBufor zbiera wyjscie do limitu i pamieta, ze je urwal.
//
// Urwanie liczy sie od poczatku, nie od konca: przyczyna bledu jest zwykle
// przy koncu wyjscia, wiec to poczatek mozna poswiecic.
type limitowanyBufor struct {
	mu      sync.Mutex
	linie   []string
	rozmiar int
	limit   int
	urwany  bool
}

func (b *limitowanyBufor) WriteLine(linia string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.linie = append(b.linie, linia)
	b.rozmiar += len(linia) + 1
	for b.rozmiar > b.limit && len(b.linie) > 1 {
		b.rozmiar -= len(b.linie[0]) + 1
		b.linie = b.linie[1:]
		b.urwany = true
	}
}

func (b *limitowanyBufor) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	tekst := strings.Join(b.linie, "\n")
	if b.urwany {
		return "[poczatek wyjscia pominiety]\n" + tekst
	}
	return tekst
}
