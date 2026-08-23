package agent

import (
	"context"
	"log/slog"
)

// kolektor uruchamia zbieranie inventory poza petla odbioru wiadomosci.
//
// Zbieranie jest ciezkie: uruchamia podprocesy i potrafi czekac na blokade
// menedzera pakietow. Gdy odbywalo sie wewnatrz petli odbioru, host na czas
// odczytu przestawal przyjmowac zadania - z panelu wygladalo to jak zawieszona
// operacja, a nie jak trwajacy odczyt.
type kolektor struct {
	// Pojemnosc jeden sklada zadania: kolejne zebranie w trakcie trwajacego
	// zwrociloby ten sam stan, wiec wystarczy jedno w zapasie.
	zadania chan struct{}
}

func nowyKolektor() *kolektor {
	return &kolektor{zadania: make(chan struct{}, 1)}
}

// zazadaj zamawia zebranie inventory i nigdy nie blokuje wolajacego.
func (k *kolektor) zazadaj() {
	select {
	case k.zadania <- struct{}{}:
	default:
	}
}

// pracuj obsluguje zamowienia do konca kontekstu. Wynik nieudanego zebrania
// nie konczy pracy: chwilowo niedostepny odczyt nie jest powodem do zerwania
// sesji. Blad wysylki konczy, bo oznacza zerwany strumien.
func (k *kolektor) pracuj(ctx context.Context, zbierz func(context.Context) (Facts, error),
	przyjmij func(Facts) error, log *slog.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-k.zadania:
			fresh, err := zbierz(ctx)
			if err != nil {
				log.Error("nie zebrano inventory", "err", err)
				continue
			}
			if err := przyjmij(fresh); err != nil {
				return err
			}
		}
	}
}
