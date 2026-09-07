package agent

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
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

	mu sync.Mutex
	// czekajacy zbiera prosby oczekujace na najblizsze zebranie. Dwie prosby
	// zlozone w tej samej chwili nie moga uruchomic dwoch odczytow: host
	// zaplacilby dwa razy za ten sam obraz.
	czekajacy []chan Odswiezenie
	// biezacy sa prosbami objetymi zebraniem, ktore juz trwa. Prosba, ktora
	// przyszla po jego starcie, zostaje w czekajacych i doczeka nastepnego:
	// trwajacy odczyt nie obejmuje modulu zamowionego po jego rozpoczeciu,
	// wiec nie wolno jej nim rozliczyc.
	biezacy []chan Odswiezenie
	// zakres zbiera moduly zamowione przez czekajacych. Zamowienie o caly
	// inwentarz pochlania kazde czesciowe.
	zakres map[string]bool
	pelny  bool
}

// Odswiezenie jest wynikiem zebrania inwentarza na zadanie.
type Odswiezenie struct {
	// Rewizja jest rewizja obrazu, ktory powstal z tego zebrania.
	Rewizja string
	// Zmieniona mowi, czy obraz rozni sie od poprzedniego. Brak zmiany nie
	// jest bledem: host, ktory sie nie zmienil, jest prawdziwa odpowiedzia.
	Zmieniona bool
	// Moduly wylicza to, co naprawde zostalo odczytane.
	Moduly []string
	Blad   error
}

// ErrSesjaZakonczona oznacza, ze sesja skonczyla sie przed odswiezeniem.
var ErrSesjaZakonczona = errors.New("session_ended")

func nowyKolektor() *kolektor {
	return &kolektor{zadania: make(chan struct{}, 1), zakres: map[string]bool{}}
}

// zazadaj zamawia zebranie calego inwentarza i nigdy nie blokuje wolajacego.
func (k *kolektor) zazadaj() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dolaczZakres(nil)
	k.zamow()
}

// odswiez zamawia zebranie i czeka na jego wynik.
//
// To jest droga operacji inventory.refresh: zadanie konczy sie dopiero wtedy,
// gdy nowy obraz powstal i zostal wyslany, a nie w chwili przyjecia zlecenia.
func (k *kolektor) odswiez(ctx context.Context, moduly []string) Odswiezenie {
	odpowiedz := make(chan Odswiezenie, 1)

	// Zgloszenie sie i zamowienie ida pod jednym zamkiem. Inaczej zebranie
	// mogloby ruszyc miedzy nimi i prosba czekalaby na odczyt, ktory jej
	// modulu nie obejmuje.
	k.mu.Lock()
	k.czekajacy = append(k.czekajacy, odpowiedz)
	k.dolaczZakres(moduly)
	k.zamow()
	k.mu.Unlock()

	select {
	case <-ctx.Done():
		return Odswiezenie{Blad: ctx.Err()}
	case wynik := <-odpowiedz:
		return wynik
	}
}

// zamow stawia zamowienie w kolejce zebran. Pelna kolejka nie jest strata:
// zamowienie, ktore w niej stoi, nie zostalo jeszcze podjete, wiec obejmie
// takze zakres dopisany przed chwila. Wymaga trzymanego zamka.
func (k *kolektor) zamow() {
	select {
	case k.zadania <- struct{}{}:
	default:
	}
}

// dolaczZakres dopisuje moduly do zakresu najblizszego zebrania. Wymaga
// trzymanego zamka.
func (k *kolektor) dolaczZakres(moduly []string) {
	if len(moduly) == 0 {
		// Caly inwentarz pochlania kazde zamowienie czesciowe.
		k.pelny = true
		return
	}
	for _, nazwa := range moduly {
		k.zakres[nazwa] = true
	}
}

// wezZakres otwiera zebranie: przejmuje czekajacych i ich zakres.
//
// Zwraca false, gdy nie ma czego zbierac - tak konczy sie zamowienie, ktore
// zdazylo trafic do juz otwartego zebrania.
func (k *kolektor) wezZakres() ([]string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.pelny && len(k.zakres) == 0 && len(k.czekajacy) == 0 {
		return nil, false
	}
	k.biezacy, k.czekajacy = k.czekajacy, nil
	if k.pelny || len(k.zakres) == 0 {
		k.pelny = false
		return nil, true
	}
	moduly := make([]string, 0, len(k.zakres))
	for nazwa := range k.zakres {
		moduly = append(moduly, nazwa)
	}
	clear(k.zakres)
	slices.Sort(moduly)
	return moduly, true
}

// rozeslij oddaje wynik prosbom objetym zebraniem i zamyka je.
func (k *kolektor) rozeslij(wynik Odswiezenie) {
	k.mu.Lock()
	biezacy := k.biezacy
	k.biezacy = nil
	k.mu.Unlock()
	for _, odpowiedz := range biezacy {
		odpowiedz <- wynik
	}
}

// zakoncz odprawia wszystkich czekajacych, takze tych spoza biezacego
// zebrania: po koncu sesji nikt juz ich nie obsluzy.
func (k *kolektor) zakoncz(blad error) {
	k.mu.Lock()
	czekajacy := append(k.biezacy, k.czekajacy...)
	k.biezacy, k.czekajacy = nil, nil
	k.mu.Unlock()
	for _, odpowiedz := range czekajacy {
		odpowiedz <- Odswiezenie{Blad: blad}
	}
}

// pracuj obsluguje zamowienia do konca kontekstu. Wynik nieudanego zebrania
// nie konczy pracy: chwilowo niedostepny odczyt nie jest powodem do zerwania
// sesji. Blad wysylki konczy, bo oznacza zerwany strumien.
func (k *kolektor) pracuj(ctx context.Context, zbierz func(context.Context, []string) (Facts, error),
	przyjmij func(Facts) (Odswiezenie, error), log *slog.Logger) error {
	defer k.zakoncz(ErrSesjaZakonczona)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-k.zadania:
			moduly, jest := k.wezZakres()
			if !jest {
				continue
			}
			fresh, err := zbierz(ctx, moduly)
			if err != nil {
				log.Error("nie zebrano inventory", "err", err, "moduly", moduly)
				k.rozeslij(Odswiezenie{Blad: err, Moduly: moduly})
				continue
			}
			wynik, err := przyjmij(fresh)
			if err != nil {
				k.rozeslij(Odswiezenie{Blad: err, Moduly: moduly})
				return err
			}
			wynik.Moduly = moduly
			k.rozeslij(wynik)
		}
	}
}
