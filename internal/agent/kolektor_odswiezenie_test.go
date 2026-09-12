package agent

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/opspec"
)

func cichyLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestOdswiezenieCzekaNaRewizje pilnuje wlasciwosci, dla ktorej ta operacja
// w ogole istnieje: zadanie konczy sie po powstaniu nowego obrazu, a nie
// w chwili przyjecia zlecenia.
func TestOdswiezenieCzekaNaRewizje(t *testing.T) {
	k := nowyKolektor()
	ctx, anuluj := context.WithCancel(context.Background())
	defer anuluj()

	zebrano := make(chan struct{})
	go func() {
		_ = k.pracuj(ctx, func(context.Context, []string) (Facts, error) {
			close(zebrano)
			return Facts{Hostname: "host"}, nil
		}, func(Facts) (Odswiezenie, error) {
			return Odswiezenie{Rewizja: "abc", Zmieniona: true}, nil
		}, cichyLog())
	}()

	wynik := k.odswiez(ctx, nil)
	select {
	case <-zebrano:
	default:
		t.Fatal("odswiezenie wrocilo bez zebrania inwentarza")
	}
	if wynik.Blad != nil {
		t.Fatalf("odswiezenie: %v", wynik.Blad)
	}
	if wynik.Rewizja != "abc" || !wynik.Zmieniona {
		t.Fatalf("wynik = %+v", wynik)
	}
}

// TestRownolegleProsbyDzielaOdczyt pilnuje deduplikacji: host nie moze placic
// za obraz raz na kazda osobe, ktora kliknela w tej samej chwili. Prosby,
// ktore przyszly po starcie odczytu, dziela sie jednym nastepnym - dlatego
// granica jest dwa, a nie tyle, ilu proszacych.
func TestRownolegleProsbyDzielaOdczyt(t *testing.T) {
	k := nowyKolektor()
	ctx, anuluj := context.WithCancel(context.Background())
	defer anuluj()

	var zebran atomic.Int32
	wolno := make(chan struct{})
	go func() {
		_ = k.pracuj(ctx, func(context.Context, []string) (Facts, error) {
			zebran.Add(1)
			<-wolno
			return Facts{Hostname: "host"}, nil
		}, func(Facts) (Odswiezenie, error) {
			return Odswiezenie{Rewizja: "abc", Zmieniona: true}, nil
		}, cichyLog())
	}()

	const ilu = 5
	var grupa sync.WaitGroup
	wyniki := make([]Odswiezenie, ilu)
	for i := 0; i < ilu; i++ {
		grupa.Add(1)
		go func(numer int) {
			defer grupa.Done()
			wyniki[numer] = k.odswiez(ctx, nil)
		}(i)
	}
	// Dajemy prosbom dojsc do kolektora, zanim odczyt sie skonczy.
	time.Sleep(50 * time.Millisecond)
	close(wolno)
	grupa.Wait()

	if odczytow := zebran.Load(); odczytow > 2 {
		t.Fatalf("liczba odczytow = %d przy %d prosbach", odczytow, ilu)
	}
	for i, wynik := range wyniki {
		if wynik.Blad != nil || wynik.Rewizja != "abc" {
			t.Fatalf("wynik %d = %+v", i, wynik)
		}
	}
}

// TestZakresCzesciowyDochodziDoOdczytu pilnuje, ze zamowione moduly trafiaja
// do zbierania, a nie gina po drodze.
func TestZakresCzesciowyDochodziDoOdczytu(t *testing.T) {
	k := nowyKolektor()
	ctx, anuluj := context.WithCancel(context.Background())
	defer anuluj()

	zakres := make(chan []string, 1)
	go func() {
		_ = k.pracuj(ctx, func(_ context.Context, moduly []string) (Facts, error) {
			zakres <- moduly
			return Facts{}, nil
		}, func(Facts) (Odswiezenie, error) {
			return Odswiezenie{Rewizja: "abc"}, nil
		}, cichyLog())
	}()

	wynik := k.odswiez(ctx, []string{ModulPackages})
	if wynik.Blad != nil {
		t.Fatal(wynik.Blad)
	}
	odczytane := <-zakres
	if len(odczytane) != 1 || odczytane[0] != ModulPackages {
		t.Fatalf("zakres odczytu = %v", odczytane)
	}
	if len(wynik.Moduly) != 1 || wynik.Moduly[0] != ModulPackages {
		t.Fatalf("zakres wyniku = %v", wynik.Moduly)
	}
}

// TestKoniecSesjiKonczyCzekanie pilnuje, ze zadanie nie wisi do limitu czasu,
// gdy sesja skonczy sie w trakcie zbierania.
func TestKoniecSesjiKonczyCzekanie(t *testing.T) {
	k := nowyKolektor()
	ctx, anuluj := context.WithCancel(context.Background())

	go func() {
		_ = k.pracuj(ctx, func(ctx context.Context, _ []string) (Facts, error) {
			<-ctx.Done()
			return Facts{}, ctx.Err()
		}, func(Facts) (Odswiezenie, error) {
			return Odswiezenie{}, nil
		}, cichyLog())
	}()

	gotowe := make(chan Odswiezenie, 1)
	go func() { gotowe <- k.odswiez(context.Background(), nil) }()
	time.Sleep(30 * time.Millisecond)
	anuluj()

	select {
	case wynik := <-gotowe:
		if wynik.Blad == nil {
			t.Fatal("odswiezenie po koncu sesji zwrocilo sukces")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("odswiezenie nie skonczylo sie po zamknieciu sesji")
	}
}

// TestProsbaWTrakcieZebraniaCzekaNaNastepne pilnuje najgrozniejszego skrotu
// deduplikacji: prosba o modul, ktora przyszla po starcie odczytu, nie moze
// zostac rozliczona obrazem, ktory tego modulu nie obejmuje.
func TestProsbaWTrakcieZebraniaCzekaNaNastepne(t *testing.T) {
	k := nowyKolektor()
	ctx, anuluj := context.WithCancel(context.Background())
	defer anuluj()

	zakresy := make(chan []string, 4)
	wolno := make(chan struct{})
	pierwszy := make(chan struct{})
	var numer atomic.Int32
	go func() {
		_ = k.pracuj(ctx, func(_ context.Context, moduly []string) (Facts, error) {
			zakresy <- moduly
			if numer.Add(1) == 1 {
				close(pierwszy)
				<-wolno
			}
			return Facts{}, nil
		}, func(Facts) (Odswiezenie, error) {
			return Odswiezenie{Rewizja: "abc"}, nil
		}, cichyLog())
	}()

	// Pierwszy odczyt obejmuje same uslugi i zatrzymuje sie w polowie.
	spozniony := make(chan Odswiezenie, 1)
	go func() { spozniony <- k.odswiez(ctx, []string{ModulServices}) }()
	<-pierwszy

	// Prosba o pakiety przychodzi juz po jego starcie.
	gotowe := make(chan Odswiezenie, 1)
	go func() { gotowe <- k.odswiez(ctx, []string{ModulPackages}) }()
	time.Sleep(50 * time.Millisecond)
	select {
	case wynik := <-gotowe:
		t.Fatalf("prosba o pakiety rozliczona odczytem uslug: %+v", wynik)
	default:
	}

	close(wolno)
	if wynik := <-spozniony; wynik.Blad != nil {
		t.Fatalf("odczyt uslug: %v", wynik.Blad)
	}
	select {
	case wynik := <-gotowe:
		if wynik.Blad != nil {
			t.Fatalf("odczyt pakietow: %v", wynik.Blad)
		}
		if len(wynik.Moduly) != 1 || wynik.Moduly[0] != ModulPackages {
			t.Fatalf("zakres wyniku = %v", wynik.Moduly)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prosba o pakiety nie doczekala sie drugiego odczytu")
	}

	if zakres := <-zakresy; len(zakres) != 1 || zakres[0] != ModulServices {
		t.Fatalf("pierwszy odczyt = %v", zakres)
	}
	if zakres := <-zakresy; len(zakres) != 1 || zakres[0] != ModulPackages {
		t.Fatalf("drugi odczyt = %v", zakres)
	}
}

// TestKazdyModulKontraktuMaZbieracz pilnuje, ze lista modulow, ktora panel
// przyjmuje w zleceniu, nie rozjedzie sie z tym, co agent umie odczytac.
// Rozjazd nie bylby widoczny: zadanie skonczyloby sie sukcesem, nie
// odswiezajac niczego.
func TestKazdyModulKontraktuMaZbieracz(t *testing.T) {
	for _, nazwa := range opspec.InventoryModules {
		if nazwa == ModulSystem {
			// Fakty podstawowe zbieraja sie zawsze, wiec nie maja wpisu
			// w mapie zbieraczy.
			continue
		}
		if _, ok := zbieraczeModulow[nazwa]; !ok {
			t.Errorf("panel przyjmuje modul %q, ktorego agent nie zbiera", nazwa)
		}
	}
	for nazwa := range zbieraczeModulow {
		if !opspec.IsInventoryModule(nazwa) {
			t.Errorf("agent zbiera modul %q, ktorego panel nie przyjmuje", nazwa)
		}
	}
	// Kolejnosc zbierania jest lista nazw, wiec literowka w niej dawalaby
	// zbieracz pusty - i wywrocilaby caly odczyt inwentarza.
	for _, nazwa := range KolejnoscModulow {
		if _, ok := zbieraczeModulow[nazwa]; !ok {
			t.Errorf("kolejnosc wymienia modul %q bez zbieracza", nazwa)
		}
	}
	if len(KolejnoscModulow) != len(zbieraczeModulow) {
		t.Errorf("kolejnosc ma %d modulow, zbieraczy jest %d",
			len(KolejnoscModulow), len(zbieraczeModulow))
	}
}
