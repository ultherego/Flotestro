package agent

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Zamowienie zebrania nie moze czekac na jego wynik. Petla odbioru wiadomosci
// zamawia inventory i musi natychmiast wrocic po kolejne zadania - inaczej
// wolny odczyt zatrzymuje zarzadzanie hostem.
func TestZamowienieZebraniaNieBlokuje(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	trwa := make(chan struct{})
	zwolnij := make(chan struct{})
	var pierwsze sync.Once
	k := nowyKolektor()
	// Tylko pierwsze zebranie ma trwac: drugie jest tym zlozonym z zamowien
	// zlozonych w trakcie i konczy sie od razu.
	go k.pracuj(ctx, func(context.Context) (Facts, error) {
		pierwsze.Do(func() {
			close(trwa)
			<-zwolnij
		})
		return Facts{}, nil
	}, func(Facts) error { return nil }, cichy())

	k.zazadaj()
	<-trwa // zebranie sie zaczelo i trwa

	zamowione := make(chan struct{})
	go func() { k.zazadaj(); close(zamowione) }()
	select {
	case <-zamowione:
	case <-time.After(2 * time.Second):
		t.Fatal("zamowienie zebrania zablokowalo sie na trwajacym odczycie")
	}
	close(zwolnij)
}

// Zamowienia zlozone w trakcie trwajacego zebrania skladaja sie w jedno:
// kazde z nich zwrociloby ten sam stan hosta.
func TestZamowieniaSieSkladaja(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	trwa := make(chan struct{})
	zwolnij := make(chan struct{})
	var zebrania atomic.Int32
	gotowe := make(chan struct{}, 8)

	k := nowyKolektor()
	go k.pracuj(ctx, func(context.Context) (Facts, error) {
		if zebrania.Add(1) == 1 {
			close(trwa)
			<-zwolnij
		}
		return Facts{}, nil
	}, func(Facts) error { gotowe <- struct{}{}; return nil }, cichy())

	k.zazadaj()
	<-trwa
	for i := 0; i < 5; i++ {
		k.zazadaj()
	}
	close(zwolnij)

	// Pierwsze zebranie plus dokladnie jedno zlozone z pieciu zamowien.
	<-gotowe
	<-gotowe
	select {
	case <-gotowe:
		t.Fatalf("zebran = %d, oczekiwano dwoch", zebrania.Load())
	case <-time.After(300 * time.Millisecond):
	}
}

// Nieudany odczyt nie konczy pracy kolektora: chwilowo niedostepne zrodlo nie
// jest powodem do zerwania sesji agenta.
func TestNieudaneZebranieNieKonczyPracy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var proby atomic.Int32
	gotowe := make(chan struct{}, 2)
	k := nowyKolektor()
	go k.pracuj(ctx, func(context.Context) (Facts, error) {
		if proby.Add(1) == 1 {
			return Facts{}, context.DeadlineExceeded
		}
		return Facts{}, nil
	}, func(Facts) error { gotowe <- struct{}{}; return nil }, cichy())

	k.zazadaj()
	time.Sleep(50 * time.Millisecond)
	k.zazadaj()

	select {
	case <-gotowe:
	case <-time.After(2 * time.Second):
		t.Fatal("kolektor nie obsluzyl zamowienia po nieudanym odczycie")
	}
}

func cichy() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
