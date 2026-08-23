package agent

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// Sedno podzialu na klasy: dlugi odczyt pakietow nie moze zatrzymac operacji,
// ktore trwaja milisekundy. Bez tego host wyglada z panelu na zawieszony.
func TestOperacjePakietoweNieBlokujaReszty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := nowyBudzet(2)

	// Klasa pakietowa jest wysycona - trwa transakcja.
	zajete := b.zajmij(ctx, KlasaPakiety)
	if zajete == nil {
		t.Fatal("nie uzyskano miejsca w klasie pakietowej")
	}
	defer zajete()

	wolne := make(chan struct{})
	go func() {
		if zwolnij := b.zajmij(ctx, KlasaOgolna); zwolnij != nil {
			zwolnij()
		}
		close(wolne)
	}()
	select {
	case <-wolne:
	case <-time.After(2 * time.Second):
		t.Fatal("operacja ogolna czekala na zakonczenie operacji pakietowej")
	}
}

// Dwa apt naraz przebudowuja te sama pamiec podreczna i razem trwaja dluzej
// niz jeden po drugim, wiec klasa pakietowa ma dokladnie jedno miejsce.
func TestDrugaOperacjaPakietowaCzeka(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := nowyBudzet(4)

	pierwsza := b.zajmij(ctx, KlasaPakiety)
	if pierwsza == nil {
		t.Fatal("nie uzyskano pierwszego miejsca")
	}

	weszla := make(chan struct{})
	go func() {
		if zwolnij := b.zajmij(ctx, KlasaPakiety); zwolnij != nil {
			defer zwolnij()
			close(weszla)
		}
	}()
	select {
	case <-weszla:
		t.Fatal("dwie operacje pakietowe weszly naraz")
	case <-time.After(200 * time.Millisecond):
	}

	pierwsza()
	select {
	case <-weszla:
	case <-time.After(2 * time.Second):
		t.Fatal("zwolnione miejsce nie zostalo przejete")
	}
}

// Koniec sesji nie moze zostawic zadania czekajacego na miejsce w nieskonczonosc.
func TestKoniecSesjiKonczyOczekiwanie(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := nowyBudzet(1)
	zajete := b.zajmij(ctx, KlasaPakiety)
	if zajete == nil {
		t.Fatal("nie uzyskano miejsca")
	}
	defer zajete()

	cancel()
	if zwolnij := b.zajmij(ctx, KlasaPakiety); zwolnij != nil {
		t.Fatal("uzyskano miejsce po zakonczeniu sesji")
	}
}

// Klasa zadania wynika z typu operacji, a nie z nazwy przekazanej z zewnatrz.
func TestKlasaZadaniaWynikaZTypuOperacji(t *testing.T) {
	przypadki := []struct {
		nazwa   string
		zadanie *agentv1.TaskEnvelope
		klasa   string
	}{
		{"plan", &agentv1.TaskEnvelope{Action: &agentv1.TaskEnvelope_PackagePlan{}}, KlasaPakiety},
		{"transakcja", &agentv1.TaskEnvelope{Action: &agentv1.TaskEnvelope_PackageUpgrade{}}, KlasaPakiety},
		{"naprawa", &agentv1.TaskEnvelope{Action: &agentv1.TaskEnvelope_PackagesRepair{}}, KlasaPakiety},
		{"jednostka", &agentv1.TaskEnvelope{Action: &agentv1.TaskEnvelope_UnitAction{}}, KlasaOgolna},
		{"dziennik", &agentv1.TaskEnvelope{Action: &agentv1.TaskEnvelope_ReadJournal{}}, KlasaOgolna},
		{"bez operacji", &agentv1.TaskEnvelope{}, KlasaOgolna},
	}
	for _, przypadek := range przypadki {
		if got := klasaZadania(przypadek.zadanie); got != przypadek.klasa {
			t.Errorf("%s: klasa = %q, oczekiwano %q", przypadek.nazwa, got, przypadek.klasa)
		}
	}
}
