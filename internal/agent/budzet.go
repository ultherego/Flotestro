package agent

import (
	"context"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// Klasy zasobu hosta. Zadania jednej klasy konkuruja ze soba, a nie z calym
// zarzadzaniem hostem.
const (
	// KlasaPakiety obejmuje operacje menedzera pakietow. Limit jeden nie jest
	// ostroznoscia: dwa apt naraz przebudowuja te sama pamiec podreczna i
	// razem trwaja dluzej niz jeden po drugim.
	KlasaPakiety = "packages"
	// KlasaOgolna to reszta: operacje na jednostkach, odczyt dziennika, stan.
	KlasaOgolna = "general"
)

// budzet pilnuje, ile zadan danej klasy moze dzialac naraz.
//
// Wspolna pula dla wszystkich zadan miala wade widoczna z panelu: dwa dlugie
// odczyty pakietow zajmowaly oba miejsca, a operacja trwajaca milisekundy
// czekala za nimi minute. Host wygladal wtedy na zawieszony, choc pracowal.
type budzet struct {
	miejsca map[string]chan struct{}
}

func nowyBudzet(ogolne int) *budzet {
	if ogolne <= 0 {
		ogolne = 2
	}
	return &budzet{miejsca: map[string]chan struct{}{
		KlasaPakiety: make(chan struct{}, 1),
		KlasaOgolna:  make(chan struct{}, ogolne),
	}}
}

// zajmij czeka na miejsce w klasie zadania. Zwrocona funkcja je zwalnia;
// nil oznacza koniec sesji przed uzyskaniem miejsca.
func (b *budzet) zajmij(ctx context.Context, klasa string) func() {
	miejsca, ok := b.miejsca[klasa]
	if !ok {
		miejsca = b.miejsca[KlasaOgolna]
	}
	select {
	case miejsca <- struct{}{}:
		return func() { <-miejsca }
	case <-ctx.Done():
		return nil
	}
}

// klasaZadania rozpoznaje klase zasobu po typie operacji. Nieznana operacja
// trafia do klasy ogolnej: nieznany koszt nie moze blokowac calej klasy
// pakietowej, a i tak przejdzie przez limit ogolny.
func klasaZadania(task *agentv1.TaskEnvelope) string {
	switch task.GetAction().(type) {
	case *agentv1.TaskEnvelope_PackagePlan,
		*agentv1.TaskEnvelope_PackageUpgrade,
		*agentv1.TaskEnvelope_PackagesRepair:
		return KlasaPakiety
	default:
		return KlasaOgolna
	}
}
