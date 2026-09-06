package vuln

import (
	"testing"
	"time"
)

// TestPrzeliczamyTylkoZmienioneWejscie pilnuje, ze przeglad floty nie
// przepisuje ocen, ktore i tak wyszlyby identyczne - i ze nie przegapia
// zadnej zmiany, ktora wynik zmienia.
func TestPrzeliczamyTylkoZmienioneWejscie(t *testing.T) {
	harmonogram := &Harmonogram{ustawienia: Domyslne()}
	snapshot := Snapshot{
		Provider: "debian", Digest: "s1", Releases: []string{"trixie"},
		FetchedAt: teraz.Add(-time.Hour),
	}
	wejscie := Wejscie{
		HostID: "host-1", Distribution: "debian", Release: "trixie",
		InventoryDigest: "lista-1", AdvisoryDigest: "",
	}
	oceniony := teraz.Add(-time.Minute)
	poprzedni := StanHosta{
		HostID: "host-1", Distribution: "debian", Release: "trixie",
		Provider: "debian", SnapshotDigest: "s1", InventoryDigest: "lista-1",
		EvaluatedAt: &oceniony,
	}

	if harmonogram.doPrzeliczenia(poprzedni, wejscie, snapshot, teraz) {
		t.Fatal("przeliczamy ocene, ktorej wejscie sie nie zmienilo")
	}

	// Kazde z trzech zrodel osobno musi wymuszac przeliczenie: feed, lista
	// pakietow i zestaw ustalen zmieniaja sie niezaleznie od siebie.
	zmiany := map[string]func(*StanHosta, *Wejscie, *Snapshot){
		"inny snapshot feedu": func(_ *StanHosta, _ *Wejscie, s *Snapshot) { s.Digest = "s2" },
		"inna lista pakietow": func(_ *StanHosta, w *Wejscie, _ *Snapshot) { w.InventoryDigest = "lista-2" },
		"inne ustalenia hosta": func(_ *StanHosta, w *Wejscie, _ *Snapshot) {
			w.AdvisoryDigest = "u2"
		},
		"inne wydanie": func(_ *StanHosta, w *Wejscie, s *Snapshot) {
			w.Release = "forky"
			s.Releases = []string{"forky"}
		},
		"host nigdy nieoceniony": func(p *StanHosta, _ *Wejscie, _ *Snapshot) { p.EvaluatedAt = nil },
		"ocena starsza niz wiek feedu": func(p *StanHosta, _ *Wejscie, _ *Snapshot) {
			dawno := teraz.Add(-48 * time.Hour)
			p.EvaluatedAt = &dawno
		},
		"lista rozjechala sie z hostem": func(_ *StanHosta, w *Wejscie, _ *Snapshot) {
			w.ListaNieaktualna = true
		},
	}
	for nazwa, zmien := range zmiany {
		p, w, s := poprzedni, wejscie, snapshot
		zmien(&p, &w, &s)
		if !harmonogram.doPrzeliczenia(p, w, s, teraz) {
			t.Errorf("%s: ocena nie zostala przeliczona", nazwa)
		}
	}

	// Sam uplyw czasu tez zmienia wynik: feed swiezy o poranku bywa
	// nieswiezy wieczorem, a to jest inna odpowiedz przy tych samych
	// odciskach.
	pozniej := teraz.Add(12 * time.Hour)
	if !harmonogram.doPrzeliczenia(poprzedni, wejscie, snapshot, pozniej) {
		t.Error("feed, ktory zdazyl sie zestarzec, nie wymusil przeliczenia")
	}
}
