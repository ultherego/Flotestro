//go:build integration

package integration

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// wynikOdswiezenia jest szczegolem proby dla operacji inventory.refresh.
type wynikOdswiezenia struct {
	Kind     string   `json:"kind"`
	Revision string   `json:"revision"`
	Changed  bool     `json:"changed"`
	Modules  []string `json:"modules"`
}

type rewizjaView struct {
	Revision   string    `json:"revision"`
	ObservedAt time.Time `json:"observed_at"`
}

type fragmentView struct {
	Module     string    `json:"module"`
	Revision   string    `json:"revision"`
	ObservedAt time.Time `json:"observed_at"`
}

const powodOdswiezenia = "test integracyjny odswiezenia inwentarza"

// TestOdswiezenieInwentarzaRozliczaSieRewizja pilnuje zasady operacji:
// zadanie konczy sie sukcesem dopiero wtedy, gdy panel ma rewizje, o ktorej
// mowi agent. Samo przyjecie zadania niczego nie dowodzi - dotad operator
// klikal "odswiez" i nie wiedzial, czy panel cokolwiek dostal.
func TestOdswiezenieInwentarzaRozliczaSieRewizja(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			przed := rewizjaHosta(t, h, host.ID)
			zlecono := time.Now()

			zadanie, proby := h.runOperation(host.ID, map[string]any{
				"action": "inventory.refresh", "reason": powodOdswiezenia,
			}, 3*time.Minute)
			if zadanie.State != "succeeded" {
				t.Fatalf("odswiezenie: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
			}

			wynik := wynikOdswiezeniaZadania(t, h, zadanie.ID)
			if wynik.Kind != "inventory_refresh" {
				t.Fatalf("rodzaj wyniku = %q", wynik.Kind)
			}
			if wynik.Revision == "" {
				t.Fatal("agent nie podal rewizji")
			}
			if len(wynik.Modules) != 0 {
				t.Errorf("odswiezenie calosci zglosilo zakres %v", wynik.Modules)
			}

			po := rewizjaHosta(t, h, host.ID)
			if po.Revision != wynik.Revision {
				t.Errorf("panel ma rewizje %s, agent zglosil %s", po.Revision, wynik.Revision)
			}
			// Odczyt ma byc swiezy, a nie odpowiedzia z pamieci: rewizja moze
			// sie powtorzyc, gdy nic sie nie zmienilo, ale obserwacja musi
			// pochodzic z chwili po zleceniu.
			if !po.ObservedAt.After(zlecono) {
				t.Errorf("obserwacja z %s, zadanie zlecone %s", po.ObservedAt, zlecono)
			}
			if po.ObservedAt.Before(przed.ObservedAt) {
				t.Errorf("obserwacja cofnela sie: %s przed %s", po.ObservedAt, przed.ObservedAt)
			}
		})
	}
}

// TestOdswiezenieZakresuNieGubiPozostalychModulow pilnuje najgrozniejszego
// bledu odczytu czesciowego: host, ktory odswiezyl jeden modul, nie moze
// wygladac jak host bez reszty inwentarza.
func TestOdswiezenieZakresuNieGubiPozostalychModulow(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	poza := fragmentHosta(t, h, host.ID, "services")
	if poza.Revision == "" {
		t.Skip("host nie ma jeszcze fragmentu uslug")
	}
	zlecono := time.Now()

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "inventory.refresh", "reason": powodOdswiezenia,
		"payload": map[string]any{"inventory": map[string]any{"modules": []string{"packages"}}},
	}, 3*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("odswiezenie zakresu: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	wynik := wynikOdswiezeniaZadania(t, h, zadanie.ID)
	if len(wynik.Modules) != 1 || wynik.Modules[0] != "packages" {
		t.Fatalf("zakres w wyniku = %v", wynik.Modules)
	}

	pakiety := fragmentHosta(t, h, host.ID, "packages")
	if !pakiety.ObservedAt.After(zlecono) {
		t.Errorf("pakiety obserwowane %s, zadanie zlecone %s", pakiety.ObservedAt, zlecono)
	}
	pozaPo := fragmentHosta(t, h, host.ID, "services")
	if pozaPo.Revision == "" {
		t.Fatal("odswiezenie pakietow skasowalo fragment uslug")
	}
}

// TestRownolegleOdswiezeniaKoncaSieRewizja sprawdza, ze zadania zlecone obok
// siebie dziela jeden odczyt zamiast wygaszac sie nawzajem. Kazde ma dostac
// rewizje, ktora panel naprawde zapisal.
func TestRownolegleOdswiezeniaKoncaSieRewizja(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	const rownoleglych = 3
	wyniki := make([]wynikOdswiezenia, rownoleglych)
	stany := make([]string, rownoleglych)
	komunikaty := make([]string, rownoleglych)

	var grupa sync.WaitGroup
	for i := range rownoleglych {
		grupa.Add(1)
		go func() {
			defer grupa.Done()
			zadanie, proby := h.runOperation(host.ID, map[string]any{
				"action": "inventory.refresh", "reason": powodOdswiezenia,
			}, 3*time.Minute)
			stany[i] = zadanie.State
			komunikaty[i] = ostatniKomunikat(proby)
			if zadanie.State == "succeeded" {
				wyniki[i] = wynikOdswiezeniaZadania(t, h, zadanie.ID)
			}
		}()
	}
	grupa.Wait()

	for i := range rownoleglych {
		if stany[i] != "succeeded" {
			t.Fatalf("odswiezenie %d: stan = %s, %s", i, stany[i], komunikaty[i])
		}
		if wyniki[i].Revision == "" {
			t.Errorf("odswiezenie %d bez rewizji", i)
		}
	}
}

func rewizjaHosta(t *testing.T, h *harness, hostID string) rewizjaView {
	t.Helper()
	var rewizja rewizjaView
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory", nil, &rewizja, http.StatusOK)
	return rewizja
}

func fragmentHosta(t *testing.T, h *harness, hostID, modul string) fragmentView {
	t.Helper()
	var fragment fragmentView
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/"+modul, nil, &fragment, http.StatusOK)
	return fragment
}

func wynikOdswiezeniaZadania(t *testing.T, h *harness, jobID string) wynikOdswiezenia {
	t.Helper()
	var odpowiedz struct {
		Items []struct {
			Detail wynikOdswiezenia `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+jobID+"/attempts", nil, &odpowiedz, http.StatusOK)
	if len(odpowiedz.Items) == 0 {
		t.Fatal("zadanie bez prob")
	}
	return odpowiedz.Items[len(odpowiedz.Items)-1].Detail
}
