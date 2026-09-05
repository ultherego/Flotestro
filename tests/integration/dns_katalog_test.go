//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
)

const powodRekordu = "test integracyjny rekordow DNS katalogu"

type strefaView struct {
	Name    string `json:"name"`
	Reverse bool   `json:"reverse"`
}

type rekordView struct {
	Zone   string   `json:"zone"`
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

type zmianaKatalogu struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Plan  struct {
		Summary   string   `json:"summary"`
		Steps     []string `json:"steps"`
		Conflicts []string `json:"conflicts"`
	} `json:"plan"`
}

// katalogDostepny mowi, czy instalacja ma polaczenie z katalogiem.
func katalogDostepny(t *testing.T, h *harness) bool {
	t.Helper()
	var stan struct {
		Configured bool `json:"configured"`
		Reachable  bool `json:"reachable"`
	}
	h.get("/api/v1/identity/status", &stan)
	return stan.Configured && stan.Reachable
}

// TestRekordKatalogowyPlanujeRekordOdwrotny pilnuje reguly, ktora najczesciej
// bywa pomijana: rekord PTR jest osobnym, widocznym krokiem planu, a nie
// szczegolem zapisu rekordu A.
func TestRekordKatalogowyPlanujeRekordOdwrotny(t *testing.T) {
	h := newHarness(t)
	if !katalogDostepny(t, h) {
		t.Skip("ta instalacja nie ma polaczenia z katalogiem")
	}

	var strefy struct {
		Items []strefaView `json:"items"`
	}
	h.get("/api/v1/identity/dns/zones", &strefy)
	var strefa string
	for _, pozycja := range strefy.Items {
		if !pozycja.Reverse {
			strefa = pozycja.Name
			break
		}
	}
	if strefa == "" {
		t.Skip("katalog nie ma strefy w przod")
	}

	var zmiana zmianaKatalogu
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "dns.record.ensure",
		"payload": map[string]any{"dns": map[string]any{
			"zone": strefa, "name": "flotestro-test", "type": "A",
			"value": "192.168.56.199", "reverse": true,
		}},
	}, &zmiana, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/identity/changes/"+zmiana.ID+"/cancel", nil, nil, 0)
	})

	// Plan musi wymieniac oba rekordy osobno: w przod i wstecz.
	if len(zmiana.Plan.Steps) < 2 {
		t.Fatalf("plan ma %d krokow: %+v", len(zmiana.Plan.Steps), zmiana.Plan.Steps)
	}
	odwrotny := false
	for _, krok := range zmiana.Plan.Steps {
		if strings.Contains(krok, "PTR") {
			odwrotny = true
		}
	}
	if !odwrotny {
		t.Fatalf("plan nie wymienia rekordu odwrotnego: %+v", zmiana.Plan.Steps)
	}
}

// TestRekordKatalogowyOdrzucaZlyMaterial pilnuje granicy: rekord odrzucony
// przez katalog ma odpasc przy zlecaniu, a nie po zatwierdzeniu.
func TestRekordKatalogowyOdrzucaZlyMaterial(t *testing.T) {
	h := newHarness(t)
	if !katalogDostepny(t, h) {
		t.Skip("ta instalacja nie ma polaczenia z katalogiem")
	}

	zle := map[string]map[string]any{
		"adres, ktory jest nazwa": {
			"zone": "flotestro.test", "name": "web", "type": "A", "value": "web.example.test",
		},
		"typ, ktorego panel nie zapisuje": {
			"zone": "flotestro.test", "name": "@", "type": "NS", "value": "ipa.flotestro.test.",
		},
		"nazwa strefy ze spacja": {
			"zone": "flotestro test", "name": "web", "type": "A", "value": "10.0.0.5",
		},
		"rekord odwrotny dla CNAME": {
			"zone": "flotestro.test", "name": "alias", "type": "CNAME",
			"value": "web.flotestro.test.", "reverse": true,
		},
	}
	for nazwa, payload := range zle {
		t.Run(nazwa, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
				"action": "dns.record.ensure", "reason": powodRekordu,
				"payload": map[string]any{"dns": payload},
			}, nil, http.StatusBadRequest)
		})
	}
}
