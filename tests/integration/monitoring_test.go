//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const powodMonitoringu = "test integracyjny modulu monitoringu"

type zrodloView struct {
	Name          string `json:"name"`
	Configured    bool   `json:"configured"`
	Healthy       bool   `json:"healthy"`
	URL           string `json:"url"`
	Reason        string `json:"reason"`
	LatencyMillis *int64 `json:"latency_millis"`
}

type alertView struct {
	Name       string            `json:"name"`
	Severity   string            `json:"severity"`
	Summary    string            `json:"summary"`
	Labels     map[string]string `json:"labels"`
	StartsAt   *time.Time        `json:"starts_at"`
	SilencedBy []string          `json:"silenced_by"`
}

type ciszaView struct {
	ID        string `json:"id"`
	EndsAt    string `json:"ends_at"`
	CreatedBy string `json:"created_by"`
	Comment   string `json:"comment"`
	Matchers  []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"matchers"`
}

type raportMonitoringuView struct {
	Sources []zrodloView `json:"sources"`
	Label   string       `json:"label"`
	Links   struct {
		Dashboard string `json:"dashboard"`
		Logs      string `json:"logs"`
	} `json:"links"`
	Alerts   []alertView `json:"alerts"`
	Silences []ciszaView `json:"silences"`
	Series   []struct {
		Name   string   `json:"name"`
		Last   *float64 `json:"last"`
		Query  string   `json:"query"`
		Reason string   `json:"unavailable_reason"`
		Points []struct {
			At    time.Time `json:"at"`
			Value float64   `json:"value"`
		} `json:"points"`
	} `json:"series"`
	From               time.Time `json:"from"`
	To                 time.Time `json:"to"`
	AlertsUnavailable  string    `json:"alerts_unavailable_reason"`
	MetricsUnavailable string    `json:"metrics_unavailable_reason"`
}

type wynikSondyView struct {
	Kind           string `json:"kind"`
	Target         string `json:"target"`
	Reachable      bool   `json:"reachable"`
	Passed         bool   `json:"passed"`
	StatusCode     *int   `json:"status_code"`
	DurationMillis int64  `json:"duration_millis"`
	Error          string `json:"error"`
}

// monitoringHosta czyta zakladke monitoringu hosta.
func monitoringHosta(h *harness, hostID string) raportMonitoringuView {
	h.t.Helper()
	var raport raportMonitoringuView
	h.get("/api/v1/hosts/"+hostID+"/monitoring", &raport)
	return raport
}

func zrodlo(raport raportMonitoringuView, nazwa string) *zrodloView {
	for i := range raport.Sources {
		if raport.Sources[i].Name == nazwa {
			return &raport.Sources[i]
		}
	}
	return nil
}

// TestMonitoringOpisujeZrodlaTakzeGdyIchNieMa pilnuje wlasciwosci, ktora
// decyduje o uzytecznosci tej zakladki: brak zrodla, zrodlo dzialajace
// i zrodlo, ktore nie odpowiada, to trzy rozne odpowiedzi.
func TestMonitoringOpisujeZrodlaTakzeGdyIchNieMa(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	raport := monitoringHosta(h, host.ID)

	if len(raport.Sources) != 2 {
		t.Fatalf("panel opisal %d zrodel: %+v", len(raport.Sources), raport.Sources)
	}
	for _, zrodlo := range raport.Sources {
		if !zrodlo.Configured && zrodlo.Reason == "" {
			t.Errorf("%s: zrodlo nieskonfigurowane bez wyjasnienia", zrodlo.Name)
		}
		if zrodlo.Configured && !zrodlo.Healthy && zrodlo.Reason == "" {
			t.Errorf("%s: zrodlo, ktore nie odpowiada, bez powodu", zrodlo.Name)
		}
	}
	// Etykieta jest zawsze: bez niej pusty wykres nie ma wyjasnienia.
	if raport.Label == "" {
		t.Error("panel nie mowi, po czym rozpoznaje ten host u zrodel")
	}
	// Zakres czasu tez: panel pokazuje cudze dane i mowi, z jakiego okna.
	if !raport.To.After(raport.From) {
		t.Errorf("zakres czasu = %s .. %s", raport.From, raport.To)
	}
	if metryki := zrodlo(raport, "prometheus"); metryki != nil && !metryki.Configured {
		if raport.MetricsUnavailable == "" {
			t.Error("brak zrodla metryk bez wyjasnienia")
		}
	}
}

// TestWyciszenieWymagaTerminuIPowodu pilnuje reguly, ktora odroznia cisze od
// wylaczenia alertu na zawsze.
func TestWyciszenieWymagaTerminuIPowodu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	raport := monitoringHosta(h, host.ID)
	alerty := zrodlo(raport, "alertmanager")
	if alerty == nil || !alerty.Configured {
		// Instalacja bez zrodla alertow odmawia wprost - i to tez jest
		// zachowanie, ktore warto sprawdzic.
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences",
			map[string]any{"duration_minutes": 60, "comment": powodMonitoringu},
			nil, http.StatusServiceUnavailable)
		t.Skip("ta instalacja nie ma zrodla alertow")
	}

	// Powod krotszy niz osiem znakow i cisza dluzsza niz doba odpadaja
	// w panelu, zanim cokolwiek pojdzie do systemu alertowego.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences",
		map[string]any{"duration_minutes": 60, "comment": "krotkie"},
		nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences",
		map[string]any{"duration_minutes": 60 * 48, "comment": powodMonitoringu},
		nil, http.StatusBadRequest)

	var cisza ciszaView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences",
		map[string]any{"duration_minutes": 45, "comment": powodMonitoringu},
		&cisza, http.StatusCreated)
	if cisza.ID == "" || cisza.CreatedBy == "" {
		t.Fatalf("wyciszenie bez identyfikatora albo wlasciciela: %+v", cisza)
	}
	if len(cisza.Matchers) == 0 || cisza.Matchers[0].Value != raport.Label {
		t.Errorf("wyciszenie nie dotyczy tego hosta: %+v", cisza.Matchers)
	}
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+host.ID+"/monitoring/silences/"+cisza.ID, nil, nil, 0)
	})

	po := monitoringHosta(h, host.ID)
	znalezione := false
	for _, wpis := range po.Silences {
		if wpis.ID == cisza.ID {
			znalezione = true
		}
	}
	if !znalezione {
		t.Fatalf("zalozone wyciszenie nie wrocilo z zakladki: %+v", po.Silences)
	}

	// Zakonczenie ciszy przed czasem tez jest decyzja - i tez ma slad.
	h.do(http.MethodDelete,
		"/api/v1/hosts/"+host.ID+"/monitoring/silences/"+cisza.ID, nil, nil, http.StatusNoContent)
	poZakonczeniu := monitoringHosta(h, host.ID)
	for _, wpis := range poZakonczeniu.Silences {
		if wpis.ID == cisza.ID {
			t.Fatal("zakonczone wyciszenie nadal obowiazuje")
		}
	}
}

// TestSondaMowiCoWidziHost pilnuje rozroznienia, ktore jest cala wartoscia
// sondy: operacja sie udala, a usluga nie odpowiada - to nie to samo, co
// operacja, ktora sie nie udala.
func TestSondaMowiCoWidziHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Sonda do panelu: host go widzi, wiec odpowiedz ma byc zgodna.
	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "monitoring.probe.run", "reason": powodMonitoringu,
		"payload": map[string]any{"monitoring": map[string]any{
			"kind": "http", "target": envOr("FLOTESTRO_TEST_API", defaultAPI) + "/healthz",
			"expect_body": "ok",
		}},
	}, 3*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("sonda zakonczyla sie stanem %s: %+v", zadanie.State, proby)
	}
	wynik := wynikSondy(t, h, zadanie.ID)
	if !wynik.Reachable || !wynik.Passed {
		t.Fatalf("sonda do panelu opisana jako %+v", wynik)
	}

	// Port zamkniety: zadanie sie udaje, a odpowiedz brzmi "nie dziala".
	zamkniety, proby := h.runOperation(host.ID, map[string]any{
		"action": "monitoring.probe.run", "reason": powodMonitoringu,
		"payload": map[string]any{"monitoring": map[string]any{
			"kind": "tcp", "target": "127.0.0.1:9", "timeout_seconds": 3,
		}},
	}, 3*time.Minute)
	if zamkniety.State != "succeeded" {
		t.Fatalf("sonda do zamknietego portu zakonczyla sie stanem %s: %+v",
			zamkniety.State, proby)
	}
	wynikZamkniety := wynikSondy(t, h, zamkniety.ID)
	if wynikZamkniety.Reachable || wynikZamkniety.Error == "" {
		t.Fatalf("zamkniety port opisany jako %+v", wynikZamkniety)
	}
	if len(proby) > 0 && !strings.Contains(proby[len(proby)-1].Message, "nie odpowiada") {
		t.Errorf("komunikat nie mowi, ze usluga nie odpowiada: %q",
			proby[len(proby)-1].Message)
	}

	// Sonda nie jest sposobem na czytanie plikow hosta cudzymi rekami.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "monitoring.probe.run", "reason": powodMonitoringu,
		"payload": map[string]any{"monitoring": map[string]any{
			"kind": "http", "target": "file:///etc/shadow",
		}},
	}, nil, http.StatusBadRequest)
}

// wynikSondy czyta wynik sondy z ostatniej proby zadania.
func wynikSondy(t *testing.T, h *harness, jobID string) wynikSondyView {
	t.Helper()
	var wynik struct {
		Items []struct {
			Detail struct {
				Probe wynikSondyView `json:"probe"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &wynik)
	if len(wynik.Items) == 0 {
		t.Fatalf("zadanie %s nie ma prob", jobID)
	}
	return wynik.Items[len(wynik.Items)-1].Detail.Probe
}
