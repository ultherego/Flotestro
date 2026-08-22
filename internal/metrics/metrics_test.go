package metrics

import (
	"context"
	"strings"
	"testing"
	"time"
)

type licznikSesji struct{ ile int }

func (l licznikSesji) Count() int { return l.ile }

type certyfikat struct{ koniec time.Time }

func (c certyfikat) NotAfter() time.Time { return c.koniec }

// TestFormatEkspozycji sprawdza zgodnosc z formatem tekstowym Prometheusa:
// kazda metryka ma HELP i TYPE przed wartosciami, a etykiety sa posortowane.
func TestFormatEkspozycji(t *testing.T) {
	wynik := render([]metric{{
		name: "flotestro_hosts", kind: "gauge", help: "Hosty floty.",
		samples: labelled("connection_state", map[string]float64{
			"online": 3, "offline": 1, "stale": 2,
		}),
	}})

	tekst := string(wynik)
	if !strings.HasPrefix(tekst, "# HELP flotestro_hosts Hosty floty.\n# TYPE flotestro_hosts gauge\n") {
		t.Fatalf("brak naglowkow metryki:\n%s", tekst)
	}
	oczekiwane := "" +
		`flotestro_hosts{connection_state="offline"} 1` + "\n" +
		`flotestro_hosts{connection_state="online"} 3` + "\n" +
		`flotestro_hosts{connection_state="stale"} 2` + "\n"
	if !strings.HasSuffix(tekst, oczekiwane) {
		t.Errorf("wartosci w zlej postaci lub kolejnosci:\n%s", tekst)
	}
}

// TestEtykietyNieRozbijajaFormatu pilnuje wartosci pochodzacych z bazy.
// Stan zadania jest tekstem z kolumny, a nie stala z kodu.
func TestEtykietyNieRozbijajaFormatu(t *testing.T) {
	wynik := string(render([]metric{{
		name: "flotestro_jobs", kind: "gauge", help: "Zadania.",
		samples: []sample{{
			labels: map[string]string{"state": "dziwny\"stan\nz nowa linia"},
			value:  1,
		}},
	}}))

	if strings.Count(wynik, "\n") != 3 {
		t.Errorf("wartosc etykiety rozbila format na wiecej wierszy:\n%s", wynik)
	}
	if !strings.Contains(wynik, `\"stan\n`) {
		t.Errorf("znaki specjalne nie zostaly zabezpieczone:\n%s", wynik)
	}
}

// TestStanNieustalonyJestPomijany pilnuje zasady, ze metryka, ktorej nie udalo
// sie ustalic, znika z odpowiedzi zamiast pokazac zero. Zero znaczy zmierzone
// zero i uruchomiloby alerty opisujace nieprawde.
func TestStanNieustalonyJestPomijany(t *testing.T) {
	// Kolektor bez bazy, bez licznika sesji i bez certyfikatu: zostaja
	// wylacznie metryki, ktore da sie policzyc w procesie.
	kolektor := NewCollector(nil, nil, nil, "panel")
	tekst := string(kolektor.Gather(context.Background()))

	for _, nieobecna := range []string{
		"flotestro_agent_sessions_active",
		"flotestro_ca_certificate_expires_in_seconds",
		"flotestro_hosts",
		"flotestro_job_queue_age_seconds",
	} {
		if strings.Contains(tekst, nieobecna) {
			t.Errorf("metryka %s pojawila sie mimo braku zrodla danych", nieobecna)
		}
	}
	for _, obecna := range []string{"flotestro_build_info", "flotestro_goroutines"} {
		if !strings.Contains(tekst, obecna) {
			t.Errorf("brak metryki %s, ktora nie zalezy od bazy", obecna)
		}
	}

	// Certyfikat bez ustalonej daty waznosci tez nie moze dac zera: zero
	// znaczyloby "wygasa teraz" i podnioslo alarm bez powodu.
	zCertem := NewCollector(nil, licznikSesji{ile: 7}, certyfikat{}, "panel")
	tekst = string(zCertem.Gather(context.Background()))
	if strings.Contains(tekst, "flotestro_ca_certificate_expires_in_seconds") {
		t.Error("nieustalona waznosc certyfikatu zostala pokazana jako wartosc")
	}
	if !strings.Contains(tekst, `flotestro_agent_sessions_active{gateway="panel"} 7`) {
		t.Errorf("liczba sesji nie zostala wystawiona:\n%s", tekst)
	}
}
