//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// harmonogramView odwzorowuje jeden wpis w migawce zadan cyklicznych.
type harmonogramView struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Source      string     `json:"source"`
	Enabled     bool       `json:"enabled"`
	Expression  string     `json:"expression"`
	Command     []string   `json:"command"`
	CommandLine string     `json:"command_line"`
	Path        string     `json:"path"`
	NextRun     *time.Time `json:"next_run"`
}

type migawkaHarmonogramow struct {
	Schedules         []harmonogramView `json:"schedules"`
	Timezone          string            `json:"timezone"`
	UnavailableReason string            `json:"unavailable_reason"`
}

const powodHarmonogramu = "test integracyjny modulu harmonogramow"

// TestCyklZyciaWpisuZarzadzanego przechodzi pelna droge wpisu panelu:
// zalozenie, wylaczenie, uruchomienie poza terminem i usuniecie. Kazdy krok
// jest sprawdzany na stanie hosta, a nie na tym, co odpowiedziala operacja.
func TestCyklZyciaWpisuZarzadzanego(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	const id = "test-cyklu-zycia"

	t.Cleanup(func() {
		h.createOperation(host.ID, map[string]any{
			"action": "schedule.remove", "reason": powodHarmonogramu,
			"payload": map[string]any{"schedule": map[string]any{"id": id}},
		})
	})

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "schedule.ensure", "reason": powodHarmonogramu,
		"payload": map[string]any{"schedule": map[string]any{
			"id":         id,
			"expression": "*/5 * * * *",
			"command":    []string{"/usr/bin/true"},
			"user":       "root",
			"enabled":    true,
		}},
	}, 90*time.Second)
	if zadanie.State != "succeeded" {
		t.Fatalf("zalozenie wpisu: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	wpis := wpisHosta(t, h, host.ID, id)
	if wpis.Source != "managed" || !wpis.Enabled {
		t.Fatalf("wpis po zalozeniu = %+v", wpis)
	}
	// Wpis wlasny panel zapisal sam, wiec zna jego argumenty; wpis zastany
	// zostaje wierszem powloki.
	if len(wpis.Command) == 0 {
		t.Errorf("wpis zarzadzany nie ma argumentow: %+v", wpis)
	}
	if wpis.NextRun == nil {
		t.Error("wpis aktywny nie ma nastepnego terminu")
	}

	// Wylaczenie nie jest usunieciem: tresc zostaje na hoscie, ale wpis
	// nie ma juz nastepnego terminu, bo sie nie uruchomi.
	zadanie, proby = h.runOperation(host.ID, map[string]any{
		"action": "schedule.disable", "reason": powodHarmonogramu,
		"payload": map[string]any{"schedule": map[string]any{"id": id, "enabled": false}},
	}, 90*time.Second)
	if zadanie.State != "succeeded" {
		t.Fatalf("wylaczenie wpisu: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}
	wpis = wpisHosta(t, h, host.ID, id)
	if wpis.Enabled {
		t.Error("wpis nadal jest wlaczony")
	}
	if wpis.NextRun != nil {
		t.Errorf("wpis wylaczony dostal termin %v", wpis.NextRun)
	}
	if wpis.Expression != "*/5 * * * *" {
		t.Errorf("wylaczenie zgubilo tresc wpisu: %+v", wpis)
	}

	// Uruchomienie poza terminem dziala takze dla wpisu wylaczonego:
	// operator wlasnie tak sprawdza, czy polecenie w ogole dziala.
	zadanie, proby = h.runOperation(host.ID, map[string]any{
		"action": "schedule.run_now", "reason": powodHarmonogramu,
		"payload": map[string]any{"schedule": map[string]any{"id": id}},
	}, 120*time.Second)
	if zadanie.State != "succeeded" {
		t.Fatalf("uruchomienie wpisu: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	zadanie, proby = h.runOperation(host.ID, map[string]any{
		"action": "schedule.remove", "reason": powodHarmonogramu,
		"payload": map[string]any{"schedule": map[string]any{"id": id}},
	}, 90*time.Second)
	if zadanie.State != "succeeded" {
		t.Fatalf("usuniecie wpisu: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}
	for _, pozostaly := range migawka(t, h, host.ID).Schedules {
		if pozostaly.ID == id {
			t.Fatalf("wpis przetrwal usuniecie: %+v", pozostaly)
		}
	}
}

// TestWpisZastanyNieJestNadpisywany sprawdza granice wlasnosci. Wpis, ktorego
// nikt do panelu nie wprowadzal, nalezy do administratora hosta: pierwsza
// operacja z panelu nie moze go po cichu zastapic.
func TestWpisZastanyNieJestNadpisywany(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var zastany harmonogramView
	for _, wpis := range migawka(t, h, host.ID).Schedules {
		if wpis.Source == "manual" && wpis.Kind == "cron" && strings.HasPrefix(wpis.Path, "/etc/cron.d/") {
			zastany = wpis
			break
		}
	}
	if zastany.Path == "" {
		t.Skip("host nie ma wpisu zastanego w /etc/cron.d")
	}
	nazwa := zastany.Path[strings.LastIndex(zastany.Path, "/")+1:]

	// Bez jawnego przejecia operacja ma zostac odrzucona z powodem, a nie
	// zakonczyc sie cicho powodzeniem.
	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "schedule.ensure", "reason": powodHarmonogramu,
		"payload": map[string]any{"schedule": map[string]any{
			"id":         nazwa,
			"expression": "0 4 * * *",
			"command":    []string{"/usr/bin/true"},
			"user":       "root",
		}},
	}, 90*time.Second)
	if zadanie.State == "succeeded" {
		t.Fatalf("panel nadpisal wpis zastany %s", zastany.Path)
	}
	komunikat := ostatniKomunikat(proby)
	if !strings.Contains(komunikat, "nie nalezy do panelu") {
		t.Errorf("odmowa bez powodu: %q", komunikat)
	}
}

// TestHarmonogramZlyPrzedWyslaniem sprawdza, ze wpis, ktorego cron nie
// zrozumie, nie dojezdza do hosta. Blad wyrazenia jest wada zlecenia,
// a nie awaria wykonania.
func TestHarmonogramZlyPrzedWyslaniem(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, przypadek := range []map[string]any{
		{"id": "zly-czas", "expression": "99 * * * *", "command": []string{"/usr/bin/true"}},
		{"id": "zly-czas", "expression": "0 4 * * *", "command": []string{"/bin/sh", "-c", "rm -rf / ; echo x"}},
		{"id": "zly-czas", "expression": "0 4 * * *", "command": []string{"true"}},
		{"id": "Zla Nazwa", "expression": "0 4 * * *", "command": []string{"/usr/bin/true"}},
	} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{"action": "schedule.ensure", "reason": powodHarmonogramu,
				"payload": map[string]any{"schedule": przypadek}},
			nil, http.StatusBadRequest)
	}
}

// TestTimeryIStandardowyCronWJednejTabeli sprawdza, ze oba mechanizmy trafiaja
// do jednej listy. Timer bez wyrazenia kalendarzowego nie moze dostac cudzego.
func TestTimeryIStandardowyCronWJednejTabeli(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	stan := migawka(t, h, host.ID)
	if stan.UnavailableReason != "" {
		t.Fatalf("harmonogramow nie odczytano: %s", stan.UnavailableReason)
	}
	// Strefa hosta jest faktem o hoscie: bez niej "03:00" nic nie znaczy.
	if stan.Timezone == "" || stan.Timezone == "Local" {
		t.Errorf("strefa hosta = %q", stan.Timezone)
	}

	var cron, timer int
	for _, wpis := range stan.Schedules {
		switch wpis.Kind {
		case "cron":
			cron++
		case "timer":
			timer++
			// Timer uruchamia jednostke, a nie polecenie.
			if !strings.HasSuffix(wpis.CommandLine, ".service") {
				t.Errorf("timer %s uruchamia %q", wpis.ID, wpis.CommandLine)
			}
		}
	}
	if cron == 0 || timer == 0 {
		t.Fatalf("wpisow crona = %d, timerow = %d", cron, timer)
	}
}

func migawka(t *testing.T, h *harness, hostID string) migawkaHarmonogramow {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/schedules",
		nil, &fragment, http.StatusOK)
	var stan migawkaHarmonogramow
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		t.Fatalf("migawka harmonogramow: %v", err)
	}
	return stan
}

// wpisHosta czeka na wpis w inwentarzu hosta. Operacja odsyla stan po zmianie,
// ale zapis fragmentu jest asynchroniczny wzgledem zakonczenia zadania.
func wpisHosta(t *testing.T, h *harness, hostID, id string) harmonogramView {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		for _, wpis := range migawka(t, h, hostID).Schedules {
			if wpis.ID == id {
				return wpis
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("wpis %s nie pojawil sie w inwentarzu hosta", id)
		}
		time.Sleep(2 * time.Second)
	}
}

func ostatniKomunikat(proby []attemptView) string {
	if len(proby) == 0 {
		return "brak prob"
	}
	ostatnia := proby[len(proby)-1]
	return ostatnia.ErrorCode + ": " + ostatnia.Message
}
