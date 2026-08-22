//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestJednostkiChronioneSaOdrzucane sprawdza, ze operacja na jednostce, ktorej
// zatrzymanie odcieloby droge naprawy hosta, nie zostaje wykonana.
func TestJednostkiChronioneSaOdrzucane(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, unit := range []string{"sshd.service", "flotestro-agent.service", "NetworkManager.service"} {
		t.Run(unit, func(t *testing.T) {
			job, attempts := h.runOperation(host.ID, map[string]any{
				"action":  "unit.stop",
				"payload": unitPayload(unit),
			}, 60*time.Second)

			if job.State == "succeeded" {
				t.Fatalf("operacja na jednostce chronionej %s zakonczyla sie sukcesem", unit)
			}
			if len(attempts) == 0 {
				t.Fatal("brak zapisanej proby")
			}
			last := attempts[len(attempts)-1]
			if last.ErrorCode != "protected_unit" {
				t.Fatalf("kod bledu = %q, oczekiwano protected_unit", last.ErrorCode)
			}
			// Odrzucenie musi nastapic przed jakakolwiek zmiana stanu.
			if last.UnitStateAfter != nil {
				t.Error("odrzucona operacja zwrocila stan po zmianie")
			}
		})
	}
}

// TestNieprawidlowaNazwaJednostkiJestOdrzucana sprawdza walidacje po stronie
// hosta. Nazwa nigdy nie trafia do powloki, ale odrzucenie musi byc jawne.
func TestNieprawidlowaNazwaJednostkiJestOdrzucana(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, unit := range []string{"cron.service; reboot", "../../etc/passwd", "cron"} {
		t.Run(unit, func(t *testing.T) {
			job, attempts := h.runOperation(host.ID, map[string]any{
				"action":  "unit.restart",
				"payload": unitPayload(unit),
			}, 60*time.Second)

			if job.State == "succeeded" {
				t.Fatalf("nieprawidlowa nazwa %q zostala wykonana", unit)
			}
			if len(attempts) > 0 && attempts[len(attempts)-1].ErrorCode != "invalid_unit" {
				t.Errorf("kod bledu = %q, oczekiwano invalid_unit",
					attempts[len(attempts)-1].ErrorCode)
			}
		})
	}
}

// TestNieznanaOperacjaJestOdrzucanaPrzezAPI sprawdza, ze katalog operacji jest
// zamkniety: nie istnieje sposob zlecenia dowolnego polecenia.
func TestNieznanaOperacjaJestOdrzucanaPrzezAPI(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, action := range []string{"shell.exec", "unit.mask", "", "systemctl"} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{"action": action, "payload": unitPayload("cron.service")},
			nil, http.StatusBadRequest)
	}
}

// TestKatalogOperacjiNieZawieraPowloki pilnuje zakazanej anty-wlasciwosci
// z dokumentu: kontrakt podstawowy nie ma operacji uruchamiajacej powloke.
func TestKatalogOperacjiNieZawieraPowloki(t *testing.T) {
	h := newHarness(t)
	var catalog struct {
		Items []struct {
			Action     string `json:"action"`
			Permission string `json:"permission"`
		} `json:"items"`
	}
	h.get("/api/v1/actions", &catalog)

	if len(catalog.Items) == 0 {
		t.Fatal("katalog operacji jest pusty")
	}
	for _, item := range catalog.Items {
		switch item.Action {
		case "shell.exec", "shell", "command.run", "exec":
			t.Fatalf("katalog zawiera operacje powloki: %s", item.Action)
		}
		if item.Permission == "" {
			t.Errorf("operacja %s nie ma uprawnienia", item.Action)
		}
	}
}

// TestPonowneDostarczenieNiePowtarzaMutacji jest testem najwazniejszej
// wlasciwosci at-least-once. Symulujemy wygasniecie lease, zwracajac zadanie
// do kolejki, i sprawdzamy, ze agent zwraca zapisany wynik zamiast restartowac
// usluge po raz drugi.
func TestPonowneDostarczenieNiePowtarzaMutacji(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("pierwsze wykonanie nie powiodlo sie: %s", job.State)
	}
	pidAfterFirst := attempts[len(attempts)-1].UnitStateAfter.MainPID

	// Zadanie wraca do kolejki dokladnie tak, jak po wygasnieciu lease.
	if _, err := pool.Exec(ctx, `
		update jobs set state = 'queued', finished_at = null, result_status = null
		where id = $1`, job.ID); err != nil {
		t.Fatalf("nie zwrocono zadania do kolejki: %v", err)
	}

	repeated := h.awaitTerminal(job.ID, 90*time.Second)
	if repeated.State != "succeeded" {
		t.Fatalf("ponowne dostarczenie zakonczylo sie stanem %s", repeated.State)
	}

	repeatedAttempts := h.attempts(job.ID)
	if len(repeatedAttempts) < 2 {
		t.Fatalf("oczekiwano drugiej proby, jest %d", len(repeatedAttempts))
	}
	last := repeatedAttempts[len(repeatedAttempts)-1]
	if !last.Replayed {
		t.Error("druga proba nie zostala oznaczona jako odtworzona z dziennika")
	}
	// Sedno testu: usluga nie zostala zrestartowana drugi raz.
	if last.UnitStateAfter != nil && last.UnitStateAfter.MainPID != pidAfterFirst {
		t.Fatalf("mutacja zostala powtorzona: PID %d -> %d",
			pidAfterFirst, last.UnitStateAfter.MainPID)
	}
}

// TestSladAudytowyJestKompletny sprawdza, ze kazdy krok operacji zostawia
// zdarzenie: utworzenie, zatwierdzenie, dostarczenie i wynik.
func TestSladAudytowyJestKompletny(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, _ := h.runOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	}, 90*time.Second)

	var events struct {
		Items []struct {
			Action    string `json:"action"`
			ActorID   string `json:"actor_id"`
			ActorType string `json:"actor_type"`
			Outcome   string `json:"outcome"`
			TargetID  string `json:"target_id"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?target_id="+job.ID+"&limit=50", &events)

	seen := map[string]bool{}
	for _, event := range events.Items {
		seen[event.Action] = true
	}
	for _, required := range []string{"job.create", "job.approve", "job.dispatch", "job.result"} {
		if !seen[required] {
			t.Errorf("brak zdarzenia audytowego %s dla zadania %s", required, job.ID)
		}
	}
}

// TestOdmowaTezJestAudytowana sprawdza, ze nieudana proba zatwierdzenia
// zostawia slad. Audyt bez odmow pokazywalby tylko to, co sie udalo.
func TestOdmowaTezJestAudytowana(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job := h.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
			map[string]any{"reason": "koniec testu"}, nil, http.StatusOK)
	})

	h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/approve",
		map[string]any{"payload_hash": "deadbeef"}, nil, http.StatusConflict)

	var events struct {
		Items []struct {
			Action  string `json:"action"`
			Outcome string `json:"outcome"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?target_id="+job.ID+"&limit=50", &events)

	denied := false
	for _, event := range events.Items {
		if event.Action == "job.approve" && event.Outcome == "denied" {
			denied = true
		}
	}
	if !denied {
		t.Fatal("odrzucone zatwierdzenie nie zostawilo zdarzenia audytowego")
	}
}
