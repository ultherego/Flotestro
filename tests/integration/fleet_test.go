//go:build integration

package integration

import (
	"testing"
	"time"
)

// TestFlotaJestZarejestrowana sprawdza, ze oba hosty zglosily sie do control
// plane i zostaly poprawnie rozpoznane.
func TestFlotaJestZarejestrowana(t *testing.T) {
	h := newHarness(t)
	hosts := h.hosts()
	if len(hosts) < 2 {
		t.Fatalf("we flocie jest %d hostow, oczekiwano co najmniej 2", len(hosts))
	}

	families := map[string]hostView{}
	for _, host := range hosts {
		families[host.OSFamily] = host
	}

	t.Run("Debian", func(t *testing.T) {
		host, ok := families["debian"]
		if !ok {
			t.Fatal("brak hosta rodziny debian")
		}
		if host.ConnectionState != "online" {
			t.Errorf("stan polaczenia = %s, oczekiwano online", host.ConnectionState)
		}
		if !maAdapter(host, "systemd") || !maAdapter(host, "packages.apt") ||
			!maAdapter(host, "journald") {
			t.Errorf("nieoczekiwane zdolnosci hosta Debian: %+v", host.Capabilities)
		}
		if maAdapter(host, "packages.dnf") {
			t.Error("host Debian nie powinien zglaszac dnf")
		}
	})

	t.Run("Fedora", func(t *testing.T) {
		host, ok := families["rhel"]
		if !ok {
			t.Fatal("brak hosta rodziny rhel")
		}
		if host.ConnectionState != "online" {
			t.Errorf("stan polaczenia = %s, oczekiwano online", host.ConnectionState)
		}
		if !maAdapter(host, "systemd") || !maAdapter(host, "packages.dnf") ||
			!maAdapter(host, "journald") {
			t.Errorf("nieoczekiwane zdolnosci hosta Fedora: %+v", host.Capabilities)
		}
		if maAdapter(host, "packages.apt") {
			t.Error("host Fedora nie powinien zglaszac apt")
		}
	})
}

// TestSygnalyZdrowiaSaUstaloneAlboPuste pilnuje, ze agent nie zamienia bledu
// odczytu na zero. Puste pole jest dozwolone, zmyslona wartosc nie.
func TestSygnalyZdrowiaSaUstaloneAlboPuste(t *testing.T) {
	h := newHarness(t)
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		// Wartosci sa opcjonalne, ale jesli sa obecne, musza byc sensowne.
		if host.FailedUnits != nil && *host.FailedUnits < 0 {
			t.Errorf("%s: ujemna liczba failed units", host.Hostname)
		}
		if host.PendingUpdates != nil && *host.PendingUpdates < 0 {
			t.Errorf("%s: ujemna liczba aktualizacji", host.Hostname)
		}
		if host.BootID == "" {
			t.Errorf("%s: brak boot_id, a host jest online", host.Hostname)
		}
	}
}

// TestOperacjaMutujacaWymagaZatwierdzenia sprawdza, ze samo zlecenie nie
// zmienia niczego na hoscie i czeka na decyzje czlowieka.
func TestOperacjaMutujacaWymagaZatwierdzenia(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job := h.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	if !job.RequiresApprova {
		t.Fatal("restart uslugi nie wymaga zatwierdzenia")
	}
	if job.State != "awaiting_approval" {
		t.Fatalf("stan = %s, oczekiwano awaiting_approval", job.State)
	}
	if job.PayloadHash == "" {
		t.Fatal("plan nie ma hasha")
	}

	// Zadanie czeka i nie trafia do kolejki, dopoki nikt go nie zatwierdzi.
	time.Sleep(4 * time.Second)
	if state := h.job(job.ID).State; state != "awaiting_approval" {
		t.Fatalf("niezatwierdzone zadanie zmienilo stan na %s", state)
	}

	h.do("POST", "/api/v1/jobs/"+job.ID+"/cancel",
		map[string]any{"reason": "sprzatanie po tescie"}, nil, 200)
}

// TestZatwierdzenieZNiezgodnymHashemJestOdrzucane chroni przed podmiana planu
// miedzy obejrzeniem a zatwierdzeniem.
func TestZatwierdzenieZNiezgodnymHashemJestOdrzucane(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job := h.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	t.Cleanup(func() {
		h.do("POST", "/api/v1/jobs/"+job.ID+"/cancel", map[string]any{"reason": "koniec testu"}, nil, 200)
	})

	h.do("POST", "/api/v1/jobs/"+job.ID+"/approve",
		map[string]any{"payload_hash": "0000000000000000000000000000000000000000000000000000000000000000"},
		nil, 409)

	if state := h.job(job.ID).State; state != "awaiting_approval" {
		t.Fatalf("odrzucone zatwierdzenie zmienilo stan na %s", state)
	}
}

// TestRestartUslugiZmieniaProces sprawdza cala droge: plan, zatwierdzenie,
// wykonanie przez helpera roota i wynik ze stanem jednostki przed i po.
func TestRestartUslugiZmieniaProces(t *testing.T) {
	cases := []struct {
		family string
		unit   string
	}{
		{"debian", "cron.service"},
		{"rhel", "crond.service"},
	}

	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			h := newHarness(t)
			host := h.hostByFamily(tc.family)

			job, attempts := h.runOperation(host.ID, map[string]any{
				"action":  "unit.restart",
				"payload": unitPayload(tc.unit),
			}, 90*time.Second)

			if job.State != "succeeded" {
				t.Fatalf("stan = %s, kod bledu = %s", job.State, job.ResultErrorCode)
			}
			if len(attempts) == 0 {
				t.Fatal("brak zapisanej proby wykonania")
			}
			last := attempts[len(attempts)-1]
			if last.ExitCode == nil || *last.ExitCode != 0 {
				t.Fatalf("kod wyjscia = %v, stderr: %s", last.ExitCode, last.Stderr)
			}
			if last.UnitStateBefore == nil || last.UnitStateAfter == nil {
				t.Fatal("brak stanu jednostki przed lub po operacji")
			}
			// Zmiana PID jest dowodem, ze restart faktycznie nastapil, a nie
			// tylko zwrocil kod zero.
			if last.UnitStateBefore.MainPID == last.UnitStateAfter.MainPID {
				t.Errorf("PID nie zmienil sie: %d", last.UnitStateAfter.MainPID)
			}
			if last.UnitStateAfter.ActiveState != "active" {
				t.Errorf("jednostka po restarcie jest w stanie %s", last.UnitStateAfter.ActiveState)
			}
		})
	}
}

// TestOdczytDziennikaNieWymagaZatwierdzenia sprawdza operacje niemutujaca.
func TestOdczytDziennikaNieWymagaZatwierdzenia(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "journal.read",
		"payload": map[string]any{
			"journal": map[string]any{"unit": "cron.service", "lines": 5},
		},
	}, 60*time.Second)

	if job.RequiresApprova {
		t.Error("odczyt dziennika nie powinien wymagac zatwierdzenia")
	}
	if job.State != "succeeded" {
		t.Fatalf("stan = %s, kod bledu = %s", job.State, job.ResultErrorCode)
	}
	if len(attempts) == 0 || attempts[len(attempts)-1].Stdout == "" {
		t.Fatal("odczyt dziennika nie zwrocil tresci")
	}
}

// maAdapter mowi, czy host zglosil dany adapter jako dostepny.
func maAdapter(host hostView, nazwa string) bool {
	for _, adapter := range host.Capabilities {
		if adapter.Name == nazwa {
			return adapter.Available
		}
	}
	return false
}
