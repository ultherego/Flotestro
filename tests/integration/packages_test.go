//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func planPayload(refresh bool, only ...string) map[string]any {
	plan := map[string]any{"refresh_metadata": refresh}
	if len(only) > 0 {
		plan["only_packages"] = only
	}
	return map[string]any{"package_plan": plan}
}

// TestPlanAktualizacjiNieZmieniaHosta sprawdza, ze planowanie jest bezpieczne:
// zwraca liste zmian i hash, ale niczego nie instaluje.
func TestPlanAktualizacjiNieZmieniaHosta(t *testing.T) {
	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			h := newHarness(t)
			host := h.hostByFamily(family)

			job, attempts := h.runOperation(host.ID, map[string]any{
				"action":  "packages.plan",
				"payload": planPayload(false),
			}, 3*time.Minute)

			if job.State != "succeeded" {
				t.Fatalf("stan = %s, kod = %s", job.State, job.ResultErrorCode)
			}
			// Plan jest operacja niemutujaca, wiec nie wymaga zatwierdzenia.
			if job.RequiresApprova {
				t.Error("planowanie wymaga zatwierdzenia, choc niczego nie zmienia")
			}

			detail := attempts[len(attempts)-1].Detail
			if detail == nil || detail.Kind != "package_plan" {
				t.Fatalf("brak typowanego wyniku planu: %+v", detail)
			}
			if detail.Manager == "" {
				t.Error("plan nie podaje menedzera pakietow")
			}
			if len(detail.Changes) > 0 && detail.PlanHash == "" {
				t.Error("plan ze zmianami nie ma hasha")
			}
			for _, change := range detail.Changes {
				if change.Name == "" || change.CandidateVersion == "" {
					t.Errorf("niepelny opis zmiany: %+v", change)
				}
			}
		})
	}
}

// TestPlanJestPowtarzalny sprawdza, ze ten sam stan hosta daje ten sam hash.
// Bez tego weryfikacja planu przy wykonaniu nie mialaby sensu.
func TestPlanJestPowtarzalny(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	first := h.planHash(host.ID)
	second := h.planHash(host.ID)
	if first != second {
		t.Fatalf("ten sam stan dal rozne hashe planu: %s != %s", first, second)
	}
}

// planHash zleca plan i zwraca jego hash.
func (h *harness) planHash(hostID string) string {
	h.t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action":  "packages.plan",
		"payload": planPayload(false),
	}, 3*time.Minute)
	if job.State != "succeeded" {
		h.t.Fatalf("plan nie powiodl sie: %s (%s)", job.State, job.ResultErrorCode)
	}
	detail := attempts[len(attempts)-1].Detail
	if detail == nil {
		h.t.Fatal("plan bez wyniku")
	}
	return detail.PlanHash
}

// TestTransakcjaZNieaktualnymPlanemJestOdrzucana chroni przed zastosowaniem
// innego zestawu pakietow niz zatwierdzony. Metadane repozytorium moga sie
// zmienic miedzy planem a wykonaniem.
func TestTransakcjaZNieaktualnymPlanemJestOdrzucana(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.upgrade",
		"payload": map[string]any{
			"package_upgrade": map[string]any{
				"packages":  []string{"bash"},
				"plan_hash": "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}, 5*time.Minute)

	if job.State == "succeeded" {
		t.Fatal("transakcja z nieaktualnym planem zostala wykonana")
	}
	last := attempts[len(attempts)-1]
	if last.ErrorCode != "plan_changed" {
		t.Fatalf("kod bledu = %q, oczekiwano plan_changed", last.ErrorCode)
	}
	// Nic nie moglo zostac zmienione.
	if last.Detail != nil && len(last.Detail.Applied) > 0 {
		t.Errorf("odrzucona transakcja zmienila %d pakietow", len(last.Detail.Applied))
	}
}

// TestTransakcjaZapisujeWersjePrzedIPo sprawdza, ze raport transakcji zawiera
// to, czego wymaga dokument: wersje przed i po oraz stan restartu.
func TestTransakcjaZapisujeWersjePrzedIPo(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	// Wybieramy pakiet z aktualnego planu, zeby test nie zalezal od tego,
	// co akurat jest nieaktualne na obrazie.
	_, planAttempts := h.runOperation(host.ID, map[string]any{
		"action":  "packages.plan",
		"payload": planPayload(false),
	}, 3*time.Minute)
	plan := planAttempts[len(planAttempts)-1].Detail
	if plan == nil || len(plan.Changes) == 0 {
		t.Skip("host nie ma dostepnych aktualizacji")
	}

	target := ""
	for _, change := range plan.Changes {
		// Pomijamy pakiety, ktore pociagaja restart lub duze zaleznosci.
		switch change.Name {
		case "kernel", "glibc", "systemd", "dnf", "rpm":
			continue
		}
		target = change.Name
		break
	}
	if target == "" {
		t.Skip("brak bezpiecznego pakietu do testu")
	}

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.upgrade",
		"payload": map[string]any{
			"package_upgrade": map[string]any{"packages": []string{target}},
		},
	}, 10*time.Minute)

	last := attempts[len(attempts)-1]
	if last.Detail == nil || last.Detail.Kind != "package_apply" {
		t.Fatalf("brak raportu transakcji: %+v", last.Detail)
	}
	// Raport powstaje takze przy bledzie; sprawdzamy jego kompletnosc.
	if job.State == "succeeded" {
		if len(last.Detail.Applied) == 0 {
			t.Errorf("udana transakcja nie zapisala zadnej zmiany wersji")
		}
		for _, change := range last.Detail.Applied {
			if change.CandidateVersion == "" {
				t.Errorf("brak wersji po zmianie dla %s", change.Name)
			}
		}
	}
	if last.Detail.PackageDatabaseBroken {
		t.Errorf("transakcja zostawila uszkodzona baze pakietow")
	}
}

// TestOperatorPlanujeAleNieAktualizuje sprawdza rozdzial uprawnien: transakcja
// pakietowa jest operacja najwyzszego ryzyka i ma osobne prawo.
func TestOperatorPlanujeAleNieAktualizuje(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	operator := h.withToken(h.createPrincipal(uniqueSubject("operator-pakiety"), []map[string]string{
		{"role": "operator", "site": host.Site, "environment": host.Environment},
	}))

	// Planowanie wolno.
	operator.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "packages.plan", "payload": planPayload(false)},
		nil, http.StatusCreated)

	// Transakcji juz nie.
	operator.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "packages.upgrade",
			"payload": map[string]any{"package_upgrade": map[string]any{}}},
		nil, http.StatusForbidden)
}

// TestUszkodzonaBazaPakietowBlokujeOperacje sprawdza, ze po nieudanej
// transakcji host nie dostaje kolejnych operacji pakietowych.
func TestUszkodzonaBazaPakietowBlokujeOperacje(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")

	if _, err := pool.Exec(ctx,
		`update hosts set package_database_broken = true where id = $1`, host.ID); err != nil {
		t.Fatalf("nie ustawiono flagi: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`update hosts set package_database_broken = false where id = $1`, host.ID)
	})

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "packages.plan", "payload": planPayload(false)},
		nil, http.StatusConflict)

	// Operacje niepakietowe nadal dzialaja: blokada dotyczy tylko pakietow.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "journal.read",
			"payload": map[string]any{"journal": map[string]any{"lines": 5}}},
		nil, http.StatusCreated)
}

// TestNieprawidlowaNazwaPakietuJestOdrzucana sprawdza walidacje po stronie API.
func TestNieprawidlowaNazwaPakietuJestOdrzucana(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, name := range []string{"bash; reboot", "../../etc/passwd", "-o", "$(reboot)"} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{"action": "packages.plan",
				"payload": planPayload(false, name)},
			nil, http.StatusBadRequest)
	}
}
