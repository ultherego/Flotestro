//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

const powodCyklu = "test integracyjny cyklu zycia pakietow"

// pakietTestowy jest maly, bez zaleznosci poza standardem i nie nalezy do
// niczego, co host uruchamia. Wybor ma znaczenie: test instaluje go i usuwa
// na dzialajacej maszynie.
const pakietTestowy = "tree"

// TestCyklZyciaPakietowNaDNF pilnuje, ze instalacja, plan usuniecia,
// usuniecie i wstrzymanie dzialaja takze tam, gdzie menedzerem jest dnf.
//
// Rozdzial pakietow obiecuje adaptery APT i DNF; przez dlugi czas pelny cykl
// mial tylko apt, a Fedora dostawala odmowe "obslugiwany wylacznie dla apt".
func TestCyklZyciaPakietowNaDNF(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	// Instalacja.
	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "packages.install", "reason": powodCyklu,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{pakietTestowy},
		}},
	}, 10*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("instalacja zakonczyla sie stanem %s: %+v", zadanie.State, proby)
	}
	t.Cleanup(func() {
		// Sprzatanie idzie ta sama droga co reszta testu; gdy usuniecie
		// w tescie sie powiedzie, to wywolanie po prostu nic nie zmieni.
		h.createOperation(host.ID, map[string]any{
			"action": "packages.remove", "reason": powodCyklu,
			"target_confirmation": host.Hostname,
			"payload": map[string]any{"package_change": map[string]any{
				"packages": []string{pakietTestowy}, "expected_removals": []string{pakietTestowy},
			}},
		})
	})

	// Plan usuniecia: to on pokazuje, co zniknie razem z pakietem.
	plan := planUsunieciaDNF(t, h, host.ID, pakietTestowy)
	if len(plan.Removals) == 0 {
		t.Fatalf("plan usuniecia jest pusty: %+v", plan)
	}
	znaleziony := false
	for _, nazwa := range plan.Removals {
		if nazwa == pakietTestowy {
			znaleziony = true
		}
	}
	if !znaleziony {
		t.Fatalf("plan nie obejmuje pakietu, o ktory pytano: %+v", plan.Removals)
	}

	// Usuniecie wymaga zgody drugiej osoby w srodowisku produkcyjnym oraz
	// wpisania nazwy celu: to operacja nieodwracalna.
	usuniecie := h.createOperation(host.ID, map[string]any{
		"action": "packages.remove", "reason": powodCyklu,
		"target_confirmation": host.Hostname,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{pakietTestowy}, "expected_removals": plan.Removals,
		}},
	})
	stan := h.approve(usuniecie.ID, usuniecie.PayloadHash)
	if stan.State == "awaiting_approval" {
		druga := h.withToken(h.createPrincipal(uniqueSubject("druga-osoba-dnf"),
			[]map[string]string{{"role": "approver", "site": host.Site, "environment": host.Environment}}))
		stan = druga.approve(usuniecie.ID, usuniecie.PayloadHash)
	}
	koniec := h.awaitTerminal(usuniecie.ID, 10*time.Minute)
	if koniec.State != "succeeded" {
		t.Fatalf("usuniecie zakonczylo sie stanem %s: %+v", koniec.State, h.attempts(usuniecie.ID))
	}

	// Po usunieciu plan nie ma juz czego usuwac - i to jest odpowiedz,
	// a nie blad.
	po := planUsunieciaDNF(t, h, host.ID, pakietTestowy)
	if len(po.Removals) != 0 {
		t.Fatalf("po usunieciu plan nadal wskazuje %v", po.Removals)
	}
}

// TestWstrzymaniePakietuNaDNF pilnuje, ze wstrzymanie dziala takze na dnf -
// albo odmawia wprost, gdy host nie ma czym go zrobic.
func TestWstrzymaniePakietuNaDNF(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	wstrzymanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "packages.hold.set", "reason": powodCyklu,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{"restic"}, "hold": true,
		}},
	}, 5*time.Minute)
	if wstrzymanie.State != "succeeded" {
		// Host bez wtyczki versionlock musi odmowic z wyjasnieniem, a nie
		// milczaco uznac pakiet za wstrzymany.
		if len(proby) == 0 || !strings.Contains(proby[len(proby)-1].Message, "versionlock") {
			t.Fatalf("wstrzymanie zakonczylo sie stanem %s bez wyjasnienia: %+v",
				wstrzymanie.State, proby)
		}
		t.Skip("ten host nie ma wtyczki versionlock")
	}

	zwolnienie, proby := h.runOperation(host.ID, map[string]any{
		"action": "packages.hold.set", "reason": powodCyklu,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{"restic"}, "hold": false,
		}},
	}, 5*time.Minute)
	if zwolnienie.State != "succeeded" {
		t.Fatalf("zwolnienie zakonczylo sie stanem %s: %+v", zwolnienie.State, proby)
	}
}

// TestPlanUsunieciaNieMilczyOOdmowie pilnuje najgrozniejszej z mozliwych
// pomylek tego modulu: pusty plan czyta sie jako "nic nie zniknie", a odmowa
// menedzera znaczy cos zupelnie innego.
func TestPlanUsunieciaNieMilczyOOdmowie(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "packages.plan", "reason": powodCyklu,
		"payload": map[string]any{"package_plan": map[string]any{
			"mode": "remove", "only_packages": []string{"systemd"},
		}},
	}, 5*time.Minute)

	if zadanie.State == "succeeded" {
		szczegol := planUsunieciaZProby(t, proby)
		// Jesli menedzer plan ulozyl, systemd musi byc na liscie chronionych.
		if len(szczegol.Protected) == 0 {
			t.Fatalf("plan usuniecia systemd nie wskazuje pakietow chronionych: %+v", szczegol)
		}
		return
	}
	if len(proby) == 0 || proby[len(proby)-1].Message == "" {
		t.Fatal("odmowa planu bez wyjasnienia")
	}
}

func planUsunieciaDNF(t *testing.T, h *harness, hostID, pakiet string) packageDetail {
	t.Helper()
	zadanie, proby := h.runOperation(hostID, map[string]any{
		"action": "packages.plan", "reason": powodCyklu,
		"payload": map[string]any{"package_plan": map[string]any{
			"mode": "remove", "only_packages": []string{pakiet},
		}},
	}, 5*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("plan usuniecia zakonczyl sie stanem %s: %+v", zadanie.State, proby)
	}
	return planUsunieciaZProby(t, proby)
}

func planUsunieciaZProby(t *testing.T, proby []attemptView) packageDetail {
	t.Helper()
	if len(proby) == 0 || proby[len(proby)-1].Detail == nil {
		t.Fatal("zadanie planu nie ma wyniku")
	}
	return *proby[len(proby)-1].Detail
}
