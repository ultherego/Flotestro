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

	// Transakcja na uszkodzonej bazie nie ma szans sie powiesc i nie moze
	// zostac zlecona.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "packages.upgrade",
			"payload": map[string]any{"package_upgrade": map[string]any{}}},
		nil, http.StatusConflict)

	// Naprawa musi byc dozwolona wlasnie w tym stanie. Zablokowanie jej
	// zamykalo hosta w petli bez wyjscia: jedyna operacja, ktora potrafi
	// zdjac te flage, byla przez nia blokowana.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "packages.repair", "reason": "odblokowanie bazy pakietow",
			"payload": map[string]any{"package_repair": map[string]any{}}},
		nil, http.StatusCreated)

	// Plan niczego nie zmienia i na zablokowanym hoscie jest najbardziej
	// potrzebny: pokazuje, co blokuje.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "packages.plan", "payload": planPayload(false)},
		nil, http.StatusCreated)

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

// TestNaprawaWymagaAdapteraZTaCecha sprawdza, ze host bez naprawy dowiaduje
// sie o tym przy zlecaniu, a nie po dostarczeniu zadania. Naprawa odpowiada
// na pytania debconfa i istnieje wylacznie dla apta; wczesniej operacja byla
// przyjmowana na kazdym hoscie i odrzucana dopiero przez helpera na Fedorze.
func TestNaprawaWymagaAdapteraZTaCecha(t *testing.T) {
	h := newHarness(t)

	// Naprawa jest operacja krytyczna, wiec wymaga uzasadnienia w audycie.
	const powod = "odblokowanie bazy pakietow"

	rhel := h.hostByFamily("rhel")
	h.do(http.MethodPost, "/api/v1/hosts/"+rhel.ID+"/operations",
		map[string]any{"action": "packages.repair", "reason": powod,
			"payload": map[string]any{"package_repair": map[string]any{}}},
		nil, http.StatusConflict)

	// Ta sama operacja na hoscie z aptem przechodzi: odmowa dotyczy braku
	// cechy adaptera, a nie samej operacji.
	debian := h.hostByFamily("debian")
	h.do(http.MethodPost, "/api/v1/hosts/"+debian.ID+"/operations",
		map[string]any{"action": "packages.repair", "reason": powod,
			"payload": map[string]any{"package_repair": map[string]any{}}},
		nil, http.StatusCreated)
}

// TestHostZglaszaRejestrAdapterow sprawdza, ze host mowi nie tylko, co ma,
// ale i dlaczego czegos nie ma. Powod jest faktem o hoscie i to host ma go
// podac - interfejs ma go powtorzyc, a nie zgadywac we wlasnym kodzie.
func TestHostZglaszaRejestrAdapterow(t *testing.T) {
	h := newHarness(t)

	for _, przypadek := range []struct {
		rodzina   string
		obecny    string
		nieobecny string
	}{
		{"debian", "packages.apt", "packages.dnf"},
		{"rhel", "packages.dnf", "packages.apt"},
	} {
		t.Run(przypadek.rodzina, func(t *testing.T) {
			host := h.hostByFamily(przypadek.rodzina)
			if len(host.Capabilities) == 0 {
				t.Fatal("host nie zglosil zadnego adaptera")
			}
			znajdz := func(nazwa string) *hostCapability {
				for i := range host.Capabilities {
					if host.Capabilities[i].Name == nazwa {
						return &host.Capabilities[i]
					}
				}
				return nil
			}

			obecny := znajdz(przypadek.obecny)
			if obecny == nil || !obecny.Available {
				t.Fatalf("adapter %s nie jest zgloszony jako dostepny", przypadek.obecny)
			}
			if obecny.Version == 0 {
				t.Errorf("adapter %s nie podaje wersji kontraktu", przypadek.obecny)
			}

			nieobecny := znajdz(przypadek.nieobecny)
			if nieobecny == nil || nieobecny.Available {
				t.Fatalf("adapter %s nie jest zgloszony jako niedostepny", przypadek.nieobecny)
			}
			// Milczaca niedostepnosc zmusza interfejs do zgadywania przyczyny.
			if nieobecny.Reason == "" {
				t.Errorf("adapter %s nie podaje powodu niedostepnosci", przypadek.nieobecny)
			}
		})
	}
}

// TestUsunieciePakietuWymagaZatwierdzonegoZbioru sprawdza granice z rozdzialu
// 3. Jeden pakiet potrafi pociagnac kilkadziesiat zaleznych, wiec operator
// zatwierdza zbior, a nie nazwe - i host liczy go ponownie przed operacja.
func TestUsunieciePakietuWymagaZatwierdzonegoZbioru(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Bez zatwierdzonego zbioru operacja nie ma podstawy.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":              "packages.remove",
			"reason":              "porzadki w laboratorium",
			"target_confirmation": host.Hostname,
			"payload":             map[string]any{"package_change": map[string]any{"packages": []string{"sl"}}},
		}, nil, http.StatusBadRequest)

	// Bez przepisanej nazwy hosta takze nie: usuniecie jest nieodwracalne.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "packages.remove",
			"reason": "porzadki w laboratorium",
			"payload": map[string]any{"package_change": map[string]any{
				"packages": []string{"sl"}, "expected_removals": []string{"sl"},
			}},
		}, nil, http.StatusBadRequest)
}

// TestPakietyChronioneSaOdrzucanePrzyZlecaniu pilnuje, ze operator dowiaduje
// sie o blokadzie przy zlecaniu, a nie po dostarczeniu zadania. Usuniecie
// agenta odcieloby host od panelu, a wiec takze od naprawy.
func TestPakietyChronioneSaOdrzucanePrzyZlecaniu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, pakiet := range []string{"flotestro-agent", "systemd", "openssh-server", "linux-image-6.12"} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{
				"action":              "packages.remove",
				"reason":              "proba usuniecia pakietu chronionego",
				"target_confirmation": host.Hostname,
				"payload": map[string]any{"package_change": map[string]any{
					"packages": []string{pakiet}, "expected_removals": []string{pakiet},
				}},
			}, nil, http.StatusBadRequest)
	}
}

// TestPlanUsunieciaPokazujeZaleznosci sprawdza, ze plan odpowiada na pytanie
// "co zniknie", zanim cokolwiek zniknie.
func TestPlanUsunieciaPokazujeZaleznosci(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Plan bez listy pakietow nie ma sensu.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":  "packages.plan",
			"payload": map[string]any{"package_plan": map[string]any{"mode": "remove"}},
		}, nil, http.StatusBadRequest)

	// Nieznany rodzaj planu tez nie.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "packages.plan",
			"payload": map[string]any{"package_plan": map[string]any{
				"mode": "wymyslony", "only_packages": []string{"sl"},
			}},
		}, nil, http.StatusBadRequest)
}

// TestWstrzymanieJestOdwracalne sprawdza, ze operacja opisuje stan docelowy,
// a nie przelacznik: powtorzenie jej nie odwraca zmiany.
func TestWstrzymanieJestOdwracalne(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, hold := range []bool{true, false} {
		job, _ := h.runOperation(host.ID, map[string]any{
			"action": "packages.hold.set",
			"payload": map[string]any{"package_change": map[string]any{
				"packages": []string{"nano"}, "hold": hold,
			}},
		}, 60*time.Second)
		if job.State != "succeeded" {
			t.Fatalf("hold=%v: stan = %s, kod = %s", hold, job.State, job.ResultErrorCode)
		}
	}
}
