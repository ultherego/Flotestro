//go:build integration

package integration

import (
	"net/http"
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

// TestInventoryJestPodzieloneNaModuly sprawdza, ze zakladka moze pobrac
// dokladnie to, co pokazuje, wraz z wlasna rewizja i wlasna swiezoscia.
// Wczesniej wszystkie zakladki dzielily jedna date obserwacji, wiec operator
// patrzacy na pakiety widzial swiezosc zupelnie czegos innego.
func TestInventoryJestPodzieloneNaModuly(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	rewizje := map[string]string{}
	for _, modul := range []string{"system", "packages", "services", "identity", "accounts", "network"} {
		t.Run(modul, func(t *testing.T) {
			var fragment inventoryFragment
			h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/"+modul,
				nil, &fragment, http.StatusOK)

			if fragment.Module != modul {
				t.Errorf("modul = %q, oczekiwano %q", fragment.Module, modul)
			}
			if fragment.Revision == "" {
				t.Error("modul bez wlasnej rewizji")
			}
			// Dane bez zrodla nie daja sie ocenic: operator nie wie, czy
			// patrzy na odczyt z hosta, czy na cache sprzed godziny.
			if fragment.Source == "" {
				t.Error("modul nie podaje zrodla odczytu")
			}
			if fragment.ObservedAt.IsZero() {
				t.Error("modul nie podaje znacznika obserwacji")
			}
			if len(fragment.Payload) == 0 {
				t.Error("modul bez tresci")
			}
			rewizje[modul] = fragment.Revision
		})
	}

	// Rewizje modulow sa niezalezne. Gdyby wszystkie byly rowne, podzial
	// istnialby tylko w adresie, a nie w danych.
	widziane := map[string]bool{}
	for modul, rewizja := range rewizje {
		if widziane[rewizja] {
			t.Errorf("modul %s dzieli rewizje z innym modulem", modul)
		}
		widziane[rewizja] = true
	}
}

// TestNiezgloszonyModulJestBrakiemZasobu pilnuje granicy miedzy modulem
// pustym a modulem, ktorego host nie zglosil. To dwie rozne odpowiedzi.
func TestNiezgloszonyModulJestBrakiemZasobu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	// Nazwa celowo nie odpowiada zadnemu modulowi i nigdy nie bedzie:
	// granica dotyczy odpowiedzi na modul niezgloszony, a nie konkretnego
	// modulu, ktory za tydzien powstanie i wywroci ten test.
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/modul-ktorego-nie-ma",
		nil, nil, http.StatusNotFound)
}

// TestModulKontenerowJestZgloszonyTylkoZSilnikiem sprawdza, ze host bez
// silnika kontenerow nie udaje hosta, na ktorym po prostu nic nie stoi.
// Pusty modul i modul niedostepny to dwie rozne odpowiedzi.
func TestModulKontenerowJestZgloszonyTylkoZSilnikiem(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			maSilnik := maAdapter(host, "docker")

			var fragment inventoryFragment
			h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/containers",
				nil, &fragment, http.StatusOK)

			if fragment.Source != "agent/docker-engine" {
				t.Errorf("zrodlo = %q", fragment.Source)
			}
			if maSilnik && fragment.UnavailableReason != "" {
				t.Errorf("host z silnikiem podaje powod niedostepnosci: %q", fragment.UnavailableReason)
			}
			// Host bez silnika musi powiedziec dlaczego, zamiast milczec.
			if !maSilnik && fragment.UnavailableReason == "" {
				t.Error("host bez silnika nie wyjasnia braku kontenerow")
			}
		})
	}
}

// TestOdczytKontenerowNaZadanie sprawdza sciezke, ktora operator uruchamia,
// otwierajac zakladke: pelne listy sa pobierane operacja, a nie w kazdym
// cyklu inwentarza.
func TestOdczytKontenerowNaZadanie(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !maAdapter(host, "docker") {
		t.Skip("host testowy nie ma silnika kontenerow")
	}

	job, _ := h.runOperation(host.ID, map[string]any{
		"action":  "docker.read",
		"payload": map[string]any{"docker_read": map[string]any{}},
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("stan = %s, kod = %s", job.State, job.ResultErrorCode)
	}
	// Odczyt niczego nie zmienia, wiec nie moze wymagac zatwierdzenia.
	if job.RequiresApprova {
		t.Error("odczyt kontenerow wymaga zatwierdzenia, choc niczego nie zmienia")
	}

	// Wynik nalezy do stanu hosta, a nie do historii zadan: zakladka pyta
	// o stan i ma go dostac bez przegladania operacji.
	var pelny inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/containers.full",
		nil, &pelny, http.StatusOK)
	if len(pelny.Payload) == 0 {
		t.Error("pelny stan kontenerow jest pusty")
	}
}

// TestHostBezSilnikaOdrzucaOdczytKontenerow pilnuje, ze operacja bez pokrycia
// w adapterze zostaje odrzucona przy zlecaniu, a nie po dostarczeniu.
func TestHostBezSilnikaOdrzucaOdczytKontenerow(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	if maAdapter(host, "docker") {
		t.Skip("host rhel ma silnik kontenerow")
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "docker.read",
			"payload": map[string]any{"docker_read": map[string]any{}}},
		nil, http.StatusConflict)
}

// TestOperacjaNiszczacaWymagaPotwierdzeniaCelu sprawdza brame z rozdzialu 6.1:
// zmiany, ktorej nie da sie cofnac, nie wolno zleci klikniecem. Operator musi
// podac powod i przepisac nazwe hosta.
func TestOperacjaNiszczacaWymagaPotwierdzeniaCelu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !maAdapter(host, "docker") {
		t.Skip("host testowy nie ma silnika kontenerow")
	}
	const kontener = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Bez powodu operacja nie moze powstac: powod zostaje w audycie.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":  "docker.container.remove",
			"payload": map[string]any{"docker_container": map[string]any{"container_id": kontener}},
		}, nil, http.StatusBadRequest)

	// Z powodem, ale bez przepisanej nazwy hosta - nadal odmowa.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":  "docker.container.remove",
			"reason":  "porzadki w laboratorium",
			"payload": map[string]any{"docker_container": map[string]any{"container_id": kontener}},
		}, nil, http.StatusBadRequest)

	// Nazwa innego hosta nie jest potwierdzeniem tego hosta.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":              "docker.container.remove",
			"reason":              "porzadki w laboratorium",
			"target_confirmation": "zupelnie-inny-host",
			"payload":             map[string]any{"docker_container": map[string]any{"container_id": kontener}},
		}, nil, http.StatusBadRequest)
}

// TestOperacjaOdwracalnaNieWymagaPrzepisywaniaNazwy pilnuje, ze brama nie
// rozlala sie na wszystko. Restart kontenera jest odwracalny i ma isc jednym
// klikniecem, jak kazda inna operacja.
func TestOperacjaOdwracalnaNieWymagaPrzepisywaniaNazwy(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !maAdapter(host, "docker") {
		t.Skip("host testowy nie ma silnika kontenerow")
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "docker.container.start",
			"payload": map[string]any{"docker_container": map[string]any{
				"container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			}},
		}, nil, http.StatusCreated)
}

// TestNieprawidlowyCelKontenerowyJestOdrzucany sprawdza walidacje po stronie
// API. Identyfikator trafia do sciezki zapytania Engine API, wiec nie moze
// niesc niczego, co ta sciezke zmienia.
func TestNieprawidlowyCelKontenerowyJestOdrzucany(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !maAdapter(host, "docker") {
		t.Skip("host testowy nie ma silnika kontenerow")
	}
	for _, id := range []string{"moj-kontener", "../images/json", "abc", ""} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{
				"action":  "docker.container.stop",
				"payload": map[string]any{"docker_container": map[string]any{"container_id": id}},
			}, nil, http.StatusBadRequest)
	}
}

// TestWdrozenieProjektuWymagaZatwierdzonegoPlanu sprawdza granice z rozdzialu
// 7: wdrozenie manifestu uruchamia na hoscie obrazy wskazane przez operatora,
// wiec nie wolno go zlecic bez planu, ktory ten operator obejrzal.
func TestWdrozenieProjektuWymagaZatwierdzonegoPlanu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !maAdapter(host, "docker.compose") {
		t.Skip("host testowy nie ma wtyczki compose")
	}
	const manifest = "services:\n  web:\n    image: nginx:alpine\n"

	// Bez hasha planu wdrozenie nie ma podstawy.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "docker.compose.deploy",
			"reason": "wdrozenie projektu testowego",
			"payload": map[string]any{"compose": map[string]any{
				"project": "testowy", "manifest": manifest,
			}},
		}, nil, http.StatusBadRequest)

	// Planowanie niczego nie zmienia, wiec nie wymaga ani powodu, ani
	// zatwierdzenia.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "docker.compose.plan",
		"payload": map[string]any{"compose": map[string]any{
			"project": "testowy", "manifest": manifest,
		}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("plan: stan = %s, kod = %s", job.State, job.ResultErrorCode)
	}
	if job.RequiresApprova {
		t.Error("planowanie projektu wymaga zatwierdzenia, choc niczego nie zmienia")
	}
	if len(attempts) == 0 || attempts[len(attempts)-1].Detail == nil {
		t.Fatal("plan nie zwrocil wyniku")
	}
}

// TestNieprawidlowyProjektJestOdrzucany sprawdza walidacje po stronie API.
// Nazwa projektu trafia do argumentu polecenia i do nazw kontenerow.
func TestNieprawidlowyProjektJestOdrzucany(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !maAdapter(host, "docker.compose") {
		t.Skip("host testowy nie ma wtyczki compose")
	}
	for _, projekt := range []string{"", "Sklep", "sklep;reboot", "../etc"} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{
				"action": "docker.compose.plan",
				"payload": map[string]any{"compose": map[string]any{
					"project": projekt, "manifest": "services: {}",
				}},
			}, nil, http.StatusBadRequest)
	}
	// Pusty manifest tez nie jest projektem.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "docker.compose.plan",
			"payload": map[string]any{"compose": map[string]any{
				"project": "sklep", "manifest": "   ",
			}},
		}, nil, http.StatusBadRequest)
}
