//go:build integration

package integration

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

type zrodloCzasuView struct {
	Address       string   `json:"address"`
	State         string   `json:"state"`
	Stratum       *uint32  `json:"stratum"`
	OffsetSeconds *float64 `json:"offset_seconds"`
}

type serwerCzasuView struct {
	Address string `json:"address"`
	Source  string `json:"source"`
	Managed bool   `json:"managed"`
}

type pomiarCzasuView struct {
	Server        string   `json:"server"`
	Reachable     bool     `json:"reachable"`
	OffsetSeconds *float64 `json:"offset_seconds"`
	Error         string   `json:"error"`
}

type migawkaCzasu struct {
	Timezone          string            `json:"timezone"`
	Service           string            `json:"service"`
	Unit              string            `json:"unit"`
	Synchronized      *bool             `json:"synchronized"`
	OffsetSeconds     *float64          `json:"offset_seconds"`
	Sources           []zrodloCzasuView `json:"sources"`
	Configured        []serwerCzasuView `json:"configured_servers"`
	ManagedPath       string            `json:"managed_path"`
	ConfigPath        string            `json:"config_path"`
	CanAddSourceDir   bool              `json:"can_add_source_dir"`
	WriteReason       string            `json:"write_reason"`
	UnavailableReason string            `json:"unavailable_reason"`
}

type wynikCzasu struct {
	Kind    string            `json:"kind"`
	Message string            `json:"message"`
	Probes  []pomiarCzasuView `json:"probes"`
}

const powodCzasu = "test integracyjny modulu czasu"

// TestCzasPokazujeStanZegaraANieSamDemon sprawdza, ze modul odpowiada na
// pytanie "czy zegar tego hosta jest dobry", a nie tylko "czy demon dziala".
func TestCzasPokazujeStanZegaraANieSamDemon(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			stan := migawkaCzasuHosta(t, h, host.ID)
			if stan.UnavailableReason != "" {
				t.Fatalf("stanu czasu nie odczytano: %s", stan.UnavailableReason)
			}
			if stan.Timezone == "" {
				t.Error("host nie zglosil strefy czasowej")
			}
			if stan.Service == "" || stan.Unit == "" {
				t.Errorf("host nie nazwal demona czasu: service=%q unit=%q", stan.Service, stan.Unit)
			}
			// Nieznane nie jest falszem: pole ma byc wypelnione albo puste,
			// a nie udawac "niezsynchronizowany" przy braku odczytu.
			if stan.Synchronized == nil {
				t.Error("stan synchronizacji nieustalony mimo dzialajacego demona")
			}
			if len(stan.Sources) == 0 && len(stan.Configured) == 0 {
				t.Error("host nie zglosil ani zrodel, ani wpisow konfiguracyjnych")
			}
		})
	}
}

// TestTestZrodelCzasuMierzyZHosta sprawdza, ze pomiar wychodzi z hosta i ze
// serwer, ktory nie odpowiedzial, niesie powod zamiast przesuniecia zerowego.
func TestTestZrodelCzasuMierzyZHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Jeden adres nieroutowalny z puli dokumentacyjnej i zrodla, ktorych host
	// naprawde uzywa: wynik ma rozroznic te dwa przypadki.
	stan := migawkaCzasuHosta(t, h, host.ID)
	sondy := []string{"203.0.113.1"}
	if len(stan.Configured) > 0 {
		sondy = append(sondy, stan.Configured[0].Address)
	}

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "time.sync.test", "reason": powodCzasu,
		"payload": map[string]any{"time": map[string]any{"probe": sondy}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("test zrodel: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	wynik := wynikCzasuZadania(t, h, zadanie.ID)
	if len(wynik.Probes) != len(sondy) {
		t.Fatalf("pomiarow = %d, pytan = %d", len(wynik.Probes), len(sondy))
	}
	for _, pomiar := range wynik.Probes {
		switch {
		case pomiar.Reachable && pomiar.OffsetSeconds == nil:
			t.Errorf("serwer %s odpowiedzial bez pomiaru przesuniecia", pomiar.Server)
		case !pomiar.Reachable && pomiar.Error == "":
			t.Errorf("serwer %s milczy bez powodu", pomiar.Server)
		case !pomiar.Reachable && pomiar.OffsetSeconds != nil:
			t.Errorf("serwer %s nie odpowiedzial, a ma przesuniecie %v",
				pomiar.Server, *pomiar.OffsetSeconds)
		}
	}
	// Adres z puli dokumentacyjnej nie odpowiada nigdy; gdyby odpowiedzial,
	// pomiar mierzylby cos innego, niz sadzimy.
	for _, pomiar := range wynik.Probes {
		if pomiar.Server == "203.0.113.1" && pomiar.Reachable {
			t.Error("adres nieroutowalny odpowiedzial - test mierzy nie to, co sadzi")
		}
	}
}

// TestZmianaZrodelWymagaDzialajacegoZrodla pilnuje reguly z dokumentu:
// serwery sa testowane, zanim host odda dzialajace zrodlo.
func TestZmianaZrodelWymagaDzialajacegoZrodla(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	przed := migawkaCzasuHosta(t, h, host.ID)
	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "time.config.apply", "reason": powodCzasu,
		"payload": map[string]any{"time": map[string]any{
			"servers": []string{"203.0.113.1", "203.0.113.2"}}},
	}, 3*time.Minute)
	if zadanie.State == "succeeded" {
		t.Fatalf("panel przyjal zrodla, ktore nie odpowiadaja: %s", ostatniKomunikat(proby))
	}
	if !strings.Contains(ostatniKomunikat(proby), "nie odpowiedzial") {
		t.Errorf("odmowa bez powodu: %q", ostatniKomunikat(proby))
	}

	// Odmowa nie moze zostawic hosta z polowa zmiany.
	po := migawkaCzasuHosta(t, h, host.ID)
	if len(po.Configured) != len(przed.Configured) {
		t.Errorf("lista serwerow zmieniona mimo odmowy: %d -> %d",
			len(przed.Configured), len(po.Configured))
	}
}

// TestStrefaCzasowaZmieniaSiePoSprawdzeniu sprawdza cala droge zmiany strefy
// wraz z odmowami dla nazw, ktorych host nie zna albo ktore nie sa nazwami.
func TestStrefaCzasowaZmieniaSiePoSprawdzeniu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	przed := migawkaCzasuHosta(t, h, host.ID)

	// Sciezka wzgledna nie dojezdza do hosta: odrzuca ja walidacja zlecenia.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "time.timezone.set", "reason": powodCzasu,
			"payload": map[string]any{"time": map[string]any{"timezone": "../../etc/passwd"}}},
		nil, http.StatusBadRequest)

	// Nazwa poprawna, ale nieznana hostowi, konczy sie odmowa z powodem.
	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "time.timezone.set", "reason": powodCzasu,
		"payload": map[string]any{"time": map[string]any{"timezone": "Europe/Atlantyda"}},
	}, 2*time.Minute)
	if zadanie.State == "succeeded" {
		t.Error("panel ustawil strefe, ktorej host nie zna")
	}
	if !strings.Contains(ostatniKomunikat(proby), "nie zna strefy") {
		t.Errorf("odmowa bez powodu: %q", ostatniKomunikat(proby))
	}

	t.Cleanup(func() {
		if przed.Timezone == "" {
			return
		}
		h.runOperation(host.ID, map[string]any{
			"action": "time.timezone.set", "reason": powodCzasu,
			"payload": map[string]any{"time": map[string]any{"timezone": przed.Timezone}},
		}, 2*time.Minute)
	})

	docelowa := "Europe/Warsaw"
	if przed.Timezone == docelowa {
		docelowa = "Etc/UTC"
	}
	zadanie, proby = h.runOperation(host.ID, map[string]any{
		"action": "time.timezone.set", "reason": powodCzasu,
		"payload": map[string]any{"time": map[string]any{"timezone": docelowa}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("zmiana strefy: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	po := migawkaCzasuHosta(t, h, host.ID)
	if po.Timezone != docelowa {
		t.Errorf("strefa po zmianie = %q, oczekiwano %q", po.Timezone, docelowa)
	}
	// Zmiana strefy nie moze ruszyc chwili, w ktorej host zyje.
	if przed.OffsetSeconds != nil && po.OffsetSeconds != nil &&
		math.Abs(*po.OffsetSeconds-*przed.OffsetSeconds) > 1 {
		t.Errorf("zmiana strefy przesunela zegar: %v -> %v", *przed.OffsetSeconds, *po.OffsetSeconds)
	}
}

// TestPanelNieDopisujeSieDoCudzejKonfiguracjiBezZgody pilnuje granicy: host,
// ktory nie wlacza zadnego katalogu, zostaje tylko do odczytu, dopoki operator
// nie zgodzi sie na dopisanie jednego wiersza.
func TestPanelNieDopisujeSieDoCudzejKonfiguracjiBezZgody(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	stan := migawkaCzasuHosta(t, h, host.ID)
	if !stan.CanAddSourceDir {
		t.Skipf("ten host ma juz katalog panelu (%s), wiec nie ma czego dopisywac", stan.ManagedPath)
	}
	if stan.WriteReason == "" {
		t.Error("host tylko do odczytu nie podal powodu")
	}
	// Serwer musi byc osiagalny, inaczej zlecenie odpadnie na wczesniejszej
	// bramce i test sprawdzilby nie to, co mial.
	if len(stan.Sources) == 0 {
		t.Skip("host nie ma dzialajacego zrodla, wobec ktorego mozna zlozyc zlecenie")
	}

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "time.config.apply", "reason": powodCzasu,
		"payload": map[string]any{"time": map[string]any{
			"servers": []string{stan.Sources[0].Address}}},
	}, 3*time.Minute)
	if zadanie.State == "succeeded" {
		t.Fatal("panel dopisal sie do cudzej konfiguracji bez zgody")
	}
	// Odmowa ma nazwac warunek, ktorego host nie spelnia, a nie tylko
	// stwierdzic, ze sie nie da.
	if !strings.Contains(ostatniKomunikat(proby), "drop-in") {
		t.Errorf("odmowa bez powodu: %q", ostatniKomunikat(proby))
	}

	po := migawkaCzasuHosta(t, h, host.ID)
	if po.ManagedPath != "" {
		t.Errorf("panel zalozyl swoj plik mimo odmowy: %q", po.ManagedPath)
	}
}

func migawkaCzasuHosta(t *testing.T, h *harness, hostID string) migawkaCzasu {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/time", nil, &fragment, http.StatusOK)
	var stan migawkaCzasu
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		t.Fatalf("migawka czasu: %v", err)
	}
	return stan
}

// wynikCzasuZadania czyta pomiary z ostatniej proby. Pomiar nalezy do proby,
// bo to ona wie, co host zmierzyl i kiedy - stan hosta juz tego nie powie.
func wynikCzasuZadania(t *testing.T, h *harness, jobID string) wynikCzasu {
	t.Helper()
	var odpowiedz struct {
		Items []struct {
			Detail wynikCzasu `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+jobID+"/attempts", nil, &odpowiedz, http.StatusOK)
	if len(odpowiedz.Items) == 0 {
		t.Fatal("zadanie bez prob")
	}
	return odpowiedz.Items[len(odpowiedz.Items)-1].Detail
}
