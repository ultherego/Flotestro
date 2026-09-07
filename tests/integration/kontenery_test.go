//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"
)

type kontenerView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Networks []struct {
		Name string `json:"name"`
		ID   string `json:"id"`
		IPv4 string `json:"ipv4"`
	} `json:"networks"`
	Mounts []struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"mounts"`
}

type siecView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Predefined bool   `json:"predefined"`
	InUse      bool   `json:"in_use"`
	Containers []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"containers"`
}

type wolumenView struct {
	Name       string `json:"name"`
	InUse      bool   `json:"in_use"`
	SizeBytes  *int64 `json:"size_bytes"`
	SizeReason string `json:"size_reason"`
	UsedBy     []struct {
		ContainerName string `json:"container_name"`
		Destination   string `json:"destination"`
		State         string `json:"state"`
	} `json:"used_by"`
}

type stanSilnika struct {
	Summary struct {
		NetworksUnused int `json:"networks_unused"`
		VolumesUnused  int `json:"volumes_unused"`
	} `json:"summary"`
	Containers []kontenerView `json:"containers"`
	Networks   []siecView     `json:"networks"`
	Volumes    []wolumenView  `json:"volumes"`
}

const powodKontenerow = "test integracyjny sieci i wolumenow"

// TestUzycieSieciIWolumenowWynikaZKontenerow pilnuje wlasciwosci, bez ktorej
// ta zakladka klamie: silnik w liscie sieci zwraca pusta mape kontenerow,
// a rozmiar i licznik odwolan wolumenu podaje dopiero przy osobnym rachunku
// miejsca. Uzycie musi wiec byc wyliczone z kontenerow - inaczej kazda siec
// i kazdy wolumen wygladalyby na porzucone i trafily pod sprzatanie.
func TestUzycieSieciIWolumenowWynikaZKontenerow(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	stan := stanSilnikaHosta(t, h, host.ID)

	// Kazde podlaczenie zgloszone przez kontener ma miec odbicie w sieci.
	for _, kontener := range stan.Containers {
		for _, podlaczenie := range kontener.Networks {
			siec := siecPoNazwie(stan.Networks, podlaczenie.Name)
			if siec == nil {
				t.Errorf("kontener %s jest w sieci %s, ktorej nie ma na liscie",
					kontener.Name, podlaczenie.Name)
				continue
			}
			if !zawieraKontener(siec.Containers, kontener.ID) {
				t.Errorf("siec %s nie wymienia kontenera %s", siec.Name, kontener.Name)
			}
			if !siec.InUse {
				t.Errorf("siec %s ma kontener %s, a jest zglaszana jako nieuzywana",
					siec.Name, kontener.Name)
			}
		}
		for _, montowanie := range kontener.Mounts {
			if montowanie.Type != "volume" || montowanie.Name == "" {
				continue
			}
			wolumen := wolumenPoNazwie(stan.Volumes, montowanie.Name)
			if wolumen == nil {
				continue
			}
			// Kontener zatrzymany tez sie liczy: jego wolumen nie jest niczyj.
			if !wolumen.InUse {
				t.Errorf("wolumen %s montuje %s, a jest zglaszany jako wolny",
					wolumen.Name, kontener.Name)
			}
		}
	}

	// Uzycie bez kontenerow byloby wymyslone.
	for _, siec := range stan.Networks {
		if siec.InUse && len(siec.Containers) == 0 {
			t.Errorf("siec %s jest w uzyciu, ale bez kontenerow", siec.Name)
		}
	}
	for _, wolumen := range stan.Volumes {
		if wolumen.InUse && len(wolumen.UsedBy) == 0 {
			t.Errorf("wolumen %s jest w uzyciu, ale bez kontenerow", wolumen.Name)
		}
		// Nieznany rozmiar zostaje nieznany, ale z powodem: zero znaczyloby
		// wolumen pusty i gotowy do skasowania.
		if wolumen.SizeBytes == nil && wolumen.SizeReason == "" {
			t.Errorf("wolumen %s bez rozmiaru i bez powodu", wolumen.Name)
		}
	}

	// Sieci wbudowane silnika sa oznaczone: to one nigdy nie sa kandydatem
	// do sprzatania.
	for _, nazwa := range []string{"bridge", "host", "none"} {
		siec := siecPoNazwie(stan.Networks, nazwa)
		if siec == nil {
			t.Errorf("host nie zglosil sieci %s", nazwa)
			continue
		}
		if !siec.Predefined {
			t.Errorf("siec %s nie jest oznaczona jako wbudowana", nazwa)
		}
	}

	if licznik := policzNieuzywaneSieci(stan.Networks); licznik != stan.Summary.NetworksUnused {
		t.Errorf("podsumowanie mowi o %d nieuzywanych sieciach, lista ma %d",
			stan.Summary.NetworksUnused, licznik)
	}
}

// TestSprzatanieOdmawiaObiektuWUzyciu pilnuje granicy sprzatania. Odmowa ma
// przyjsc z hosta i miec wlasny kod: operator, ktory prosil o usuniecie
// wolumenu dzialajacej uslugi, ma zobaczyc, ze host odmowil, a nie ze
// operacja sie nie powiodla.
func TestSprzatanieOdmawiaObiektuWUzyciu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	stan := stanSilnikaHosta(t, h, host.ID)

	t.Run("siec w uzyciu", func(t *testing.T) {
		siec := pierwszaSiecWUzyciu(stan.Networks)
		if siec == nil {
			t.Skip("host nie ma sieci z podlaczonym kontenerem")
		}
		odmowa(t, h, host, map[string]any{"network_ids": []string{siec.ID}},
			"docker_object_in_use")
	})

	t.Run("siec wbudowana", func(t *testing.T) {
		siec := siecPoNazwie(stan.Networks, "bridge")
		if siec == nil {
			t.Skip("host nie zglosil sieci bridge")
		}
		odmowa(t, h, host, map[string]any{"network_ids": []string{siec.ID}},
			"docker_network_predefined")
	})

	t.Run("wolumen w uzyciu", func(t *testing.T) {
		wolumen := pierwszyWolumenWUzyciu(stan.Volumes)
		if wolumen == nil {
			t.Skip("host nie ma wolumenu montowanego przez kontener")
		}
		odmowa(t, h, host, map[string]any{"volume_names": []string{wolumen.Name}},
			"docker_object_in_use")
	})

	// Cisza po usunieciu czegos, czego nie ma, bylaby gorsza niz odmowa:
	// operator uznalby, ze cos sprzatnal.
	t.Run("wolumen nieistniejacy", func(t *testing.T) {
		odmowa(t, h, host, map[string]any{"volume_names": []string{"nie-ma-takiego-wolumenu"}},
			"docker_object_missing")
	})
}

// odmowa zleca sprzatanie i wymaga, by host odmowil z podanym kodem.
//
// Sprzatanie usuwa dane bezpowrotnie, wiec wymaga zgody dwoch osob. Test
// zbiera obie: bez tej drugiej zadanie zostaloby w awaiting_approval i nikt
// by sie nie dowiedzial, czy host w ogole by odmowil.
func odmowa(t *testing.T, h *harness, host hostView, sprzatanie map[string]any, kod string) {
	t.Helper()
	zadanie := h.createOperation(host.ID, map[string]any{
		"action": "docker.prune", "reason": powodKontenerow,
		"target_confirmation": host.Hostname,
		"payload":             map[string]any{"docker_prune": sprzatanie},
	})
	zadanie = h.approve(zadanie.ID, zadanie.PayloadHash)
	if zadanie.CollectedApprovals < zadanie.RequiredApprovals {
		drugi := h.withToken(h.createPrincipal(uniqueSubject("approver-sprzatanie"),
			[]map[string]string{
				{"role": "approver", "site": host.Site, "environment": host.Environment},
			}))
		drugi.approve(zadanie.ID, zadanie.PayloadHash)
	}

	koncowe := h.awaitTerminal(zadanie.ID, 2*time.Minute)
	if koncowe.State == "succeeded" {
		t.Fatalf("host wykonal sprzatanie, ktorego mial odmowic: %v", sprzatanie)
	}
	if koncowe.ResultErrorCode != kod {
		t.Fatalf("kod odmowy = %q, oczekiwano %q (%s)",
			koncowe.ResultErrorCode, kod, ostatniKomunikat(h.attempts(zadanie.ID)))
	}
}

func stanSilnikaHosta(t *testing.T, h *harness, hostID string) stanSilnika {
	t.Helper()
	zadanie, proby := h.runOperation(hostID, map[string]any{
		"action": "docker.read", "reason": powodKontenerow,
		"payload": map[string]any{"docker_read": map[string]any{}},
	}, 3*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("odczyt silnika: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	var fragment struct {
		Payload           stanSilnika `json:"payload"`
		UnavailableReason string      `json:"unavailable_reason"`
	}
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/containers.full",
		nil, &fragment, http.StatusOK)
	if fragment.UnavailableReason != "" {
		t.Skipf("silnik kontenerow niedostepny: %s", fragment.UnavailableReason)
	}
	return fragment.Payload
}

func siecPoNazwie(sieci []siecView, nazwa string) *siecView {
	for i := range sieci {
		if sieci[i].Name == nazwa {
			return &sieci[i]
		}
	}
	return nil
}

func wolumenPoNazwie(wolumeny []wolumenView, nazwa string) *wolumenView {
	for i := range wolumeny {
		if wolumeny[i].Name == nazwa {
			return &wolumeny[i]
		}
	}
	return nil
}

func pierwszaSiecWUzyciu(sieci []siecView) *siecView {
	for i := range sieci {
		if sieci[i].InUse && !sieci[i].Predefined {
			return &sieci[i]
		}
	}
	return nil
}

func pierwszyWolumenWUzyciu(wolumeny []wolumenView) *wolumenView {
	for i := range wolumeny {
		if wolumeny[i].InUse {
			return &wolumeny[i]
		}
	}
	return nil
}

func zawieraKontener(lista []struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}, id string) bool {
	for _, pozycja := range lista {
		if pozycja.ID == id {
			return true
		}
	}
	return false
}

func policzNieuzywaneSieci(sieci []siecView) int {
	licznik := 0
	for _, siec := range sieci {
		if !siec.InUse && !siec.Predefined {
			licznik++
		}
	}
	return licznik
}

type zdarzenieView struct {
	Time       time.Time         `json:"time"`
	Type       string            `json:"type"`
	Action     string            `json:"action"`
	ActorID    string            `json:"actor_id"`
	ActorName  string            `json:"actor_name"`
	Attributes map[string]string `json:"attributes"`
}

type wynikZdarzen struct {
	Kind   string `json:"kind"`
	Events struct {
		Events    []zdarzenieView `json:"events"`
		Since     time.Time       `json:"since"`
		Until     time.Time       `json:"until"`
		Types     []string        `json:"types"`
		Truncated bool            `json:"truncated"`
	} `json:"events"`
	UnavailableReason string `json:"unavailable_reason"`
}

// TestOdczytZdarzenKonczySieSam pilnuje wlasciwosci, bez ktorej ta operacja
// nie moglaby istniec: odczyt jest zamkniety w oknie i konczy sie sam, takze
// gdy nikt na niego nie czeka. Zadanie czytajace zdarzenia "do odwolania"
// zostaloby na hoscie na zawsze.
func TestOdczytZdarzenKonczySieSam(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	start := time.Now()
	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "docker.events", "reason": powodKontenerow,
		"payload": map[string]any{"docker_events": map[string]any{
			"since_seconds": 3600, "follow_seconds": 5, "max_events": 50,
		}},
	}, 3*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("odczyt zdarzen: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}
	// Sledzenie 5 sekund ma sie skonczyc w kilkanascie sekund, a nie po
	// limicie czasu zadania.
	if trwalo := time.Since(start); trwalo > time.Minute {
		t.Errorf("odczyt z oknem sledzenia 5 s trwal %s", trwalo)
	}

	wynik := wynikZdarzenZadania(t, h, zadanie.ID)
	if wynik.UnavailableReason != "" {
		t.Skipf("silnik kontenerow niedostepny: %s", wynik.UnavailableReason)
	}
	if wynik.Kind != "docker_events" {
		t.Fatalf("rodzaj wyniku = %q", wynik.Kind)
	}
	// Okno musi wrocic w wyniku: bez niego pusta lista nie mowi nic, bo
	// cisza w oknie i brak odczytu wygladaja tak samo.
	if wynik.Events.Since.IsZero() || wynik.Events.Until.IsZero() {
		t.Fatalf("wynik bez okna: %+v", wynik.Events)
	}
	if !wynik.Events.Until.After(wynik.Events.Since) {
		t.Errorf("okno konczy sie przed poczatkiem: %s - %s",
			wynik.Events.Since, wynik.Events.Until)
	}
	if len(wynik.Events.Types) != 4 {
		t.Errorf("brak filtra mial dac cztery rodzaje, jest %v", wynik.Events.Types)
	}
	for _, zdarzenie := range wynik.Events.Events {
		if zdarzenie.Type == "" || zdarzenie.Action == "" {
			t.Errorf("zdarzenie bez rodzaju albo dzialania: %+v", zdarzenie)
		}
		if zdarzenie.Time.Before(wynik.Events.Since.Add(-time.Minute)) {
			t.Errorf("zdarzenie %s spoza okna (%s)", zdarzenie.Time, wynik.Events.Since)
		}
	}
}

// TestOdczytZdarzenWidziOperacjeNaHoscie sprawdza, ze dziennik odpowiada na
// pytanie, na ktore stan hosta nie odpowiada: co sie tu wydarzylo. Restart
// kontenera zostawia w stanie ten sam kontener co przedtem, a w dzienniku -
// slad.
func TestOdczytZdarzenWidziOperacjeNaHoscie(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	stan := stanSilnikaHosta(t, h, host.ID)
	var cel *kontenerView
	for i := range stan.Containers {
		if stan.Containers[i].State == "running" {
			cel = &stan.Containers[i]
			break
		}
	}
	if cel == nil {
		t.Skip("host nie ma dzialajacego kontenera")
	}

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "docker.container.restart", "reason": powodKontenerow,
		"payload": map[string]any{"docker_container": map[string]any{
			"container_id": cel.ID, "name": cel.Name, "timeout_seconds": 10,
		}},
	}, 3*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("restart kontenera: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	zdarzenia, proby := h.runOperation(host.ID, map[string]any{
		"action": "docker.events", "reason": powodKontenerow,
		"payload": map[string]any{"docker_events": map[string]any{
			"since_seconds": 300, "types": []string{"container"}, "max_events": 200,
		}},
	}, 3*time.Minute)
	if zdarzenia.State != "succeeded" {
		t.Fatalf("odczyt zdarzen: stan = %s, %s", zdarzenia.State, ostatniKomunikat(proby))
	}

	wynik := wynikZdarzenZadania(t, h, zdarzenia.ID)
	if wynik.UnavailableReason != "" {
		t.Skipf("silnik kontenerow niedostepny: %s", wynik.UnavailableReason)
	}
	znalezione := false
	for _, zdarzenie := range wynik.Events.Events {
		if zdarzenie.Type != "container" {
			t.Errorf("filtr container przepuscil %q", zdarzenie.Type)
		}
		if zdarzenie.ActorName == cel.Name && zdarzenie.Action == "restart" {
			znalezione = true
		}
	}
	if !znalezione {
		t.Errorf("dziennik nie zna restartu kontenera %s", cel.Name)
	}
}

// TestZlecenieZdarzenSpozaOknaJestOdrzucane pilnuje, ze granice sa czescia
// kontraktu operacji: operator dowiaduje sie o nich przy zlecaniu, a nie
// przez ciche przyciecie na hoscie.
func TestZlecenieZdarzenSpozaOknaJestOdrzucane(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for nazwa, zamowienie := range map[string]map[string]any{
		"okno wstecz":     {"since_seconds": 7 * 24 * 3600},
		"sledzenie":       {"follow_seconds": 3600},
		"limit zdarzen":   {"max_events": 100000},
		"nieznany rodzaj": {"types": []string{"daemon"}},
	} {
		t.Run(nazwa, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{
					"action": "docker.events", "reason": powodKontenerow,
					"payload": map[string]any{"docker_events": zamowienie},
				}, nil, http.StatusBadRequest)
		})
	}
}

func wynikZdarzenZadania(t *testing.T, h *harness, jobID string) wynikZdarzen {
	t.Helper()
	var odpowiedz struct {
		Items []struct {
			Detail wynikZdarzen `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+jobID+"/attempts", nil, &odpowiedz, http.StatusOK)
	if len(odpowiedz.Items) == 0 {
		t.Fatal("zadanie bez prob")
	}
	return odpowiedz.Items[len(odpowiedz.Items)-1].Detail
}
