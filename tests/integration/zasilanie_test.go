//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

type blokadaView struct {
	Who  string `json:"who"`
	Why  string `json:"why"`
	Mode string `json:"mode"`
}

type uruchomienieView struct {
	Index      int    `json:"index"`
	BootID     string `json:"boot_id"`
	FirstEntry string `json:"first_entry"`
}

type migawkaZasilania struct {
	BootID            string             `json:"boot_id"`
	BootedAt          string             `json:"booted_at"`
	UptimeSeconds     *float64           `json:"uptime_seconds"`
	RunningKernel     string             `json:"running_kernel"`
	RebootRequired    *bool              `json:"reboot_required"`
	RebootReasons     []string           `json:"reboot_reasons"`
	Inhibitors        []blokadaView      `json:"inhibitors"`
	InhibitorsKnown   bool               `json:"inhibitors_known"`
	LastBoots         []uruchomienieView `json:"last_boots"`
	UnavailableReason string             `json:"unavailable_reason"`
}

const powodZasilania = "test integracyjny modulu zasilania"

// TestZasilaniePokazujeStartHosta sprawdza fakty, na ktorych stoi kazda
// operacja restartu: identyfikator startu, czas dzialania i to, co wylaczenie
// wstrzymuje.
func TestZasilaniePokazujeStartHosta(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			stan := migawkaZasilaniaHosta(t, h, host.ID)
			if stan.UnavailableReason != "" {
				t.Fatalf("stanu startu nie odczytano: %s", stan.UnavailableReason)
			}
			if stan.BootID == "" || stan.BootedAt == "" {
				t.Errorf("host nie zglosil startu: %+v", stan.BootID)
			}
			// Host dzialajacy zero sekund nie istnieje: brak odczytu ma byc
			// pusty, a nie rowny zeru.
			if stan.UptimeSeconds == nil || *stan.UptimeSeconds <= 0 {
				t.Errorf("czas dzialania = %v", stan.UptimeSeconds)
			}
			if stan.RunningKernel == "" {
				t.Error("host nie zglosil dzialajacego jadra")
			}
			if stan.RebootRequired == nil {
				t.Error("potrzeba restartu nieustalona")
			}
			// Brak blokad i nieodczytane blokady to dwie rozne odpowiedzi.
			if !stan.InhibitorsKnown {
				t.Error("blokady wylaczenia nieodczytane")
			}
			if len(stan.LastBoots) == 0 {
				t.Error("host nie zglosil zadnego startu w dzienniku")
			}
			// Biezacy start ma indeks zero i ten sam identyfikator, ktory
			// host podaje jako swoj boot_id.
			for _, start := range stan.LastBoots {
				if start.Index != 0 {
					continue
				}
				if odmyslnik(start.BootID) != odmyslnik(stan.BootID) {
					t.Errorf("biezacy start = %q, boot_id hosta = %q", start.BootID, stan.BootID)
				}
			}
		})
	}
}

// TestWylaczenieWymagaPowoduINazwyCelu pilnuje bramek przy operacji, ktorej
// panel nie potrafi cofnac: nikt nie wlaczy tego hosta zdalnie.
func TestWylaczenieWymagaPowoduINazwyCelu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Bez nazwy celu: klikniecie nie jest wystarczajaca decyzja.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "system.shutdown", "reason": powodZasilania,
			"payload": map[string]any{"power": map[string]any{"reason": powodZasilania}}},
		nil, http.StatusBadRequest)

	// Bez powodu w payloadzie: slad audytowy jest jedyna rzecza, ktora po tej
	// operacji zostaje.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "system.shutdown", "reason": powodZasilania,
			"target_confirmation": host.Hostname,
			"payload":             map[string]any{"power": map[string]any{"reason": "bo tak"}}},
		nil, http.StatusBadRequest)

	// Tryb spoza listy nie dojezdza do hosta.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "system.shutdown", "reason": powodZasilania,
			"target_confirmation": host.Hostname,
			"payload": map[string]any{"power": map[string]any{
				"mode": "kexec", "reason": powodZasilania}}},
		nil, http.StatusBadRequest)
}

// TestOperacjaNieodwracalnaNieDzialaMasowo pilnuje granicy kampanii: nazwa
// celu jest jedyna bramka przy operacji bez drogi powrotu, a kampania nie ma
// jednego celu do wpisania.
func TestOperacjaNieodwracalnaNieDzialaMasowo(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, akcja := range []struct {
		typ     string
		payload map[string]any
	}{
		{"system.shutdown", map[string]any{"power": map[string]any{"reason": powodZasilania}}},
		{"disk.wipe", map[string]any{"storage": map[string]any{"device": "/dev/sdz"}}},
	} {
		t.Run(akcja.typ, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/campaigns", map[string]any{
				"name": "proba operacji nieodwracalnej", "action": akcja.typ,
				"payload":  akcja.payload,
				"selector": map[string]any{"host_ids": []string{host.ID}},
			}, nil, http.StatusBadRequest)
		})
	}
}

// TestOknoSerwisoweOmijaKampanie sprawdza, po co okno serwisowe istnieje:
// kampania ma ominac host, przy ktorym ktos pracuje.
func TestOknoSerwisoweOmijaKampanie(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Okno bez konca i okno bez powodu nie sa oknami.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
		map[string]any{"reason": "wymiana dysku"}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
		map[string]any{"duration_minutes": 30}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
		map[string]any{"duration_minutes": 60 * 24 * 60, "reason": "wymiana dysku"},
		nil, http.StatusBadRequest)

	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
			map[string]any{"clear": true}, nil, http.StatusOK)
	})

	var wOknie hostView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
		map[string]any{"duration_minutes": 30, "reason": powodZasilania}, &wOknie, http.StatusOK)
	if wOknie.Maintenance == nil {
		t.Fatal("host po otwarciu okna nie zglasza okna")
	}
	if wOknie.Maintenance.Reason != powodZasilania || wOknie.Maintenance.SetBy == "" {
		t.Errorf("okno = %+v", wOknie.Maintenance)
	}
	if !wOknie.Maintenance.Until.After(time.Now()) {
		t.Errorf("okno konczy sie w przeszlosci: %v", wOknie.Maintenance.Until)
	}

	// Kampania obejmujaca wylacznie host w oknie nie ma czego robic.
	h.do(http.MethodPost, "/api/v1/campaigns", map[string]any{
		"name": "proba okna serwisowego", "action": "unit.restart",
		"payload":  map[string]any{"unit": map[string]any{"unit": "cron.service"}},
		"selector": map[string]any{"host_ids": []string{host.ID}},
	}, nil, http.StatusBadRequest)

	// Zamkniete okno przestaje obowiazywac od razu, razem z powodem.
	var poZamknieciu hostView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
		map[string]any{"clear": true}, &poZamknieciu, http.StatusOK)
	if poZamknieciu.Maintenance != nil {
		t.Errorf("okno po zamknieciu = %+v", poZamknieciu.Maintenance)
	}
}

// odmyslnik usuwa myslniki z identyfikatora startu. Dziennik pisze go bez
// nich, /proc z nimi - to ten sam identyfikator.
func odmyslnik(identyfikator string) string {
	wynik := make([]byte, 0, len(identyfikator))
	for i := 0; i < len(identyfikator); i++ {
		if identyfikator[i] != '-' {
			wynik = append(wynik, identyfikator[i])
		}
	}
	return string(wynik)
}

func migawkaZasilaniaHosta(t *testing.T, h *harness, hostID string) migawkaZasilania {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/power", nil, &fragment, http.StatusOK)
	var stan migawkaZasilania
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		t.Fatalf("migawka zasilania: %v", err)
	}
	return stan
}
