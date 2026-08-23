//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type linkDNSView struct {
	Name         string   `json:"name"`
	Servers      []string `json:"servers"`
	Domains      []string `json:"domains"`
	DefaultRoute *bool    `json:"default_route"`
}

type migawkaDNS struct {
	Owner             string        `json:"owner"`
	Mode              string        `json:"mode"`
	ResolvConf        string        `json:"resolv_conf"`
	Servers           []string      `json:"servers"`
	SearchDomains     []string      `json:"search_domains"`
	Links             []linkDNSView `json:"links"`
	Writable          bool          `json:"writable"`
	WriteAdapter      string        `json:"write_adapter"`
	ReadOnlyReason    string        `json:"read_only_reason"`
	UnavailableReason string        `json:"unavailable_reason"`
}

type zapytanieView struct {
	Name       string   `json:"name"`
	Addresses  []string `json:"addresses"`
	Server     string   `json:"server"`
	Error      string   `json:"error"`
	TookMillis int64    `json:"took_millis"`
}

// TestResolverMaWlascicielaIPowodDlaTylkoOdczytu sprawdza rzecz, ktora
// rozstrzyga o kazdej zmianie DNS: kto pisze plik resolvera. Plik nalezacy
// do uslugi zostanie nadpisany, wiec zapis w nim znikalby sam.
func TestResolverMaWlascicielaIPowodDlaTylkoOdczytu(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			stan := migawkaDNSHosta(t, h, host.ID)
			if stan.UnavailableReason != "" {
				t.Fatalf("stanu resolvera nie odczytano: %s", stan.UnavailableReason)
			}
			if stan.Owner == "" {
				t.Error("host nie powiedzial, kto pisze jego resolv.conf")
			}
			if len(stan.Servers) == 0 {
				t.Error("host nie zglosil zadnego serwera DNS")
			}
			// Host tylko do odczytu ma powiedziec dlaczego, zamiast milczec.
			if !stan.Writable && stan.ReadOnlyReason == "" {
				t.Error("host bez mozliwosci zapisu nie tlumaczy, dlaczego")
			}
			if stan.Writable && stan.WriteAdapter == "" {
				t.Error("host z mozliwoscia zapisu nie nazwal mechanizmu")
			}
		})
	}
}

// TestTestRozwiazywaniaPytaZHosta sprawdza, ze odpowiedz pochodzi z hosta
// i niesie powod, gdy nazwy nie da sie rozwiazac. Cisza w miejscu odpowiedzi
// wygladalaby jak nazwa bez adresu.
func TestTestRozwiazywaniaPytaZHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "dns.resolve.test",
		"payload": map[string]any{"dns": map[string]any{
			"names": []string{"ipa.flotestro.test", "nie-ma-takiej-nazwy.flotestro.test"}}},
	}, 90*time.Second)
	if zadanie.State != "succeeded" {
		t.Fatalf("test rozwiazywania: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	zapytania := zapytaniaZadania(t, h, zadanie.ID)
	if len(zapytania) != 2 {
		t.Fatalf("zapytan = %d", len(zapytania))
	}
	po := map[string]zapytanieView{}
	for _, zapytanie := range zapytania {
		po[zapytanie.Name] = zapytanie
	}
	rozwiazana := po["ipa.flotestro.test"]
	if len(rozwiazana.Addresses) == 0 {
		t.Errorf("nazwa domeny nierozwiazana: %+v", rozwiazana)
	}
	// Zrodlo odpowiedzi jest tu polowa odpowiedzi: przy diagnozie DNS pytanie
	// brzmi "kto mi to powiedzial".
	if rozwiazana.Server == "" {
		t.Error("odpowiedz nie mowi, skad przyszla")
	}
	nierozwiazana := po["nie-ma-takiej-nazwy.flotestro.test"]
	if len(nierozwiazana.Addresses) != 0 {
		t.Errorf("nieistniejaca nazwa dostala adres: %+v", nierozwiazana)
	}
	if nierozwiazana.Error == "" {
		t.Error("nierozwiazana nazwa bez powodu")
	}
	// Kod wyjscia nie jest powodem: operator ma przeczytac, co powiedzial
	// resolver.
	if strings.Contains(nierozwiazana.Error, "exit status") {
		t.Errorf("powod bez tresci resolvera: %q", nierozwiazana.Error)
	}
}

// TestZlyResolverNieDojezdzaDoHosta pilnuje, ze konfiguracja, ktora odcielaby
// host od katalogu i Kerberosa, jest odrzucona przy zlecaniu.
func TestZlyResolverNieDojezdzaDoHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	const powod = "test integracyjny modulu resolvera"

	przypadki := []struct {
		zmiana   map[string]any
		dlaczego string
	}{
		{map[string]any{"interface": "enp0s8"}, "zmiana bez serwera"},
		{map[string]any{"interface": "enp0s8", "servers": []string{"nie-adres"}}, "serwer, ktory nie jest adresem"},
		{map[string]any{"interface": "../etc", "servers": []string{"192.168.56.50"}}, "nazwa interfejsu ze sciezka"},
		{map[string]any{"interface": "enp0s8", "servers": []string{"192.168.56.50"},
			"search_domains": []string{"zla domena"}}, "domena z odstepem"},
	}
	for _, przypadek := range przypadki {
		t.Run(przypadek.dlaczego, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "dns.host.apply", "reason": powod,
					"payload": map[string]any{"dns": przypadek.zmiana}},
				nil, http.StatusBadRequest)
		})
	}

	// Host bez mechanizmu zapisu odmawia przy zlecaniu, a nie po dostarczeniu.
	debian := h.hostByFamily("debian")
	if stan := migawkaDNSHosta(t, h, debian.ID); !stan.Writable {
		h.do(http.MethodPost, "/api/v1/hosts/"+debian.ID+"/operations",
			map[string]any{"action": "dns.host.apply", "reason": powod,
				"payload": map[string]any{"dns": map[string]any{
					"interface": "eth1", "servers": []string{"192.168.56.50"}}}},
			nil, http.StatusConflict)
	}
}

func migawkaDNSHosta(t *testing.T, h *harness, hostID string) migawkaDNS {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/dns", nil, &fragment, http.StatusOK)
	var stan migawkaDNS
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		t.Fatalf("migawka resolvera: %v", err)
	}
	return stan
}

// zapytaniaZadania czyta wynik testu z ostatniej proby. Wynik nalezy do proby,
// bo to ona wie, co odpowiedzial host i kiedy.
func zapytaniaZadania(t *testing.T, h *harness, jobID string) []zapytanieView {
	t.Helper()
	var odpowiedz struct {
		Items []struct {
			Detail struct {
				Queries struct {
					Queries []zapytanieView `json:"queries"`
				} `json:"queries"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+jobID+"/attempts", nil, &odpowiedz, http.StatusOK)
	if len(odpowiedz.Items) == 0 {
		t.Fatal("zadanie bez prob")
	}
	return odpowiedz.Items[len(odpowiedz.Items)-1].Detail.Queries.Queries
}
