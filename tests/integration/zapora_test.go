//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type regulaView struct {
	Table   string  `json:"table"`
	Chain   string  `json:"chain"`
	Text    string  `json:"text"`
	Source  string  `json:"source"`
	Comment string  `json:"comment"`
	Packets *uint64 `json:"packets"`
}

type migawkaZapory struct {
	Adapter string `json:"adapter"`
	Hash    string `json:"hash"`
	Tables  []struct {
		Name   string `json:"name"`
		Source string `json:"source"`
		Owner  string `json:"owner"`
	} `json:"tables"`
	Rules []regulaView `json:"rules"`
	Zones []struct {
		Name   string   `json:"name"`
		Active bool     `json:"active"`
		Ports  []string `json:"ports"`
	} `json:"zones"`
	Writable          bool   `json:"writable"`
	UnavailableReason string `json:"unavailable_reason"`
}

const powodZapory = "test integracyjny modulu zapory"

// TestZaporaOdrozniaCudzeTablice sprawdza granice wlasnosci. Tablice dockera
// i firewalld sa przepisywane bez udzialu panelu, wiec regula w nich nie jest
// ani nasza, ani trwala - i operator ma to widziec, zanim zacznie ja poprawiac.
func TestZaporaOdrozniaCudzeTablice(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			stan := migawkaZaporyHosta(t, h, host.ID)
			if stan.UnavailableReason != "" {
				t.Fatalf("stanu zapory nie odczytano: %s", stan.UnavailableReason)
			}
			if stan.Adapter == "" || stan.Hash == "" {
				t.Fatalf("adapter = %q, odcisk = %q", stan.Adapter, stan.Hash)
			}
			var obce int
			for _, tabela := range stan.Tables {
				if tabela.Source == "foreign" {
					obce++
					// Cudza tablica ma powiedziec, do kogo nalezy.
					if tabela.Owner == "" {
						t.Errorf("cudza tablica bez wlasciciela: %+v", tabela)
					}
				}
			}
			if obce == 0 {
				t.Error("host nie rozpoznal zadnej cudzej tablicy")
			}
		})
	}
}

// TestRegulaOdcinajacaPanelJestOdrzucana pilnuje jedynej reguly, ktorej nie
// wolno stracic. Bez kanalu zarzadzania host przestaje odpowiadac i nie ma
// czym cofnac zmiany.
func TestRegulaOdcinajacaPanelJestOdrzucana(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "firewall.rule.ensure", "reason": powodZapory,
		"payload": map[string]any{"firewall": map[string]any{
			"rule_id": "test-blokady-panelu", "chain": "wejscie", "action": "drop",
			"protocol": "tcp", "ports": []string{"8000-9000"}, "rollback_seconds": 60}},
	}, 2*time.Minute)
	if zadanie.State == "succeeded" {
		t.Fatal("panel przyjal regule odcinajaca sam siebie")
	}
	komunikat := ostatniKomunikat(proby)
	if !strings.Contains(komunikat, "kanal") && !strings.Contains(komunikat, "panelem") {
		t.Errorf("odmowa bez powodu: %q", komunikat)
	}
}

// TestCyklZyciaRegulyPanelu przechodzi cala droge reguly: zalozenie,
// potwierdzenie lacznosci i usuniecie. Po tescie host zostaje bez regul
// panelu, tak jak przed nim.
func TestCyklZyciaRegulyPanelu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	stan := migawkaZaporyHosta(t, h, host.ID)
	if !stan.Writable {
		t.Skip("host nie pozwala zmieniac zapory")
	}
	const nazwa = "test-cyklu-zycia"

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "firewall.rule.remove", "reason": powodZapory,
			"payload": map[string]any{"firewall": map[string]any{
				"rule_id": nazwa, "rollback_seconds": 60}},
		}, 2*time.Minute)
	})

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "firewall.rule.ensure", "reason": powodZapory,
		"payload": map[string]any{"firewall": map[string]any{
			"rule_id": nazwa, "chain": "wejscie", "action": "drop",
			"protocol": "tcp", "ports": []string{"25"},
			"sources": []string{"10.10.0.0/16"}, "comment": "test",
			"rollback_seconds": 60, "expected_hash": stan.Hash}},
	}, 3*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("zalozenie reguly: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}
	// Zmiana bez potwierdzonej lacznosci zostawialaby uzbrojony zegar, ktory
	// za chwile cofnalby dzialajaca zmiane.
	if !strings.Contains(ostatniKomunikat(proby), "wycofanie rozbrojone") {
		t.Errorf("zmiana bez potwierdzenia lacznosci: %s", ostatniKomunikat(proby))
	}

	po := regulaPanelu(t, h, host.ID, nazwa)
	if po.Table != "flotestro" || po.Chain != "wejscie" {
		t.Errorf("regula trafila poza tablice panelu: %+v", po)
	}
	if !strings.Contains(po.Text, "tcp dport 25") || !strings.Contains(po.Text, "drop") {
		t.Errorf("tresc reguly = %q", po.Text)
	}
	// Licznik jest czescia reguly: bez niego nie wiadomo, czy cokolwiek
	// przez nia przeszlo.
	if po.Packets == nil {
		t.Error("regula panelu bez licznika")
	}

	// Odcisk zestawu regul zmienil sie wraz z regula, wiec zlecenie wobec
	// starego odcisku ma zostac odrzucone.
	zadanie, proby = h.runOperation(host.ID, map[string]any{
		"action": "firewall.rule.ensure", "reason": powodZapory,
		"payload": map[string]any{"firewall": map[string]any{
			"rule_id": "test-nieaktualny", "chain": "wejscie", "action": "drop",
			"protocol": "tcp", "ports": []string{"26"},
			"sources":          []string{"10.10.0.0/16"},
			"rollback_seconds": 60, "expected_hash": stan.Hash}},
	}, 2*time.Minute)
	if zadanie.State == "succeeded" {
		t.Errorf("przyjeto zmiane wobec nieaktualnego zestawu regul: %s", ostatniKomunikat(proby))
	}
}

// TestZlaRegulaNieDojezdzaDoHosta sprawdza, ze regula, ktorej host nie
// zrozumie, jest odrzucona przy zlecaniu.
func TestZlaRegulaNieDojezdzaDoHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	przypadki := []struct {
		zmiana   map[string]any
		dlaczego string
	}{
		{map[string]any{"rule_id": "Zla Nazwa", "chain": "wejscie", "action": "drop",
			"protocol": "tcp", "ports": []string{"25"}}, "nazwa z odstepem"},
		{map[string]any{"rule_id": "test", "chain": "POSTROUTING", "action": "drop",
			"protocol": "tcp", "ports": []string{"25"}}, "cudzy lancuch"},
		{map[string]any{"rule_id": "test", "chain": "wejscie", "action": "log",
			"protocol": "tcp", "ports": []string{"25"}}, "nieznane dzialanie"},
		{map[string]any{"rule_id": "test", "chain": "wejscie", "action": "drop"},
			"regula bez zadnego dopasowania"},
		{map[string]any{"rule_id": "test", "chain": "wejscie", "action": "drop",
			"protocol": "tcp", "ports": []string{"25"}, "comment": `x" accept #`},
			"komentarz z cudzyslowem"},
	}
	for _, przypadek := range przypadki {
		t.Run(przypadek.dlaczego, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "firewall.rule.ensure", "reason": powodZapory,
					"payload": map[string]any{"firewall": przypadek.zmiana}},
				nil, http.StatusBadRequest)
		})
	}
}

// TestStrefyFirewalldSaOsobnymModelem sprawdza, ze host z firewalld opisuje
// dostep strefami, a operacja strefowa jest trwala i przeladowana.
func TestStrefyFirewalldSaOsobnymModelem(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	stan := migawkaZaporyHosta(t, h, host.ID)
	if len(stan.Zones) == 0 {
		t.Skip("host nie ma firewalld")
	}

	var aktywna string
	for _, strefa := range stan.Zones {
		if strefa.Active {
			aktywna = strefa.Name
		}
	}
	if aktywna == "" {
		t.Skip("host nie ma aktywnej strefy")
	}

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "firewall.zone.port", "reason": powodZapory,
			"payload": map[string]any{"firewall": map[string]any{
				"zone": aktywna, "ports": []string{"9444"}, "protocol": "tcp", "enable": false}},
		}, 2*time.Minute)
	})

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "firewall.zone.port", "reason": powodZapory,
		"payload": map[string]any{"firewall": map[string]any{
			"zone": aktywna, "ports": []string{"9444"}, "protocol": "tcp", "enable": true}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("otwarcie portu: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	po := migawkaZaporyHosta(t, h, host.ID)
	otwarty := false
	for _, strefa := range po.Zones {
		if strefa.Name != aktywna {
			continue
		}
		for _, port := range strefa.Ports {
			if port == "9444/tcp" {
				otwarty = true
			}
		}
	}
	if !otwarty {
		t.Errorf("port nie pojawil sie w strefie %s: %+v", aktywna, po.Zones)
	}
}

func migawkaZaporyHosta(t *testing.T, h *harness, hostID string) migawkaZapory {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/firewall", nil, &fragment, http.StatusOK)
	var stan migawkaZapory
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		t.Fatalf("migawka zapory: %v", err)
	}
	return stan
}

// regulaPanelu czeka na regule w inwentarzu hosta: zapis fragmentu jest
// asynchroniczny wzgledem zakonczenia zadania.
func regulaPanelu(t *testing.T, h *harness, hostID, nazwa string) regulaView {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		for _, regula := range migawkaZaporyHosta(t, h, hostID).Rules {
			if regula.Source == "managed" && strings.Contains(regula.Comment, nazwa) {
				return regula
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("regula %s nie pojawila sie w inwentarzu hosta", nazwa)
		}
		time.Sleep(2 * time.Second)
	}
}
