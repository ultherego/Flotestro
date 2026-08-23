//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type adresView struct {
	Family    string `json:"family"`
	Address   string `json:"address"`
	Permanent bool   `json:"permanent"`
}

type interfejsView struct {
	Name       string      `json:"name"`
	Kind       string      `json:"kind"`
	MTU        int         `json:"mtu"`
	OperState  string      `json:"oper_state"`
	Carrier    *bool       `json:"carrier"`
	SpeedMbps  *int        `json:"speed_mbps"`
	Addresses  []adresView `json:"addresses"`
	Management bool        `json:"management"`
}

type migawkaSieci struct {
	Interfaces []interfejsView `json:"interfaces"`
	Routes     []struct {
		Destination string `json:"destination"`
		Family      string `json:"family"`
	} `json:"routes"`
	ManagementInterface string `json:"management_interface"`
	ManagementAddress   string `json:"management_address"`
	WriteAdapter        string `json:"write_adapter"`
	UnavailableReason   string `json:"unavailable_reason"`
}

// TestSiecWskazujeKanalZarzadzania sprawdza rzecz, ktora decyduje o
// bezpieczenstwie kazdej zmiany sieci: host ma sam powiedziec, ktorym
// interfejsem rozmawia z panelem. Zgadywanie z pierwszej pozycji listy
// konczyloby sie zmiana interfejsu, przez ktory wlasnie przyszlo polecenie.
func TestSiecWskazujeKanalZarzadzania(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			stan := migawkaSieciHosta(t, h, host.ID)
			if stan.UnavailableReason != "" {
				t.Fatalf("stanu sieci nie odczytano: %s", stan.UnavailableReason)
			}
			if stan.ManagementInterface == "" || stan.ManagementAddress == "" {
				t.Fatalf("host nie wskazal kanalu zarzadzania: %+v", stan)
			}
			var oznaczone int
			for _, interfejs := range stan.Interfaces {
				if interfejs.Management {
					oznaczone++
					if interfejs.Name != stan.ManagementInterface {
						t.Errorf("oznaczony interfejs %q, kanal %q", interfejs.Name, stan.ManagementInterface)
					}
				}
			}
			if oznaczone != 1 {
				t.Errorf("oznaczonych interfejsow zarzadzania = %d", oznaczone)
			}
		})
	}
}

// TestSiecRozrozniaRodzajeInterfejsow pilnuje, ze most kontenerow nie udaje
// karty sieciowej. Host z dockerem ma kilkanascie interfejsow wirtualnych
// i bez rodzaju obraz jest nieczytelny.
func TestSiecRozrozniaRodzajeInterfejsow(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	stan := migawkaSieciHosta(t, h, host.ID)

	rodzaje := map[string]string{}
	for _, interfejs := range stan.Interfaces {
		rodzaje[interfejs.Name] = interfejs.Kind
		// Adres bez maski nie mowi, jaka siec host uwaza za lokalna.
		for _, adres := range interfejs.Addresses {
			if !hasPrefixMask(adres.Address) {
				t.Errorf("adres %q bez maski na %s", adres.Address, interfejs.Name)
			}
		}
	}
	if rodzaje["lo"] != "loopback" {
		t.Errorf("rodzaj lo = %q", rodzaje["lo"])
	}
	if rodzaj, ok := rodzaje["docker0"]; ok && rodzaj != "bridge" {
		t.Errorf("rodzaj docker0 = %q", rodzaj)
	}
	if len(stan.Routes) == 0 {
		t.Error("host nie zglosil zadnej trasy")
	}
}

// TestBrakZapisuSieciMaPowod sprawdza granice miedzy modulem niedostepnym
// a modulem tylko do odczytu. Host bez NetworkManagera nie jest hostem bez
// sieci - i ma powiedziec, dlaczego panel nic tu nie zmieni.
func TestBrakZapisuSieciMaPowod(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var zdolnosc *hostCapability
	for i := range host.Capabilities {
		if host.Capabilities[i].Name == "network" {
			zdolnosc = &host.Capabilities[i]
		}
	}
	if zdolnosc == nil {
		t.Fatal("host nie zglosil modulu sieci")
	}
	if !zdolnosc.Available {
		t.Fatalf("modul sieci niedostepny: %s", zdolnosc.Reason)
	}
	stan := migawkaSieciHosta(t, h, host.ID)
	if stan.WriteAdapter == "" && zdolnosc.Reason == "" {
		t.Error("host bez adaptera zapisu nie tlumaczy, dlaczego panel nic nie zmieni")
	}
	if stan.WriteAdapter != "" && zdolnosc.Reason != "" {
		t.Errorf("host z adapterem %q podaje powod niedostepnosci: %s",
			stan.WriteAdapter, zdolnosc.Reason)
	}
}

func migawkaSieciHosta(t *testing.T, h *harness, hostID string) migawkaSieci {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/network",
		nil, &fragment, http.StatusOK)
	var stan migawkaSieci
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		t.Fatalf("migawka sieci: %v", err)
	}
	return stan
}

func hasPrefixMask(adres string) bool {
	for i := len(adres) - 1; i >= 0; i-- {
		if adres[i] == '/' {
			return i < len(adres)-1
		}
	}
	return false
}

// TestZlaKonfiguracjaSieciNieDojezdzaDoHosta sprawdza, ze wartosc, ktorej
// host nie przyjmie albo ktora odcielaby go od panelu, jest odrzucona przy
// zlecaniu. Zmiana sieci to nie jest miejsce na uczenie sie z bledu wykonania.
func TestZlaKonfiguracjaSieciNieDojezdzaDoHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	const powod = "test integracyjny modulu sieci"

	przypadki := []struct {
		akcja    string
		zmiana   map[string]any
		dlaczego string
	}{
		{"network.mtu.set", map[string]any{"interface": "enp0s8", "mtu": "900"},
			"MTU ponizej progu IPv6"},
		{"network.mtu.set", map[string]any{"interface": "enp0s8", "mtu": "duzo"},
			"MTU, ktore nie jest liczba"},
		{"network.mtu.set", map[string]any{"interface": "../etc", "mtu": "1500"},
			"nazwa interfejsu ze sciezka"},
		{"network.route.ensure", map[string]any{"interface": "enp0s8",
			"routes": []string{"192.168.9.0 192.168.56.1"}}, "cel trasy bez maski"},
		{"network.profile.apply", map[string]any{"interface": "enp0s8", "method": "manual"},
			"metoda manual bez adresu"},
		{"network.profile.apply", map[string]any{"interface": "enp0s8", "method": "manual",
			"addresses": []string{"192.168.56.40"}}, "adres bez maski"},
		{"network.profile.apply", map[string]any{"interface": "enp0s8", "method": "wlasna"},
			"nieznana metoda"},
	}
	for _, przypadek := range przypadki {
		t.Run(przypadek.dlaczego, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": przypadek.akcja, "reason": powod,
					"payload": map[string]any{"network": przypadek.zmiana}},
				nil, http.StatusBadRequest)
		})
	}
}

// TestHostBezMechanizmuZapisuOdmawiaPrzyZlecaniu sprawdza granice, ktora
// rejestr zdolnosci ma pilnowac: host, ktory nie utrzyma zmiany po restarcie,
// nie ma jej w ogole dostac.
func TestHostBezMechanizmuZapisuOdmawiaPrzyZlecaniu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	stan := migawkaSieciHosta(t, h, host.ID)
	if stan.WriteAdapter != "" {
		t.Skipf("host ma adapter zapisu %s", stan.WriteAdapter)
	}

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "network.mtu.set", "reason": "test integracyjny modulu sieci",
			"payload": map[string]any{"network": map[string]any{
				"interface": "eth1", "mtu": "1400"}}},
		nil, http.StatusConflict)

	// Odczyt stanu sieci dziala na tym samym hoscie: modul tylko do odczytu
	// to nie modul niedostepny.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "network.plan",
			"payload": map[string]any{"network": map[string]any{"interface": "eth1"}}},
		nil, http.StatusCreated)
}

// TestZmianaSieciJestPotwierdzanaLacznoscia przechodzi pelna droge zmiany:
// host uzbraja wycofanie, zmienia MTU, sprawdza droge do panelu i dopiero
// wtedy rozbraja zegar. Po tescie MTU wraca do wartosci domyslnej.
func TestZmianaSieciJestPotwierdzanaLacznoscia(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	stan := migawkaSieciHosta(t, h, host.ID)
	if stan.WriteAdapter == "" {
		t.Skip("host nie ma mechanizmu zapisu konfiguracji sieci")
	}
	interfejs := stan.ManagementInterface
	if interfejs == "" {
		t.Skip("host nie wskazal interfejsu zarzadzania")
	}

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "network.mtu.set", "reason": "test integracyjny modulu sieci",
			"payload": map[string]any{"network": map[string]any{
				"interface": interfejs, "mtu": "auto", "rollback_seconds": 60}},
		}, 3*time.Minute)
	})

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "network.mtu.set", "reason": "test integracyjny modulu sieci",
		"payload": map[string]any{"network": map[string]any{
			"interface": interfejs, "mtu": "1400", "rollback_seconds": 60}},
	}, 3*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("zmiana MTU: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}
	// Komunikat ma powiedziec, ze zegar ratunkowy byl uzbrojony i zostal
	// rozbrojony po sprawdzeniu drogi do panelu. Cicha zmiana sieci nie
	// odroznialaby sie od zmiany, ktora zadnego zegara nie miala.
	if !strings.Contains(ostatniKomunikat(proby), "wycofanie rozbrojone") {
		t.Errorf("zmiana bez potwierdzenia lacznosci: %s", ostatniKomunikat(proby))
	}

	po := migawkaSieciHosta(t, h, host.ID)
	for _, wpis := range po.Interfaces {
		if wpis.Name == interfejs && wpis.MTU != 1400 {
			// Inwentarz moze byc o cykl starszy niz zmiana, wiec brak nowej
			// wartosci nie jest tu bledem - ale zla wartosc juz tak.
			if wpis.MTU != 1500 {
				t.Errorf("MTU interfejsu %s = %d", interfejs, wpis.MTU)
			}
		}
	}
}
