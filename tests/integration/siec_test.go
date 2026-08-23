//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
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
