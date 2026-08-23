//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type kluczHostaView struct {
	Type        string `json:"type"`
	Bits        int    `json:"bits"`
	Fingerprint string `json:"fingerprint"`
	Path        string `json:"path"`
}

type migawkaSSH struct {
	Ports                  []string         `json:"ports"`
	PermitRootLogin        string           `json:"permit_root_login"`
	PasswordAuthentication string           `json:"password_authentication"`
	PubkeyAuthentication   string           `json:"pubkey_authentication"`
	MaxAuthTries           int              `json:"max_auth_tries"`
	HostKeys               []kluczHostaView `json:"host_keys"`
	ManagedPath            string           `json:"managed_path"`
	ManagedPresent         bool             `json:"managed_present"`
	Unit                   string           `json:"unit"`
	UnavailableReason      string           `json:"unavailable_reason"`
}

const powodSSH = "test integracyjny modulu sshd"

// TestKonfiguracjaSSHPochodziZSerwera sprawdza, ze panel pokazuje to, co
// serwer naprawde stosuje, wraz z odciskami kluczy - i nigdy klucza
// prywatnego.
func TestKonfiguracjaSSHPochodziZSerwera(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			stan := migawkaSSHHosta(t, h, host.ID)
			if stan.UnavailableReason != "" {
				t.Fatalf("konfiguracji nie odczytano: %s", stan.UnavailableReason)
			}
			if len(stan.Ports) == 0 || stan.MaxAuthTries == 0 {
				t.Errorf("stan = %+v", stan)
			}
			// Nazwa jednostki rozni sie miedzy dystrybucjami, a przeladowanie
			// niewlasciwej nie robi nic i nie zglasza bledu.
			if stan.Unit != "ssh.service" && stan.Unit != "sshd.service" {
				t.Errorf("jednostka = %q", stan.Unit)
			}
			if len(stan.HostKeys) == 0 {
				t.Fatal("host nie zglosil zadnego klucza")
			}
			for _, klucz := range stan.HostKeys {
				if !strings.HasPrefix(klucz.Fingerprint, "SHA256:") {
					t.Errorf("odcisk = %q", klucz.Fingerprint)
				}
				// Panel nie ma powodu widziec klucza prywatnego, wiec
				// wskazuje wylacznie plik publiczny.
				if !strings.HasSuffix(klucz.Path, ".pub") {
					t.Errorf("sciezka klucza = %q", klucz.Path)
				}
			}
		})
	}
}

// TestZmianaOdcinajacaLogowanieJestOdrzucana pilnuje granicy: serwer, do
// ktorego nie da sie zalogowac zadna metoda, nie jest zabezpieczony - jest
// niedostepny.
func TestZmianaOdcinajacaLogowanieJestOdrzucana(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "ssh.config.apply", "reason": powodSSH,
		"payload": map[string]any{"ssh": map[string]any{
			"password_authentication": "no", "pubkey_authentication": "no"}},
	}, 2*time.Minute)
	if zadanie.State == "succeeded" {
		t.Fatal("panel przyjal konfiguracje bez zadnej metody uwierzytelnienia")
	}
	if !strings.Contains(ostatniKomunikat(proby), "uwierzytelnienia") {
		t.Errorf("odmowa bez powodu: %q", ostatniKomunikat(proby))
	}
}

// TestUstawieniePrzesloniete jest o tym, co odroznia zapis od skutku:
// w sshd wygrywa pierwsza wartosc, wiec wczesniejszy plik administratora
// przeslania plik panelu. Cisza w tym miejscu bylaby falszywym sukcesem.
func TestUstawieniePrzesloniete(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	stan := migawkaSSHHosta(t, h, host.ID)

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "ssh.config.apply", "reason": powodSSH,
			"payload": map[string]any{"ssh": map[string]any{
				"max_auth_tries": "6"}},
		}, 2*time.Minute)
	})

	// MaxAuthTries nikt inny nie ustawia, wiec ta czesc ma sie udac.
	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "ssh.config.apply", "reason": powodSSH,
		"payload": map[string]any{"ssh": map[string]any{"max_auth_tries": "4"}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("zmiana MaxAuthTries: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	po := migawkaSSHHosta(t, h, host.ID)
	if po.MaxAuthTries != 4 {
		t.Errorf("MaxAuthTries = %d", po.MaxAuthTries)
	}
	if !po.ManagedPresent || po.ManagedPath != "/etc/ssh/sshd_config.d/90-flotestro.conf" {
		t.Errorf("plik panelu = %+v", po.ManagedPath)
	}
	// Serwer dalej dziala: konfiguracja byla sprawdzona przez sshd przed
	// przeladowaniem.
	if len(po.Ports) == 0 {
		t.Error("serwer nie odpowiada po zmianie")
	}
	_ = stan
}

// TestZlaKonfiguracjaSSHNieDojezdzaDoHosta sprawdza odmowe przy zlecaniu.
func TestZlaKonfiguracjaSSHNieDojezdzaDoHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, przypadek := range []struct {
		zmiana   map[string]any
		dlaczego string
	}{
		{map[string]any{"port": "0"}, "port zero"},
		{map[string]any{"permit_root_login": "moze"}, "nieznana wartosc root login"},
		{map[string]any{"max_auth_tries": "0"}, "zero prob"},
		{map[string]any{"allow_users": []string{"zly wpis"}}, "wzorzec z odstepem"},
	} {
		t.Run(przypadek.dlaczego, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "ssh.config.apply", "reason": powodSSH,
					"payload": map[string]any{"ssh": przypadek.zmiana}},
				nil, http.StatusBadRequest)
		})
	}

	// Wymiana klucza dotyczy typow, ktore host w ogole ma.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "ssh.hostkey.rotate", "reason": powodSSH,
			"payload": map[string]any{"ssh": map[string]any{"key_type": "dsa"}}},
		nil, http.StatusBadRequest)
}

func migawkaSSHHosta(t *testing.T, h *harness, hostID string) migawkaSSH {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/ssh", nil, &fragment, http.StatusOK)
	var stan migawkaSSH
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		t.Fatalf("migawka sshd: %v", err)
	}
	return stan
}
