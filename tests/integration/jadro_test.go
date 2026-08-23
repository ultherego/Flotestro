//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type ustawienieView struct {
	Key     string `json:"key"`
	Current string `json:"current"`
	Desired string `json:"desired"`
	Managed bool   `json:"managed"`
}

type modulView struct {
	Name        string `json:"name"`
	SizeBytes   uint64 `json:"size_bytes"`
	Blacklisted bool   `json:"blacklisted"`
}

type migawkaJadra struct {
	Release           string           `json:"release"`
	CommandLine       string           `json:"command_line"`
	Settings          []ustawienieView `json:"settings"`
	Modules           []modulView      `json:"modules"`
	Blacklist         []string         `json:"blacklist"`
	ManagedPath       string           `json:"managed_path"`
	UnavailableReason string           `json:"unavailable_reason"`
}

const powodJadra = "test integracyjny modulu jadra"

// TestJadroPokazujeProfilANieCalePs sprawdza, ze modul pokazuje profil
// ustawien i moduly, a nie kilka tysiecy kluczy /proc/sys.
func TestJadroPokazujeProfilANieCalePs(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			stan := migawkaJadraHosta(t, h, host.ID)
			if stan.UnavailableReason != "" {
				t.Fatalf("stanu jadra nie odczytano: %s", stan.UnavailableReason)
			}
			if stan.Release == "" || stan.CommandLine == "" {
				t.Errorf("stan = %+v", stan.Release)
			}
			if len(stan.Settings) == 0 || len(stan.Settings) > 200 {
				t.Errorf("ustawien = %d; profil ma byc zbiorem, a nie cala galezia", len(stan.Settings))
			}
			for _, ustawienie := range stan.Settings {
				// Klucz bez wartosci biezacej i docelowej nie mowi nic;
				// pokazany wygladalby na ustawienie o wartosci zerowej.
				if ustawienie.Current == "" && ustawienie.Desired == "" {
					t.Errorf("ustawienie bez wartosci: %+v", ustawienie)
				}
			}
			if len(stan.Modules) == 0 {
				t.Error("host nie zglosil zadnego modulu")
			}
		})
	}
}

// TestUstawienieJadraJestZapisaneITrwale sprawdza pelna droge: zapis do pliku
// panelu, zastosowanie od reki i widocznosc w inwentarzu.
func TestUstawienieJadraJestZapisaneITrwale(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "sysctl.ensure", "reason": powodJadra,
			"payload": map[string]any{"kernel": map[string]any{
				"settings": map[string]string{"vm.swappiness": "60"}}},
		}, 2*time.Minute)
	})

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "sysctl.ensure", "reason": powodJadra,
		"payload": map[string]any{"kernel": map[string]any{
			"settings": map[string]string{"vm.swappiness": "25"}}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("zapis ustawienia: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	stan := migawkaJadraHosta(t, h, host.ID)
	var swappiness ustawienieView
	for _, ustawienie := range stan.Settings {
		if ustawienie.Key == "vm.swappiness" {
			swappiness = ustawienie
		}
	}
	if swappiness.Current != "25" || swappiness.Desired != "25" || !swappiness.Managed {
		t.Errorf("ustawienie po zapisie = %+v", swappiness)
	}
	if stan.ManagedPath != "/etc/sysctl.d/90-flotestro.conf" {
		t.Errorf("plik panelu = %q", stan.ManagedPath)
	}
}

// TestUstawieniaPozaZakresemNieDojezdzajaDoHosta pilnuje granicy: /proc/sys
// zawiera przelaczniki, ktore wylaczaja ochrony jadra albo zatrzymuja host.
func TestUstawieniaPozaZakresemNieDojezdzajaDoHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, przypadek := range []struct {
		ustawienia map[string]string
		dlaczego   string
	}{
		{map[string]string{"kernel.sysrq": "1"}, "przelacznik sysrq"},
		{map[string]string{"kernel.core_pattern": "|/tmp/x"}, "program przy zrzucie pamieci"},
		{map[string]string{"dev.raid.speed_limit_max": "1"}, "galaz poza zakresem"},
		{map[string]string{"vm.swappiness": "10\nkernel.sysrq = 1"}, "nowa linia w wartosci"},
	} {
		t.Run(przypadek.dlaczego, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "sysctl.ensure", "reason": powodJadra,
					"payload": map[string]any{"kernel": map[string]any{
						"settings": przypadek.ustawienia}}},
				nil, http.StatusBadRequest)
		})
	}

	// Klucz, ktorego host nie zna, zostalby w pliku na zawsze i nie zrobil nic.
	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "sysctl.ensure", "reason": powodJadra,
		"payload": map[string]any{"kernel": map[string]any{
			"settings": map[string]string{"vm.nie_ma_takiego_klucza": "1"}}},
	}, 2*time.Minute)
	if zadanie.State == "succeeded" {
		t.Error("panel zapisal ustawienie, ktorego jadro nie zna")
	}
	if !strings.Contains(ostatniKomunikat(proby), "nie zna ustawienia") {
		t.Errorf("odmowa bez powodu: %q", ostatniKomunikat(proby))
	}
}

// TestBlokadaModuluMowiCoSieStanie sprawdza, ze panel nie udaje, iz wpis
// w modprobe.d wyladowal dzialajacy modul.
func TestBlokadaModuluMowiCoSieStanie(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Modul, bez ktorego host nie wstanie, nie da sie zablokowac.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "kernel.module.blacklist", "reason": powodJadra,
			"payload": map[string]any{"kernel": map[string]any{
				"module": "dm_mod", "blacklist": true}}},
		nil, http.StatusBadRequest)

	stan := migawkaJadraHosta(t, h, host.ID)
	var zaladowany string
	for _, modul := range stan.Modules {
		if !modul.Blacklisted && modul.Name != "" && !strings.HasPrefix(modul.Name, "dm") {
			zaladowany = modul.Name
			break
		}
	}
	if zaladowany == "" {
		t.Skip("host nie ma modulu nadajacego sie do proby")
	}

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "kernel.module.blacklist", "reason": powodJadra,
			"payload": map[string]any{"kernel": map[string]any{
				"module": zaladowany, "blacklist": false}},
		}, 2*time.Minute)
	})

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "kernel.module.blacklist", "reason": powodJadra,
		"payload": map[string]any{"kernel": map[string]any{
			"module": zaladowany, "blacklist": true}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("blokada modulu: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}
	// Modul zaladowany nie znika po zapisaniu blokady i operator ma to
	// przeczytac, a nie odkryc przy nastepnym restarcie.
	if !strings.Contains(ostatniKomunikat(proby), "restarcie") {
		t.Errorf("blokada bez wyjasnienia skutku: %q", ostatniKomunikat(proby))
	}

	po := migawkaJadraHosta(t, h, host.ID)
	znaleziony := false
	for _, nazwa := range po.Blacklist {
		if nazwa == zaladowany {
			znaleziony = true
		}
	}
	if !znaleziony {
		t.Errorf("blokada nie widoczna w inwentarzu: %v", po.Blacklist)
	}
}

func migawkaJadraHosta(t *testing.T, h *harness, hostID string) migawkaJadra {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/kernel", nil, &fragment, http.StatusOK)
	var stan migawkaJadra
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		t.Fatalf("migawka jadra: %v", err)
	}
	return stan
}
