//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

type plikView struct {
	Path           string `json:"path"`
	DesiredSHA256  string `json:"desired_sha256"`
	ObservedSHA256 string `json:"observed_sha256"`
	Mode           string `json:"mode"`
	Exists         bool   `json:"exists"`
	Drift          bool   `json:"drift"`
	UpdatedBy      string `json:"updated_by"`
}

type wersjaView struct {
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	AppliedBy string `json:"applied_by"`
}

const powodPlikow = "test integracyjny modulu plikow"
const sciezkaTestowa = "/etc/flotestro-test.conf"

// TestPlikZakazanyNieDojezdzaDoHosta pilnuje granicy, ktora oddziela ten
// modul od menedzera plikow roota: plik z hashami hasel, klucz prywatny
// i regula sudo maja wlasne moduly i nie sa tu edytowalne.
func TestPlikZakazanyNieDojezdzaDoHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, sciezka := range []string{
		"/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/admin",
		"/etc/ssh/ssh_host_ed25519_key", "/root/.ssh/authorized_keys",
		"/etc/pam.d/sshd", "../etc/motd",
	} {
		t.Run(sciezka, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "file.ensure", "reason": powodPlikow,
					"payload": map[string]any{"file": map[string]any{
						"path": sciezka, "content": "x\n"}}},
				nil, http.StatusBadRequest)
		})
	}
}

// TestPlikPozaAllowlistaJestOdrzucanyPrzezHosta sprawdza drugi poziom:
// zakres sciezek wyznacza administrator hosta, a nie zlecenie.
func TestPlikPozaAllowlistaJestOdrzucanyPrzezHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": powodPlikow,
		"payload": map[string]any{"file": map[string]any{
			"path": "/var/lib/flotestro-poza-zakresem.conf", "content": "x\n"}},
	}, 2*time.Minute)
	if zadanie.State == "succeeded" {
		t.Fatal("host zapisal plik spoza allowlisty")
	}
	komunikat := ostatniKomunikat(proby)
	if !strings.Contains(komunikat, "allowlist") {
		t.Errorf("odmowa bez powodu: %q", komunikat)
	}
	// Odmowa mowi, gdzie zakres jest wyznaczony: operator ma wiedziec,
	// co zrobic dalej, a nie tylko ze sie nie da.
	if !strings.Contains(komunikat, "files.allow") {
		t.Errorf("odmowa nie wskazuje zrodla zakresu: %q", komunikat)
	}
}

// TestCyklZyciaPlikuZarzadzanego przechodzi cala droge: zapis, drift po
// zmianie poza panelem, powrot do wersji i usuniecie.
func TestCyklZyciaPlikuZarzadzanego(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	t.Cleanup(func() {
		stan := plikZarzadzany(t, h, host.ID, sciezkaTestowa)
		h.runOperation(host.ID, map[string]any{
			"action": "file.remove", "reason": powodPlikow,
			"payload": map[string]any{"file": map[string]any{
				"path": sciezkaTestowa, "expected_sha256": stan.ObservedSHA256}},
		}, 2*time.Minute)
	})

	pierwsza := "klucz = pierwsza\n"
	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": powodPlikow,
		"payload": map[string]any{"file": map[string]any{
			"path": sciezkaTestowa, "content": pierwsza, "mode": "640"}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("pierwszy zapis: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}
	// Plik, dla ktorego panel nie zna sprawdzenia, dostaje to powiedziane
	// wprost: brak walidacji jest faktem, a nie cisza.
	if !strings.Contains(ostatniKomunikat(proby), "walidatora") {
		t.Errorf("zapis bez informacji o walidacji: %q", ostatniKomunikat(proby))
	}

	stan := plikZarzadzany(t, h, host.ID, sciezkaTestowa)
	if !stan.Exists || stan.Drift {
		t.Fatalf("stan po zapisie = %+v", stan)
	}
	if stan.ObservedSHA256 != stan.DesiredSHA256 {
		t.Errorf("odciski = %s vs %s", stan.ObservedSHA256, stan.DesiredSHA256)
	}
	pierwszyOdcisk := stan.DesiredSHA256

	// Drugi zapis wymaga odcisku tresci, ktora operator ogladal.
	zadanie, proby = h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": powodPlikow,
		"payload": map[string]any{"file": map[string]any{
			"path": sciezkaTestowa, "content": "klucz = druga\n", "mode": "640"}},
	}, 2*time.Minute)
	if zadanie.State == "succeeded" {
		t.Fatal("panel nadpisal istniejacy plik bez odcisku")
	}
	if !strings.Contains(ostatniKomunikat(proby), "odcisk") {
		t.Errorf("odmowa bez powodu: %q", ostatniKomunikat(proby))
	}

	zadanie, proby = h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": powodPlikow,
		"payload": map[string]any{"file": map[string]any{
			"path": sciezkaTestowa, "content": "klucz = druga\n", "mode": "640",
			"expected_sha256": stan.ObservedSHA256}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("drugi zapis: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	// Historia niesie obie wersje, wiec da sie wrocic do pierwszej.
	wersje := historiaPliku(t, h, host.ID, sciezkaTestowa)
	if len(wersje) < 2 {
		t.Fatalf("wersji w historii = %d", len(wersje))
	}
	stan = plikZarzadzany(t, h, host.ID, sciezkaTestowa)
	zadanie, proby = h.runOperation(host.ID, map[string]any{
		"action": "file.rollback", "reason": powodPlikow,
		"payload": map[string]any{"file": map[string]any{
			"path": sciezkaTestowa, "version_sha256": pierwszyOdcisk,
			"expected_sha256": stan.ObservedSHA256, "mode": "640"}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("powrot do wersji: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}
	po := plikZarzadzany(t, h, host.ID, sciezkaTestowa)
	if po.DesiredSHA256 != pierwszyOdcisk || po.Drift {
		t.Errorf("stan po powrocie = %+v", po)
	}
}

// TestOdczytPlikuNiesieTrescIOdcisk sprawdza droge, ktora poprzedza kazdy
// zapis: bez odczytu operator nie ma odcisku, ktorym zwiaze swoja zmiane.
func TestOdczytPlikuNiesieTrescIOdcisk(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	zadanie, _ := h.runOperation(host.ID, map[string]any{
		"action":  "file.read",
		"payload": map[string]any{"file": map[string]any{"path": "/etc/hosts"}},
	}, 90*time.Second)
	if zadanie.State != "succeeded" {
		t.Fatalf("odczyt: stan = %s", zadanie.State)
	}

	var odpowiedz struct {
		Items []struct {
			Detail struct {
				Kind      string `json:"kind"`
				Content   string `json:"content"`
				SHA256    string `json:"sha256"`
				Truncated bool   `json:"truncated"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+zadanie.ID+"/attempts", nil, &odpowiedz, http.StatusOK)
	if len(odpowiedz.Items) == 0 {
		t.Fatal("zadanie bez prob")
	}
	detal := odpowiedz.Items[len(odpowiedz.Items)-1].Detail
	if detal.Content == "" || len(detal.SHA256) != 64 {
		t.Errorf("odczyt = %+v", detal)
	}
	if !strings.Contains(detal.Content, "localhost") {
		t.Errorf("tresc /etc/hosts = %q", detal.Content[:min(60, len(detal.Content))])
	}
}

func plikZarzadzany(t *testing.T, h *harness, hostID, sciezka string) plikView {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		var odpowiedz struct {
			Items []plikView `json:"items"`
		}
		h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/files", nil, &odpowiedz, http.StatusOK)
		for _, plik := range odpowiedz.Items {
			if plik.Path == sciezka {
				return plik
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("plik %s nie jest zarzadzany", sciezka)
		}
		time.Sleep(2 * time.Second)
	}
}

func historiaPliku(t *testing.T, h *harness, hostID, sciezka string) []wersjaView {
	t.Helper()
	var odpowiedz struct {
		Items []wersjaView `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/files/history?path="+sciezka,
		nil, &odpowiedz, http.StatusOK)
	return odpowiedz.Items
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
