//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

type wersjaSekretuView struct {
	Version   int        `json:"version"`
	SizeBytes int        `json:"size_bytes"`
	CreatedBy string     `json:"created_by"`
	Destroyed *time.Time `json:"destroyed_at"`
}

type sekretView struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Description    string              `json:"description"`
	CurrentVersion int                 `json:"current_version"`
	CreatedBy      string              `json:"created_by"`
	RetiredAt      *time.Time          `json:"retired_at"`
	Versions       []wersjaSekretuView `json:"versions"`
}

type plikZarzadzanyView struct {
	Path                 string `json:"path"`
	DesiredSHA256        string `json:"desired_sha256"`
	DesiredSecret        string `json:"desired_secret"`
	DesiredSecretVersion int    `json:"desired_secret_version"`
	ObservedSHA256       string `json:"observed_sha256"`
	Exists               bool   `json:"exists"`
	Drift                bool   `json:"drift"`
	DriftUnknownReason   string `json:"drift_unknown_reason"`
}

const powodSekretu = "test integracyjny magazynu sekretow"

// nowySekret zaklada sekret o nazwie unikalnej dla przebiegu i pilnuje, zeby
// zostal wycofany po tescie.
func nowySekret(t *testing.T, h *harness, wartosc string) sekretView {
	t.Helper()
	nazwa := fmt.Sprintf("integracja.%d", time.Now().UnixNano())
	var sekret sekretView
	h.do(http.MethodPost, "/api/v1/secrets", map[string]any{
		"name": nazwa, "description": powodSekretu, "value": wartosc,
	}, &sekret, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/secrets/"+nazwa+"/retire", nil, nil, 0)
	})
	return sekret
}

// TestWartoscSekretuNieWychodziPrzezAPI pilnuje wlasciwosci, dla ktorej
// magazyn w ogole istnieje: wartosc wchodzi i nie wychodzi.
func TestWartoscSekretuNieWychodziPrzezAPI(t *testing.T) {
	h := newHarness(t)
	wartosc := "nie-powinno-tego-byc-w-odpowiedzi-" + fmt.Sprint(time.Now().UnixNano())
	sekret := nowySekret(t, h, wartosc)

	if sekret.CurrentVersion != 1 || len(sekret.Versions) != 1 {
		t.Fatalf("sekret po zalozeniu = %+v", sekret)
	}
	// Rozmiar jest metadana, wiec wolno go pokazac; tresci nie.
	if sekret.Versions[0].SizeBytes != len(wartosc) {
		t.Errorf("rozmiar wersji = %d, wartosc ma %d bajtow",
			sekret.Versions[0].SizeBytes, len(wartosc))
	}

	// Ani lista, ani szczegoly nie moga nigdzie niesc wartosci.
	for _, sciezka := range []string{"/api/v1/secrets", "/api/v1/secrets/" + sekret.Name} {
		var surowa json.RawMessage
		h.do(http.MethodGet, sciezka, nil, &surowa, http.StatusOK)
		if strings.Contains(string(surowa), wartosc) {
			t.Fatalf("%s zwrocilo wartosc sekretu", sciezka)
		}
	}
}

// TestSekretMusiIstniecPrzedZleceniem pilnuje, zeby literowka w nazwie odpadala
// przy zlecaniu, a nie po kilku minutach na hoscie.
func TestSekretMusiIstniecPrzedZleceniem(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	sekret := nowySekret(t, h, "wartosc-do-testu-granic")

	// Nieistniejacy sekret.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "file.ensure", "reason": powodSekretu,
		"payload": map[string]any{"file": map[string]any{
			"path": "/etc/flotestro-test.conf", "mode": "600",
			"content_secret": map[string]any{"name": "nie.ma.takiego.sekretu"},
		}},
	}, nil, http.StatusBadRequest)

	// Wersja spoza zakresu.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "file.ensure", "reason": powodSekretu,
		"payload": map[string]any{"file": map[string]any{
			"path": "/etc/flotestro-test.conf", "mode": "600",
			"content_secret": map[string]any{"name": sekret.Name, "version": 99},
		}},
	}, nil, http.StatusBadRequest)

	// Tresc jawna i sekret naraz: nie wiadomo, co wyladuje w pliku.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "file.ensure", "reason": powodSekretu,
		"payload": map[string]any{"file": map[string]any{
			"path": "/etc/flotestro-test.conf", "mode": "600", "content": "jawna tresc",
			"content_secret": map[string]any{"name": sekret.Name},
		}},
	}, nil, http.StatusBadRequest)

	// Wycofany sekret nie da sie juz wydac.
	h.do(http.MethodPost, "/api/v1/secrets/"+sekret.Name+"/retire", nil, nil, http.StatusOK)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "file.ensure", "reason": powodSekretu,
		"payload": map[string]any{"file": map[string]any{
			"path": "/etc/flotestro-test.conf", "mode": "600",
			"content_secret": map[string]any{"name": sekret.Name},
		}},
	}, nil, http.StatusConflict)
}

// TestObrotZostawiaStarszeWersje sprawdza, ze obrot dokłada wersje, a nie
// podmienia jedyna: host z dzierzawa na wersje wczesniejsza ma ja dostac.
func TestObrotZostawiaStarszeWersje(t *testing.T) {
	h := newHarness(t)
	sekret := nowySekret(t, h, "pierwsza-wartosc")

	var poObrocie sekretView
	h.do(http.MethodPost, "/api/v1/secrets/"+sekret.Name+"/rotate",
		map[string]any{"value": "druga-wartosc"}, &poObrocie, http.StatusOK)
	if poObrocie.CurrentVersion != 2 || len(poObrocie.Versions) != 2 {
		t.Fatalf("sekret po obrocie = %+v", poObrocie)
	}

	// Zniszczenie wersji zostawia slad, ze istniala.
	var poZniszczeniu sekretView
	h.do(http.MethodDelete, "/api/v1/secrets/"+sekret.Name+"/versions/1", nil,
		&poZniszczeniu, http.StatusOK)
	var wersja1 wersjaSekretuView
	for _, wersja := range poZniszczeniu.Versions {
		if wersja.Version == 1 {
			wersja1 = wersja
		}
	}
	if wersja1.Version != 1 || wersja1.Destroyed == nil {
		t.Errorf("wersja 1 po zniszczeniu = %+v", wersja1)
	}
	if poZniszczeniu.CurrentVersion != 2 {
		t.Errorf("zniszczenie starej wersji ruszylo wersje biezaca: %d", poZniszczeniu.CurrentVersion)
	}
}

// TestPlikZSekretuNieZostawiaWartosciWPanelu jest testem calej drogi: wartosc
// dociera na host, a w panelu nie ma ani jej, ani jej odcisku.
func TestPlikZSekretuNieZostawiaWartosciWPanelu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	wartosc := "wartosc-testu-integracyjnego-" + fmt.Sprint(time.Now().UnixNano())
	sekret := nowySekret(t, h, wartosc)
	sciezka := "/etc/flotestro-sekret-test.conf"

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "file.remove", "reason": powodSekretu,
			"payload": map[string]any{"file": map[string]any{"path": sciezka}},
		}, 2*time.Minute)
	})

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": powodSekretu,
		"payload": map[string]any{"file": map[string]any{
			"path": sciezka, "mode": "600",
			"content_secret": map[string]any{"name": sekret.Name},
		}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("zapis z sekretu: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	// Zadanie niesie odnosnik, nigdy wartosc.
	var surowe json.RawMessage
	h.do(http.MethodGet, "/api/v1/jobs/"+zadanie.ID, nil, &surowe, http.StatusOK)
	if strings.Contains(string(surowe), wartosc) {
		t.Error("wartosc sekretu znalazla sie w zadaniu")
	}
	if !strings.Contains(string(surowe), sekret.Name) {
		t.Error("zadanie nie niesie odnosnika do sekretu")
	}
	// Wynik proby tez nie moze jej niesc.
	h.do(http.MethodGet, "/api/v1/jobs/"+zadanie.ID+"/attempts", nil, &surowe, http.StatusOK)
	if strings.Contains(string(surowe), wartosc) {
		t.Error("wartosc sekretu znalazla sie w wyniku proby")
	}

	// Stan docelowy to nazwa sekretu i wersja - bez odcisku tresci.
	var pliki struct {
		Items []plikZarzadzanyView `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/files", nil, &pliki, http.StatusOK)
	var widok plikZarzadzanyView
	for _, plik := range pliki.Items {
		if plik.Path == sciezka {
			widok = plik
		}
	}
	if widok.Path == "" {
		t.Fatal("panel nie zapisal stanu docelowego pliku")
	}
	if widok.DesiredSecret != sekret.Name || widok.DesiredSecretVersion != 1 {
		t.Errorf("stan docelowy = %+v", widok)
	}
	if widok.DesiredSHA256 != "" {
		t.Error("panel zapisal odcisk tresci pochodzacej z magazynu")
	}
	// Panel nie udaje zgodnosci, ktorej nie sprawdzil.
	if widok.Drift {
		t.Error("panel zglasza drift pliku, ktorego tresci nie porownuje")
	}
	if widok.DriftUnknownReason == "" {
		t.Error("brak porownania tresci bez wyjasnienia")
	}
	// Host tez nie zglasza odcisku takiego pliku.
	if widok.ObservedSHA256 != "" {
		t.Error("host zglosil odcisk tresci pochodzacej z magazynu")
	}

	// Slad audytowy ma fakt wydania, nie wartosc.
	var audyt json.RawMessage
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/audit?limit=50", nil, &audyt, http.StatusOK)
	if strings.Contains(string(audyt), wartosc) {
		t.Error("wartosc sekretu znalazla sie w audycie")
	}
}
