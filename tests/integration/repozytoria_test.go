//go:build integration

package integration

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const powodZrodla = "test integracyjny zrodel pakietow"

type repozytoriumView struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	URL               string `json:"url"`
	Enabled           bool   `json:"enabled"`
	Signed            bool   `json:"signed"`
	Username          string `json:"username"`
	SecretName        string `json:"secret_name"`
	Managed           bool   `json:"managed"`
	Path              string `json:"path"`
	UnavailableReason string `json:"unavailable_reason"`
}

type fragmentPakietowView struct {
	Manager      string `json:"manager"`
	Repositories struct {
		Repositories []repozytoriumView `json:"repositories"`
		Known        bool               `json:"repositories_known"`
		Reason       string             `json:"repositories_unavailable_reason"`
	} `json:"repositories"`
}

// kluczZrodla sklada material klucza publicznego w ramce ASCII.
//
// Pakiet jest minimalny, ale prawdziwy: wersja 4, znacznik czasu, algorytm
// i material. Host liczy z niego odcisk tak samo, jak policzylby go z klucza
// dostawcy - a testowe zrodlo jest wylaczone, wiec nikt tym kluczem niczego
// nie weryfikuje.
func kluczZrodla() string {
	pakiet := append([]byte{4, 0x66, 0x00, 0x00, 0x00, 1}, make([]byte, 20)...)
	ramka := append([]byte{0xc0 | 6, byte(len(pakiet))}, pakiet...)
	return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" +
		base64.StdEncoding.EncodeToString(ramka) +
		"\n-----END PGP PUBLIC KEY BLOCK-----\n"
}

// zrodlaHosta czyta zrodla pakietow z inwentarza hosta.
func zrodlaHosta(h *harness, hostID string) fragmentPakietowView {
	h.t.Helper()
	var fragment struct {
		Payload fragmentPakietowView `json:"payload"`
	}
	h.get("/api/v1/hosts/"+hostID+"/inventory/packages", &fragment)
	return fragment.Payload
}

func znajdzZrodlo(zrodla []repozytoriumView, id string) *repozytoriumView {
	for i := range zrodla {
		if zrodla[i].ID == id {
			return &zrodla[i]
		}
	}
	return nil
}

// TestZrodloPakietowZHaslemZMagazynu przechodzi cala droge operacji: zapis
// zrodla wraz z kluczem i haslem, odczyt z inwentarza, wycofanie po nieudanym
// pobraniu metadanych i usuniecie.
func TestZrodloPakietowZHaslemZMagazynu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	id := fmt.Sprintf("flotestro-test-%d", time.Now().UnixNano()%100000)
	haslo := fmt.Sprintf("haslo-zrodla-%d", time.Now().UnixNano())
	sekret := nowySekret(t, h, haslo)

	opis := map[string]any{
		"id": id, "name": "Zrodlo testowe",
		"url": "https://pakiety.example.test/debian",
		// Zrodlo wylaczone: host zapisuje pliki, ale nie probuje pobierac
		// metadanych z adresu, ktorego w tej sieci nie ma.
		"suites": []string{"stable"}, "components": []string{"main"},
		"enabled": false, "gpg_key": kluczZrodla(),
		"username": "flota", "password_secret": map[string]any{"name": sekret.Name},
	}
	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "packages.repository.set", "reason": powodZrodla,
			"payload": map[string]any{"repository": map[string]any{"id": id, "remove": true}},
		}, 3*time.Minute)
	})

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "packages.repository.set", "reason": powodZrodla,
		"payload": map[string]any{"repository": opis},
	}, 3*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("zapis zrodla zakonczyl sie stanem %s: %+v", zadanie.State, proby)
	}

	fragment := zrodlaHosta(h, host.ID)
	if !fragment.Repositories.Known {
		t.Fatalf("host nie odczytal zrodel: %s", fragment.Repositories.Reason)
	}
	zapisane := znajdzZrodlo(fragment.Repositories.Repositories, id)
	if zapisane == nil {
		t.Fatalf("zrodla %s nie ma w inwentarzu: %+v", id, fragment.Repositories.Repositories)
	}
	if !zapisane.Managed {
		t.Error("zrodlo zapisane przez panel nie jest oznaczone jako zarzadzane")
	}
	if zapisane.Enabled {
		t.Error("zrodlo wylaczone zostalo zapisane jako wlaczone")
	}
	if !zapisane.Signed {
		t.Error("zrodlo ze sprawdzaniem podpisow zostalo zapisane bez nich")
	}
	// Panel widzi nazwe sekretu i nazwe uzytkownika; wartosci hasla nie widzi
	// nikt poza magazynem i hostem w chwili zapisu.
	if zapisane.SecretName != sekret.Name || zapisane.Username != "flota" {
		t.Errorf("powiazanie z sekretem opisane jako %+v", zapisane)
	}
	sprawdzBrakWartosci(t, h, haslo)

	// Wlaczenie zrodla, ktorego nie da sie pobrac, musi zostawic host w stanie
	// sprzed zmiany: zrodlo, ktore nie odpowiada, zablokowaloby kazda nastepna
	// operacje pakietowa.
	zepsute := map[string]any{}
	for klucz, wartosc := range opis {
		zepsute[klucz] = wartosc
	}
	zepsute["enabled"] = true
	nieudane, _ := h.runOperation(host.ID, map[string]any{
		"action": "packages.repository.set", "reason": powodZrodla,
		"payload": map[string]any{"repository": zepsute},
	}, 5*time.Minute)
	if nieudane.State == "succeeded" {
		t.Fatal("zrodlo, ktorego nie da sie pobrac, zostalo przyjete")
	}
	po := znajdzZrodlo(zrodlaHosta(h, host.ID).Repositories.Repositories, id)
	if po == nil || po.Enabled {
		t.Fatalf("po nieudanej zmianie zrodlo wyglada tak: %+v", po)
	}

	// Usuniecie zabiera zrodlo razem z kluczem i haslem.
	usuniecie, proby := h.runOperation(host.ID, map[string]any{
		"action": "packages.repository.set", "reason": powodZrodla,
		"payload": map[string]any{"repository": map[string]any{"id": id, "remove": true}},
	}, 3*time.Minute)
	if usuniecie.State != "succeeded" {
		t.Fatalf("usuniecie zrodla zakonczylo sie stanem %s: %+v", usuniecie.State, proby)
	}
	if zostalo := znajdzZrodlo(zrodlaHosta(h, host.ID).Repositories.Repositories, id); zostalo != nil {
		t.Fatalf("zrodlo zostalo po usunieciu: %+v", zostalo)
	}
}

// TestZrodloNieosiagalneWycofujeZmiane pilnuje wycofania na obu rodzinach.
//
// Ani apt, ani dnf nie zglaszaja nieudanego pobrania metadanych kodem wyjscia:
// oba koncza sie zerem i komunikatem o zbudowanym cache. Zrodlo, ktore nie
// odpowiada, zablokowaloby jednak kazda nastepna operacje pakietowa - wiec to
// panel musi przeczytac, co narzedzie napisalo, i cofnac zmiane.
func TestZrodloNieosiagalneWycofujeZmiane(t *testing.T) {
	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			h := newHarness(t)
			host := h.hostByFamily(rodzina)
			id := fmt.Sprintf("flotestro-nieosiagalne-%d", time.Now().UnixNano()%100000)

			opis := map[string]any{
				"id": id, "url": "https://pakiety.example.test/repo",
				"enabled": false, "gpg_key": kluczZrodla(),
			}
			if rodzina == "debian" {
				opis["suites"] = []string{"stable"}
				opis["components"] = []string{"main"}
			}
			t.Cleanup(func() {
				h.runOperation(host.ID, map[string]any{
					"action": "packages.repository.set", "reason": powodZrodla,
					"payload": map[string]any{"repository": map[string]any{"id": id, "remove": true}},
				}, 3*time.Minute)
			})

			zadanie, proby := h.runOperation(host.ID, map[string]any{
				"action": "packages.repository.set", "reason": powodZrodla,
				"payload": map[string]any{"repository": opis},
			}, 3*time.Minute)
			if zadanie.State != "succeeded" {
				t.Fatalf("zapis wylaczonego zrodla zakonczyl sie stanem %s: %+v",
					zadanie.State, proby)
			}

			wlaczone := map[string]any{}
			for klucz, wartosc := range opis {
				wlaczone[klucz] = wartosc
			}
			wlaczone["enabled"] = true
			nieudane, proby := h.runOperation(host.ID, map[string]any{
				"action": "packages.repository.set", "reason": powodZrodla,
				"payload": map[string]any{"repository": wlaczone},
			}, 5*time.Minute)
			if nieudane.State == "succeeded" {
				t.Fatal("zrodlo, ktorego nie da sie pobrac, zostalo przyjete")
			}
			if len(proby) == 0 || !strings.Contains(proby[len(proby)-1].Message, "przywrocono") {
				t.Fatalf("odmowa nie mowi o wycofaniu zmiany: %+v", proby)
			}
			po := znajdzZrodlo(zrodlaHosta(h, host.ID).Repositories.Repositories, id)
			if po == nil || po.Enabled {
				t.Fatalf("po nieudanej zmianie zrodlo wyglada tak: %+v", po)
			}
		})
	}
}

// TestZrodloPakietowPilnujeZaufania pilnuje granic operacji: zrodlo jest
// decyzja o tym, czyje pakiety host przyjmie, wiec bledne zlecenie ma odpadac
// przy zlecaniu, a nie na hoscie.
func TestZrodloPakietowPilnujeZaufania(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	zle := map[string]map[string]any{
		"bez klucza i bez zgody": {
			"id": "flotestro-bez-klucza", "url": "https://pakiety.example.test/debian",
			"suites": []string{"stable"}, "enabled": true,
		},
		"bez podpisow po http": {
			"id": "flotestro-http", "url": "http://pakiety.example.test/debian",
			"suites": []string{"stable"}, "enabled": true, "allow_unsigned": true,
		},
		"material, ktory nie jest kluczem": {
			"id": "flotestro-zly-klucz", "url": "https://pakiety.example.test/debian",
			"suites": []string{"stable"}, "enabled": true,
			"gpg_key": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		},
		"identyfikator wychodzacy z katalogu": {
			"id": "../../etc/apt/sources.list", "url": "https://pakiety.example.test/debian",
			"suites": []string{"stable"}, "enabled": true, "allow_unsigned": true,
		},
		"haslo po http": {
			"id": "flotestro-haslo-http", "url": "http://pakiety.example.test/debian",
			"suites": []string{"stable"}, "enabled": true, "allow_unsigned": true,
			"username": "flota", "password_secret": map[string]any{"name": "nie.ma.takiego"},
		},
	}
	for nazwa, opis := range zle {
		t.Run(nazwa, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
				"action": "packages.repository.set", "reason": powodZrodla,
				"payload": map[string]any{"repository": opis},
			}, nil, http.StatusBadRequest)
		})
	}

	// Zrodlo bez sprawdzania podpisow jest dopuszczalne wylacznie jako jawna
	// zgoda operatora - i tylko po https.
	t.Run("jawna zgoda po https", func(t *testing.T) {
		var zadanie jobView
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
			"action": "packages.repository.set", "reason": powodZrodla,
			"payload": map[string]any{"repository": map[string]any{
				"id": "flotestro-zgoda", "url": "https://pakiety.example.test/debian",
				"suites": []string{"stable"}, "enabled": false, "allow_unsigned": true,
			}},
		}, &zadanie, http.StatusCreated)
		// Zadania nie wykonujemy: sprawdzamy granice zlecania, a nie zapis.
		h.do(http.MethodPost, "/api/v1/jobs/"+zadanie.ID+"/cancel", nil, nil, 0)
	})
}

// TestZrodlaWInwentarzuSaCzytane pilnuje, ze pusta lista i lista nieodczytana
// to dwie rozne odpowiedzi.
func TestZrodlaWInwentarzuSaCzytane(t *testing.T) {
	h := newHarness(t)
	for _, rodzina := range []string{"debian", "rhel"} {
		fragment := zrodlaHosta(h, h.hostByFamily(rodzina).ID)
		if !fragment.Repositories.Known {
			t.Errorf("%s: zrodla nieodczytane (%s)", rodzina, fragment.Repositories.Reason)
			continue
		}
		if len(fragment.Repositories.Repositories) == 0 {
			t.Errorf("%s: host nie zglasza zadnego zrodla pakietow", rodzina)
		}
		// Zrodla dystrybucji nie sa zarzadzane przez panel i tak maja wygladac.
		for _, zrodlo := range fragment.Repositories.Repositories {
			if zrodlo.Managed {
				t.Errorf("%s: zrodlo dystrybucji %s opisane jako zarzadzane", rodzina, zrodlo.ID)
			}
		}
	}
}
