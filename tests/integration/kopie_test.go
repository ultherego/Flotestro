//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const powodKopii = "test integracyjny modulu kopii zapasowych"

type definicjaKopiiView struct {
	Name           string   `json:"name"`
	Tool           string   `json:"tool"`
	Repository     string   `json:"repository"`
	Paths          []string `json:"paths"`
	PasswordSecret string   `json:"password_secret"`
	Initialize     bool     `json:"initialize"`
	Status         string   `json:"status"`
	LastSuccessAt  *string  `json:"last_success_at"`
	AgeHours       *float64 `json:"age_hours"`
	LastVerifyAt   *string  `json:"last_verify_at"`
	Unverified     bool     `json:"unverified"`
	Snapshots      *int     `json:"snapshots"`
	RepositorySize *int64   `json:"repository_size"`
}

type raportKopiiView struct {
	Definitions []definicjaKopiiView `json:"definitions"`
	Status      string               `json:"status"`
	Tools       struct {
		Tools []struct {
			Name      string `json:"name"`
			Available bool   `json:"available"`
			Version   string `json:"version"`
		} `json:"tools"`
		RunbooksKnown bool `json:"runbooks_known"`
	} `json:"tools"`
}

type szczegolKopiiView struct {
	Kind  string `json:"kind"`
	State struct {
		Snapshots []struct {
			ID    string   `json:"id"`
			Time  string   `json:"time"`
			Paths []string `json:"paths"`
		} `json:"snapshots"`
		TotalSizeBytes    *uint64 `json:"total_size_bytes"`
		UnavailableReason string  `json:"unavailable_reason"`
	} `json:"state"`
	Outcome struct {
		SnapshotID string  `json:"snapshot_id"`
		BytesAdded *uint64 `json:"bytes_added"`
	} `json:"outcome"`
}

// kopieHosta czyta zakladke kopii hosta.
func kopieHosta(h *harness, hostID string) raportKopiiView {
	h.t.Helper()
	var raport raportKopiiView
	h.get("/api/v1/hosts/"+hostID+"/backups", &raport)
	return raport
}

// hostZResticiem wybiera host, ktory ma czym zrobic kopie.
func hostZResticiem(t *testing.T, h *harness) hostView {
	t.Helper()
	for _, rodzina := range []string{"debian", "rhel"} {
		host := h.hostByFamily(rodzina)
		for _, narzedzie := range kopieHosta(h, host.ID).Tools.Tools {
			if narzedzie.Name == "restic" && narzedzie.Available {
				return host
			}
		}
	}
	t.Skip("zaden host floty testowej nie ma resticu")
	return hostView{}
}

// TestKopiaZapasowaPelnyCykl przechodzi cala droge modulu: definicja, kopia,
// odczyt repozytorium, weryfikacja i odtworzenie do katalogu roboczego.
func TestKopiaZapasowaPelnyCykl(t *testing.T) {
	h := newHarness(t)
	host := hostZResticiem(t, h)
	znacznik := time.Now().UnixNano()
	nazwa := fmt.Sprintf("integracja-%d", znacznik%100000)
	repozytorium := fmt.Sprintf("/srv/flotestro-test-%d", znacznik%100000)
	cel := fmt.Sprintf("/srv/flotestro-test-%d-odtworzenie", znacznik%100000)
	haslo := fmt.Sprintf("haslo-repozytorium-%d", znacznik)
	sekret := nowySekret(t, h, haslo)

	definicja := map[string]any{
		"name": nazwa, "tool": "restic", "repository": repozytorium,
		"paths": []string{"/etc/flotestro"}, "keep_last": 2,
		"initialize": true, "password_secret": sekret.Name,
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", definicja, nil, http.StatusOK)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+host.ID+"/backups?name="+nazwa, nil, nil, 0)
	})

	zlecenie := map[string]any{
		"id": nazwa, "tool": "restic", "repository": repozytorium,
		"paths": []string{"/etc/flotestro"}, "keep_last": 2, "initialize": true,
		"password_secret": map[string]any{"name": sekret.Name},
	}

	// Kopia zaklada repozytorium, bo definicja na to pozwala.
	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "backup.run", "reason": powodKopii,
		"payload": map[string]any{"backup": zlecenie},
	}, 10*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("kopia zakonczyla sie stanem %s: %+v", zadanie.State, proby)
	}

	// Plan czyta repozytorium: to stamtad wiadomo, kiedy kopia naprawde
	// powstala - takze wtedy, gdy zrobil ja cron, a nie panel.
	plan, proby := h.runOperation(host.ID, map[string]any{
		"action": "backup.plan", "reason": powodKopii,
		"payload": map[string]any{"backup": zlecenie},
	}, 5*time.Minute)
	if plan.State != "succeeded" {
		t.Fatalf("odczyt repozytorium zakonczyl sie stanem %s: %+v", plan.State, proby)
	}
	szczegol := szczegolKopii(t, h, plan.ID)
	if len(szczegol.State.Snapshots) == 0 {
		t.Fatalf("repozytorium nie zglasza zadnej kopii: %+v", szczegol.State)
	}
	kopia := szczegol.State.Snapshots[len(szczegol.State.Snapshots)-1]
	if kopia.ID == "" || len(kopia.Paths) == 0 {
		t.Fatalf("kopia opisana jako %+v", kopia)
	}

	// Weryfikacja z odczytem danych: dopiero to mowi, ze kopia da sie
	// odtworzyc, a nie tylko, ze indeks sie zgadza.
	weryfikacja := map[string]any{}
	for klucz, wartosc := range zlecenie {
		weryfikacja[klucz] = wartosc
	}
	weryfikacja["read_data"] = true
	sprawdzenie, proby := h.runOperation(host.ID, map[string]any{
		"action": "backup.verify", "reason": powodKopii,
		"payload": map[string]any{"backup": weryfikacja},
	}, 10*time.Minute)
	if sprawdzenie.State != "succeeded" {
		t.Fatalf("weryfikacja zakonczyla sie stanem %s: %+v", sprawdzenie.State, proby)
	}

	// Panel zna teraz wiek kopii i to, ze ktos ja sprawdzil.
	raport := kopieHosta(h, host.ID)
	var widok *definicjaKopiiView
	for i := range raport.Definitions {
		if raport.Definitions[i].Name == nazwa {
			widok = &raport.Definitions[i]
		}
	}
	if widok == nil {
		t.Fatalf("definicji %s nie ma w zakladce: %+v", nazwa, raport.Definitions)
	}
	if widok.Status != "ok" || widok.LastSuccessAt == nil {
		t.Errorf("stan kopii opisany jako %+v", widok)
	}
	if widok.Unverified || widok.LastVerifyAt == nil {
		t.Errorf("sprawdzona kopia opisana jako niesprawdzona: %+v", widok)
	}
	if widok.Snapshots == nil || *widok.Snapshots == 0 {
		t.Errorf("panel nie zna liczby kopii: %+v", widok)
	}

	// Odtworzenie do katalogu roboczego. Panel nie odtwarza wprost do drzew
	// systemowych i nie odtwarza do prywatnego /tmp pomocnika.
	odtworzenie := map[string]any{}
	for klucz, wartosc := range zlecenie {
		odtworzenie[klucz] = wartosc
	}
	odtworzenie["snapshot_id"] = kopia.ID
	odtworzenie["target"] = cel
	odtworzenie["overwrite"] = "empty-target"
	przywrocenie, proby := h.runOperation(host.ID, map[string]any{
		"action": "backup.restore", "reason": powodKopii,
		"payload": map[string]any{"backup": odtworzenie},
	}, 10*time.Minute)
	if przywrocenie.State != "succeeded" {
		t.Fatalf("odtworzenie zakonczylo sie stanem %s: %+v", przywrocenie.State, proby)
	}

	// Drugie odtworzenie do tego samego katalogu odpada: katalog nie jest juz
	// pusty, a plan nadpisania na to nie pozwala.
	powtorne, proby := h.runOperation(host.ID, map[string]any{
		"action": "backup.restore", "reason": powodKopii,
		"payload": map[string]any{"backup": odtworzenie},
	}, 10*time.Minute)
	if powtorne.State == "succeeded" {
		t.Fatal("odtworzenie do niepustego katalogu przeszlo mimo planu 'pusty katalog'")
	}
	if len(proby) == 0 || !strings.Contains(proby[len(proby)-1].Message, "is not empty") {
		t.Fatalf("odmowa nie mowi, o co chodzi: %+v", proby)
	}

	// Haslo repozytorium nie moze byc nigdzie poza magazynem - takze
	// w wyjsciu narzedzia, ktore panel przechowuje w wyniku zadania.
	sprawdzBrakWartosci(t, h, haslo)
}

// TestKopiaPilnujeCeluOdtworzenia pilnuje granicy, ktora odroznia odtworzenie
// od rozpakowania starego stanu na dzialajacym systemie.
func TestKopiaPilnujeCeluOdtworzenia(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	podstawa := map[string]any{
		"id": "integracja-granice", "tool": "restic", "repository": "/srv/flotestro-test",
		"paths": []string{"/etc/flotestro"}, "snapshot_id": "abc123",
	}

	zle := map[string]map[string]any{
		"katalog systemowy":            {"target": "/etc", "overwrite": "empty-target"},
		"wnetrze katalogu systemowego": {"target": "/etc/nginx", "overwrite": "empty-target"},
		"korzen":                       {"target": "/", "overwrite": "empty-target"},
		"prywatny tmp pomocnika":       {"target": "/var/tmp/kopia", "overwrite": "empty-target"},
		"bez planu nadpisania":         {"target": "/srv/kopia"},
		"sciezka wzgledna":             {"target": "srv/kopia", "overwrite": "empty-target"},
		"bez wskazania kopii":          {"target": "/srv/kopia", "overwrite": "empty-target", "snapshot_id": ""},
	}
	for nazwa, dodatki := range zle {
		t.Run(nazwa, func(t *testing.T) {
			payload := map[string]any{}
			for klucz, wartosc := range podstawa {
				payload[klucz] = wartosc
			}
			for klucz, wartosc := range dodatki {
				payload[klucz] = wartosc
			}
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
				"action": "backup.restore", "reason": powodKopii,
				"payload": map[string]any{"backup": payload},
			}, nil, http.StatusBadRequest)
		})
	}
}

// TestDefinicjaKopiiWymagaIstniejacegoSekretu pilnuje, zeby literowka w nazwie
// sekretu odpadala przy zapisie definicji, a nie przy pierwszej kopii - czyli
// w najgorszym momencie.
func TestDefinicjaKopiiWymagaIstniejacegoSekretu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", map[string]any{
		"name": "integracja-bez-sekretu", "tool": "restic",
		"repository": "/srv/flotestro-test", "paths": []string{"/etc/flotestro"},
		"password_secret": "nie.ma.takiego.sekretu",
	}, nil, http.StatusBadRequest)

	// Definicja bez narzedzia albo z nazwa wychodzaca z katalogu tez odpada.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", map[string]any{
		"name": "integracja", "tool": "tar", "repository": "/srv/flotestro-test",
	}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", map[string]any{
		"name": "../ucieczka", "tool": "restic", "repository": "/srv/flotestro-test",
	}, nil, http.StatusBadRequest)
}

// szczegolKopii czyta wynik operacji z ostatniej proby zadania.
func szczegolKopii(t *testing.T, h *harness, jobID string) szczegolKopiiView {
	t.Helper()
	var wynik struct {
		Items []struct {
			Detail szczegolKopiiView `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &wynik)
	if len(wynik.Items) == 0 {
		t.Fatalf("zadanie %s nie ma prob", jobID)
	}
	return wynik.Items[len(wynik.Items)-1].Detail
}

// TestWidokKopiiPokazujeObciazenieBackendu sprawdza to, czego lista kopii nie
// mowi: ktory backend jest waskim gardlem. Kopie ida z wielu hostow do jednego
// repozytorium, a to ono decyduje, ile z nich pojdzie naraz.
func TestWidokKopiiPokazujeObciazenieBackendu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	nazwa := fmt.Sprintf("obciazenie-%d", time.Now().UnixNano())
	repozytorium := "/srv/" + nazwa
	sekret := nowySekret(t, h, "haslo-"+nazwa)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", map[string]any{
		"name": nazwa, "tool": "restic", "repository": repozytorium,
		"paths": []string{"/etc/flotestro"}, "keep_last": 1,
		"initialize": true, "password_secret": sekret.Name,
	}, nil, http.StatusOK)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+host.ID+"/backups?name="+nazwa, nil, nil, 0)
	})

	// Budzet backendu jest polityka panelu, a nie stanem hosta: widok ma go
	// pokazac takze wtedy, gdy do repozytorium nie poszla jeszcze zadna kopia.
	h.ustawBudzet("backend:"+repozytorium+":backup", 2, 50)

	var widok struct {
		NeverRestored int `json:"never_restored"`
		Items         []struct {
			Definition    string  `json:"definition"`
			LastRestoreAt *string `json:"last_restore_at"`
		} `json:"items"`
		Repositories []struct {
			Repository     string   `json:"repository"`
			Hosts          int      `json:"hosts"`
			BudgetKey      string   `json:"budget_key"`
			Capacity       *int     `json:"capacity"`
			Used           *int     `json:"used"`
			OldestAgeHours *float64 `json:"oldest_age_hours"`
		} `json:"repositories"`
	}
	h.get("/api/v1/backups", &widok)

	var znalezione bool
	for _, pozycja := range widok.Repositories {
		if pozycja.Repository != repozytorium {
			continue
		}
		znalezione = true
		if pozycja.Hosts != 1 {
			t.Errorf("repozytorium opisane dla %d hostow", pozycja.Hosts)
		}
		if pozycja.BudgetKey != "backend:"+repozytorium+":backup" {
			t.Errorf("klucz budzetu = %q", pozycja.BudgetKey)
		}
		// Pojemnosc ustawiona przez operatora ma dojsc do widoku: bez niej
		// nie widac, co ogranicza rownoleglosc kopii.
		if pozycja.Capacity == nil || *pozycja.Capacity != 2 {
			t.Errorf("pojemnosc backendu = %v", pozycja.Capacity)
		}
		if pozycja.Used == nil {
			t.Error("widok nie mowi, ile tokenow backendu jest zajetych")
		}
	}
	if !znalezione {
		t.Fatalf("widok kopii nie zna repozytorium %s: %+v", repozytorium, widok.Repositories)
	}

	// Kopia, ktorej nikt nigdy nie odtworzyl, jest nadzieja, a nie kopia.
	// Definicja zalozona przed chwila nie byla odtwarzana ani razu i widok
	// ma to powiedziec wprost, a nie milczec.
	var opisana bool
	for _, pozycja := range widok.Items {
		if pozycja.Definition != nazwa {
			continue
		}
		opisana = true
		if pozycja.LastRestoreAt != nil {
			t.Errorf("nowa definicja ma date odtworzenia: %v", *pozycja.LastRestoreAt)
		}
	}
	if !opisana {
		t.Errorf("widok nie zna definicji %s", nazwa)
	}
	if widok.NeverRestored == 0 {
		t.Error("widok nie liczy kopii, ktorych nigdy nie odtwarzano")
	}
}
