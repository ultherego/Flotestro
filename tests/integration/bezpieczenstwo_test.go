//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

type nasluchView struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Exposed  bool   `json:"exposed"`
}

type migawkaOchrony struct {
	MAC struct {
		System         string `json:"system"`
		Mode           string `json:"mode"`
		ConfiguredMode string `json:"configured_mode"`
		Reason         string `json:"reason"`
	} `json:"mac"`
	Audit struct {
		Present bool  `json:"present"`
		Active  *bool `json:"active"`
		Rules   *int  `json:"rules"`
	} `json:"audit"`
	FIPSEnabled       *bool         `json:"fips_enabled"`
	SecureBoot        *bool         `json:"secure_boot"`
	SecureBootReason  string        `json:"secure_boot_reason"`
	Listening         []nasluchView `json:"listening"`
	ListeningKnown    bool          `json:"listening_known"`
	UnavailableReason string        `json:"unavailable_reason"`
}

type naprawaView struct {
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload"`
	Note    string          `json:"note"`
}

type ustalenieView struct {
	CheckID      string       `json:"check_id"`
	CheckVersion int          `json:"check_version"`
	Title        string       `json:"title"`
	Severity     string       `json:"severity"`
	Rationale    string       `json:"rationale"`
	Passed       bool         `json:"passed"`
	Unknown      bool         `json:"unknown"`
	Expected     string       `json:"expected"`
	Observed     string       `json:"observed"`
	Module       string       `json:"module"`
	Revision     string       `json:"revision"`
	Remediation  *naprawaView `json:"remediation"`
}

type raportView struct {
	Findings    []ustalenieView `json:"findings"`
	PlanHash    string          `json:"plan_hash"`
	GeneratedAt time.Time       `json:"generated_at"`
	Counts      map[string]int  `json:"counts"`
}

type krokNaprawyView struct {
	CheckID string `json:"check_id"`
	Action  string `json:"action"`
	JobID   string `json:"job_id"`
	State   string `json:"state"`
	Skipped string `json:"skipped"`
}

const powodOchrony = "test integracyjny modulu bezpieczenstwa"

// TestStanOchronnyPochodziZHosta sprawdza fakty, na ktorych stoja wszystkie
// ustalenia: MAC, audyt, tryb rozruchu i to, czym host wystaje na zewnatrz.
func TestStanOchronnyPochodziZHosta(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			stan := migawkaOchronyHosta(t, h, host.ID)
			if stan.UnavailableReason != "" {
				t.Fatalf("stanu ochronnego nie odczytano: %s", stan.UnavailableReason)
			}
			// Host bez MAC ma powiedziec dlaczego, a nie milczec.
			if stan.MAC.System == "" && stan.MAC.Reason == "" {
				t.Error("brak systemu MAC bez powodu")
			}
			if stan.MAC.System != "" && stan.MAC.Mode == "" {
				t.Errorf("system MAC bez trybu: %+v", stan.MAC)
			}
			if !stan.ListeningKnown {
				t.Error("nie odczytano gniazd nasluchujacych")
			}
			if len(stan.Listening) == 0 {
				t.Error("host nie zglosil zadnego gniazda, a przynajmniej agent gdzies sluchа")
			}
			// Stan nieustalony niesie powod: pytanie o secure boot na hoscie
			// bez EFI nie ma odpowiedzi i nie zmyslamy jej.
			if stan.SecureBoot == nil && stan.SecureBootReason == "" {
				t.Error("nieustalony secure boot bez powodu")
			}
			if !stan.Audit.Present && stan.Audit.Active != nil {
				t.Errorf("host bez audytu zglasza jego stan: %+v", stan.Audit)
			}
		})
	}
}

// TestUstaleniaSaPowtarzalne sprawdza kontrakt raportu zgodnosci.
func TestUstaleniaSaPowtarzalne(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	raport := raportOchrony(t, h, host.ID)
	if len(raport.Findings) == 0 {
		t.Fatal("raport bez ustalen")
	}
	if raport.PlanHash == "" {
		t.Error("raport bez odcisku planu")
	}

	for _, ustalenie := range raport.Findings {
		if ustalenie.CheckID == "" || ustalenie.CheckVersion == 0 {
			t.Errorf("ustalenie bez wersji sprawdzenia: %+v", ustalenie)
		}
		if ustalenie.Expected == "" || ustalenie.Observed == "" || ustalenie.Rationale == "" {
			t.Errorf("%s bez oczekiwania, obserwacji albo uzasadnienia", ustalenie.CheckID)
		}
		// Ustalenie spelnione nie niesie planu naprawy: naprawianie stanu
		// poprawnego jest zaproszeniem do zmiany bez powodu.
		if (ustalenie.Passed || ustalenie.Unknown) && ustalenie.Remediation != nil {
			t.Errorf("%s nie wymaga dzialania, a niesie naprawe", ustalenie.CheckID)
		}
		// Ustalenie liczone z modulu wskazuje rewizje odczytu, z ktorego
		// powstalo - bez tego wyniku nie da sie powtorzyc.
		if ustalenie.Module != "" && !ustalenie.Unknown && ustalenie.Revision == "" {
			t.Errorf("%s bez rewizji odczytu", ustalenie.CheckID)
		}
	}

	// Ten sam stan hosta daje ten sam odcisk planu.
	powtorzony := raportOchrony(t, h, host.ID)
	if powtorzony.PlanHash != raport.PlanHash {
		t.Error("odcisk planu zmienil sie miedzy dwoma odczytami tego samego stanu")
	}
}

// TestNaprawaWymagaPlanuIWyboru pilnuje reguly z dokumentu: nie ma przycisku
// "napraw wszystko", a plan wiaze zlecenie ze stanem, ktory operator ogladal.
func TestNaprawaWymagaPlanuIWyboru(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	raport := raportOchrony(t, h, host.ID)

	// Plan sprzed zmiany stanu nie moze zostac wykonany.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": "0000", "check_ids": []string{"kernel.rp-filter"},
			"reason": powodOchrony}, nil, http.StatusConflict)

	// Pusta lista nie znaczy "wszystko".
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": raport.PlanHash, "check_ids": []string{}, "reason": powodOchrony},
		nil, http.StatusBadRequest)

	// Sprawdzenie spoza planu nie istnieje.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": raport.PlanHash, "check_ids": []string{"nie.ma.takiego"},
			"reason": powodOchrony}, nil, http.StatusBadRequest)

	// Ustalenie bez operacji naprawczej nie tworzy zadania - i mowi dlaczego.
	var bezOperacji string
	for _, ustalenie := range raport.Findings {
		if !ustalenie.Passed && !ustalenie.Unknown &&
			(ustalenie.Remediation == nil || ustalenie.Remediation.Action == "") {
			bezOperacji = ustalenie.CheckID
			break
		}
	}
	if bezOperacji == "" {
		t.Skip("ten host nie ma ustalenia bez operacji naprawczej")
	}
	var odpowiedz struct {
		Steps []krokNaprawyView `json:"steps"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": raport.PlanHash, "check_ids": []string{bezOperacji},
			"reason": powodOchrony}, &odpowiedz, http.StatusCreated)
	if len(odpowiedz.Steps) != 1 || odpowiedz.Steps[0].JobID != "" {
		t.Fatalf("kroki = %+v", odpowiedz.Steps)
	}
	if odpowiedz.Steps[0].Skipped == "" {
		t.Error("krok pominiety bez wyjasnienia")
	}
}

// TestNaprawaTworzyZadanieModulu sprawdza, ze naprawa nie jest osobnym
// mechanizmem: to zwykle zadanie modulu, ktory za dana rzecz odpowiada.
func TestNaprawaTworzyZadanieModulu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	raport := raportOchrony(t, h, host.ID)

	var doNaprawy ustalenieView
	for _, ustalenie := range raport.Findings {
		if !ustalenie.Passed && !ustalenie.Unknown &&
			ustalenie.Remediation != nil && ustalenie.Remediation.Action != "" {
			doNaprawy = ustalenie
			break
		}
	}
	if doNaprawy.CheckID == "" {
		t.Skip("ten host nie ma ustalenia z operacja naprawcza")
	}

	var odpowiedz struct {
		PlanHash string            `json:"plan_hash"`
		Steps    []krokNaprawyView `json:"steps"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": raport.PlanHash, "check_ids": []string{doNaprawy.CheckID},
			"reason": powodOchrony}, &odpowiedz, http.StatusCreated)
	if len(odpowiedz.Steps) != 1 || odpowiedz.Steps[0].JobID == "" {
		t.Fatalf("kroki = %+v", odpowiedz.Steps)
	}
	krok := odpowiedz.Steps[0]
	if krok.Action != doNaprawy.Remediation.Action {
		t.Errorf("operacja = %q, plan mowil %q", krok.Action, doNaprawy.Remediation.Action)
	}

	// Zadanie naprawcze przechodzi zwykla droge: czeka na zatwierdzenie tak
	// samo jak to samo zlecenie zlozone recznie.
	var zadanie jobView
	h.do(http.MethodGet, "/api/v1/jobs/"+krok.JobID, nil, &zadanie, http.StatusOK)
	if zadanie.ActionType != doNaprawy.Remediation.Action {
		t.Errorf("typ zadania = %q", zadanie.ActionType)
	}
	if !zadanie.RequiresApprova {
		t.Error("zadanie naprawcze nie wymaga zatwierdzenia")
	}
	// Nie wykonujemy go: test sprawdza droge, a nie zmienia stanu floty.
	// Powtorzony przebieg dostaje to samo zadanie - klucz idempotencji wiaze
	// je z planem - wiec anulujemy tylko wtedy, gdy jeszcze czeka.
	if zadanie.State == "awaiting_approval" || zadanie.State == "queued" {
		h.do(http.MethodPost, "/api/v1/jobs/"+krok.JobID+"/cancel",
			map[string]any{"reason": "koniec testu integracyjnego"}, nil, http.StatusOK)
	}
}

// TestPrzelaczenieMACMaGranice pilnuje tego, czego panel nie robi: nie wylacza
// SELinuksa i nie udaje, ze ma go host, ktory go nie ma.
func TestPrzelaczenieMACMaGranice(t *testing.T) {
	h := newHarness(t)

	// Wylaczenie nie dojezdza do hosta: odrzuca je walidacja zlecenia.
	rhel := h.hostByFamily("rhel")
	h.do(http.MethodPost, "/api/v1/hosts/"+rhel.ID+"/operations",
		map[string]any{"action": "selinux.mode.set", "reason": powodOchrony,
			"payload": map[string]any{"security": map[string]any{"mode": "disabled"}}},
		nil, http.StatusBadRequest)

	// Host bez SELinuksa odmawia juz przy zlecaniu, a nie po dostarczeniu.
	debian := h.hostByFamily("debian")
	if maZdolnosc(debian, "security.mac") {
		t.Skip("ten host ma SELinuksa, wiec nie sprawdzi odmowy z braku zdolnosci")
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+debian.ID+"/operations",
		map[string]any{"action": "selinux.mode.set", "reason": powodOchrony,
			"payload": map[string]any{"security": map[string]any{"mode": "permissive"}}},
		nil, http.StatusConflict)
}

func maZdolnosc(host hostView, nazwa string) bool {
	for _, zdolnosc := range host.Capabilities {
		if zdolnosc.Name == nazwa {
			return zdolnosc.Available
		}
	}
	return false
}

func migawkaOchronyHosta(t *testing.T, h *harness, hostID string) migawkaOchrony {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/security", nil, &fragment, http.StatusOK)
	var stan migawkaOchrony
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		t.Fatalf("migawka ochrony: %v", err)
	}
	return stan
}

func raportOchrony(t *testing.T, h *harness, hostID string) raportView {
	t.Helper()
	var raport raportView
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/security", nil, &raport, http.StatusOK)
	return raport
}
