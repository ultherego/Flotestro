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
	Reach    string `json:"reach"`
}

type migawkaOchrony struct {
	MAC struct {
		System         string `json:"system"`
		Mode           string `json:"mode"`
		ConfiguredMode string `json:"configured_mode"`
		Reason         string `json:"reason"`
	} `json:"mac"`
	Audit struct {
		Present         bool  `json:"present"`
		Active          *bool `json:"active"`
		RulesLoaded     *int  `json:"rules_loaded"`
		RulesConfigured *int  `json:"rules_configured"`
	} `json:"audit"`
	FIPSEnabled       *bool             `json:"fips_enabled"`
	SecureBoot        *bool             `json:"secure_boot"`
	SecureBootReason  string            `json:"secure_boot_reason"`
	Listening         []nasluchView     `json:"listening"`
	ListeningKnown    bool              `json:"listening_known"`
	OwnersKnown       bool              `json:"owners_known"`
	Missing           map[string]string `json:"missing"`
	UnavailableReason string            `json:"unavailable_reason"`
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
	Applicable   bool         `json:"applicable"`
	Passed       bool         `json:"passed"`
	Unknown      bool         `json:"unknown"`
	ReasonCode   string       `json:"reason_code"`
	Expected     string       `json:"expected"`
	Observed     string       `json:"observed"`
	Module       string       `json:"module"`
	Revision     string       `json:"revision"`
	Remediation  *naprawaView `json:"remediation"`
}

type raportView struct {
	Findings        []ustalenieView `json:"findings"`
	PlanHash        string          `json:"plan_hash"`
	PlanHashVersion int             `json:"plan_hash_version"`
	GeneratedAt     time.Time       `json:"generated_at"`
	Counts          map[string]int  `json:"counts"`
}

type krokPlanuView struct {
	Position       int    `json:"position"`
	CheckID        string `json:"check_id"`
	CheckVersion   int    `json:"check_version"`
	ActionType     string `json:"action_type"`
	LockClass      string `json:"lock_class"`
	RequiresReboot bool   `json:"requires_reboot"`
	JobID          string `json:"job_id"`
	State          string `json:"state"`
	Reason         string `json:"reason"`
}

type planNaprawyView struct {
	ID              string          `json:"id"`
	HostID          string          `json:"host_id"`
	PlanHash        string          `json:"plan_hash"`
	PlanHashVersion int             `json:"plan_hash_version"`
	StopOnFailure   bool            `json:"stop_on_failure"`
	State           string          `json:"state"`
	Steps           []krokPlanuView `json:"steps"`
}

type odpowiedzPlanu struct {
	Plan    planNaprawyView   `json:"plan"`
	Skipped map[string]string `json:"skipped"`
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
				t.Error("host nie zglosil zadnego gniazda, a przynajmniej agent gdzies slucha")
			}
			// Zasieg jest klasyfikacja, a nie wnioskiem o widocznosci
			// z internetu: tego nie widac z samego adresu.
			klasy := map[string]bool{"loopback": true, "host-network": true, "all-interfaces": true}
			for _, gniazdo := range stan.Listening {
				if !klasy[gniazdo.Reach] {
					t.Errorf("gniazdo %s/%d ma zasieg %q", gniazdo.Protocol, gniazdo.Port, gniazdo.Reach)
				}
			}
			// Fakt, ktorego nie udalo sie zebrac, niesie powod - a nie
			// wartosc domyslna.
			for nazwa, powod := range stan.Missing {
				if powod == "" {
					t.Errorf("brakujacy fakt %s bez powodu", nazwa)
				}
			}
			// Reguly zaladowane i skonfigurowane to dwa pytania.
			if stan.Audit.Present && stan.Audit.Active != nil && *stan.Audit.Active {
				if stan.Audit.RulesLoaded == nil || stan.Audit.RulesConfigured == nil {
					t.Errorf("dzialajacy audyt bez licznikow regul: %+v", stan.Audit)
				}
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
	// Postac kanoniczna odcisku jest wersjonowana: zmiana zasad liczenia ma
	// uniewaznic zatwierdzone plany jawnie, a nie po cichu.
	if raport.PlanHashVersion == 0 {
		t.Error("raport bez wersji kanonizacji odcisku")
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
		if (ustalenie.Passed || ustalenie.Unknown || !ustalenie.Applicable) && ustalenie.Remediation != nil {
			t.Errorf("%s nie wymaga dzialania, a niesie naprawe", ustalenie.CheckID)
		}
		// Stan nieustalony i "nie dotyczy" nios kod powodu: bez niego
		// operator nie wie, czy czekac, naprawiac, czy nadac uprawnienia.
		if (ustalenie.Unknown || !ustalenie.Applicable) && ustalenie.ReasonCode == "" {
			t.Errorf("%s bez wyniku i bez kodu powodu", ustalenie.CheckID)
		}
		if ustalenie.Applicable && !ustalenie.Unknown && ustalenie.ReasonCode != "" {
			t.Errorf("%s ma wynik i kod powodu naraz: %q", ustalenie.CheckID, ustalenie.ReasonCode)
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

// TestSprawdzenieNiedotyczaceNieJestPorazka pilnuje granicy oceny: host bez
// danego komponentu nie przegrywa jego sprawdzenia i nie zalicza go po cichu.
func TestSprawdzenieNiedotyczaceNieJestPorazka(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			stan := migawkaOchronyHosta(t, h, host.ID)
			raport := raportOchrony(t, h, host.ID)

			trwalosc := znajdzUstalenie(t, raport, "mac.persistent")
			maSELinuksa := stan.MAC.System == "selinux"
			if trwalosc.Applicable != maSELinuksa {
				t.Errorf("sprawdzenie SELinuksa: applicable=%v przy systemie MAC %q",
					trwalosc.Applicable, stan.MAC.System)
			}
			if !trwalosc.Applicable && (trwalosc.Passed || trwalosc.Unknown) {
				t.Errorf("stan nie dotyczy zmieszany z wynikiem: %+v", trwalosc)
			}

			// Host bez demona audytu nie przegrywa sprawdzenia jego regul.
			reguly := znajdzUstalenie(t, raport, "audit.rules-loaded")
			if !stan.Audit.Present && reguly.Applicable {
				t.Errorf("sprawdzenie regul dotyczy hosta bez audytu: %+v", reguly)
			}

			// Podsumowanie liczy stan nie dotyczy osobno.
			if raport.Counts["not_applicable"] == 0 && !maSELinuksa {
				t.Errorf("podsumowanie bez stanu nie dotyczy: %v", raport.Counts)
			}
		})
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
	// Ustalenie bez operacji nie tworzy planu w ogole: nie ma z czego.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": raport.PlanHash, "check_ids": []string{bezOperacji},
			"reason": powodOchrony}, nil, http.StatusBadRequest)
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

	var odpowiedz odpowiedzPlanu
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": raport.PlanHash, "check_ids": []string{doNaprawy.CheckID},
			"reason": powodOchrony}, &odpowiedz, http.StatusCreated)
	plan := odpowiedz.Plan
	t.Cleanup(func() {
		// Plan zostawiony w toku blokowalby kolejne przebiegi tego testu.
		h.do(http.MethodPost,
			"/api/v1/hosts/"+host.ID+"/security/remediation/"+plan.ID+"/stop", nil, nil, 0)
	})

	if plan.State != "running" || len(plan.Steps) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	krok := plan.Steps[0]
	if krok.ActionType != doNaprawy.Remediation.Action {
		t.Errorf("operacja = %q, plan mowil %q", krok.ActionType, doNaprawy.Remediation.Action)
	}
	if krok.Position != 1 || krok.CheckVersion != doNaprawy.CheckVersion {
		t.Errorf("krok = %+v", krok)
	}
	if !plan.StopOnFailure {
		t.Error("plan nie zatrzymuje sie po bledzie")
	}
	if plan.PlanHash != raport.PlanHash || plan.PlanHashVersion != raport.PlanHashVersion {
		t.Errorf("plan nie jest zwiazany z ustaleniami: %+v", plan)
	}

	// Drugi plan na tym samym hoscie nie moze isc rownolegle: kroki jednego
	// zakladaja stan, ktory drugi zmienia pod nimi.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": raport.PlanHash, "check_ids": []string{doNaprawy.CheckID},
			"reason": powodOchrony}, nil, http.StatusConflict)

	// Zatrzymanie zamyka plan i nie zostawia krokow w zawieszeniu.
	var zatrzymany planNaprawyView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation/"+plan.ID+"/stop",
		nil, &zatrzymany, http.StatusOK)
	if zatrzymany.State != "stopped" {
		t.Errorf("plan po zatrzymaniu = %q", zatrzymany.State)
	}
	for _, krok := range zatrzymany.Steps {
		if krok.State == "pending" {
			t.Errorf("krok %s zostal w stanie pending po zatrzymaniu planu", krok.CheckID)
		}
	}
}

func znajdzUstalenie(t *testing.T, raport raportView, id string) ustalenieView {
	t.Helper()
	for _, ustalenie := range raport.Findings {
		if ustalenie.CheckID == id {
			return ustalenie
		}
	}
	t.Fatalf("raport nie ma ustalenia %s", id)
	return ustalenieView{}
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
