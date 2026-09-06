//go:build integration

package integration

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/vuln/version"
)

// zamowienieView odwzorowuje zamowienie enrollmentu.
// krokView odwzorowuje jeden krok instalacji.
type krokView struct {
	Key   string `json:"key"`
	State string `json:"state"`
}

type zamowienieView struct {
	ID                string     `json:"id"`
	Token             string     `json:"token"`
	Site              string     `json:"site"`
	Environment       string     `json:"environment"`
	Kind              string     `json:"kind"`
	Purpose           string     `json:"purpose"`
	ExpectedMachineID string     `json:"expected_machine_id"`
	ExpectedHostID    string     `json:"expected_host_id"`
	MaxUses           int        `json:"max_uses"`
	Uses              int        `json:"uses"`
	Status            string     `json:"status"`
	EnrolledHostID    string     `json:"enrolled_host_id"`
	ExpiresAt         time.Time  `json:"expires_at"`
	Steps             []krokView `json:"steps"`
}

// TestZamowienieEnrollmentuPokazujeTokenRaz pilnuje, ze jawny token istnieje
// wylacznie w odpowiedzi na utworzenie zamowienia.
//
// Token jest sekretem jednorazowym. Gdyby dalo sie go odczytac z listy albo
// z pojedynczego zamowienia, kazdy z prawem odczytu instalacji mialby klucz
// do wprowadzenia wlasnej maszyny do floty.
func TestZamowienieEnrollmentuPokazujeTokenRaz(t *testing.T) {
	h := newHarness(t)
	var utworzone zamowienieView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "test zamowienia", "site": "lab", "environment": "test",
		"ttl_minutes": 15,
	}, &utworzone, http.StatusCreated)

	if utworzone.Token == "" {
		t.Fatal("zamowienie bez tokenu - agent nie ma czym sie przedstawic")
	}
	if utworzone.Purpose != "new" || utworzone.Kind != "agent" {
		t.Fatalf("cel = %q, rodzaj = %q", utworzone.Purpose, utworzone.Kind)
	}
	if utworzone.Status != "pending" {
		t.Fatalf("status = %q", utworzone.Status)
	}

	var odczytane zamowienieView
	h.get("/api/v1/enrollment-requests/"+utworzone.ID, &odczytane)
	if odczytane.Token != "" {
		t.Fatal("odczyt zamowienia oddaje token")
	}
	if odczytane.ID != utworzone.ID {
		t.Fatalf("id = %q, chcemy %q", odczytane.ID, utworzone.ID)
	}

	var lista struct {
		Items []zamowienieView `json:"items"`
	}
	h.get("/api/v1/enrollment-requests", &lista)
	znalezione := false
	for _, pozycja := range lista.Items {
		if pozycja.ID == utworzone.ID {
			znalezione = true
		}
		if pozycja.Token != "" {
			t.Fatalf("lista zamowien oddaje token dla %s", pozycja.ID)
		}
	}
	if !znalezione {
		t.Fatal("utworzone zamowienie nie pojawilo sie na liscie")
	}
}

// TestCofnieteZamowienieNieDzialaOdRazu pilnuje, ze cofniecie zamyka token
// natychmiast, takze gdy czesc puli zostala juz wykorzystana.
func TestCofnieteZamowienieNieDzialaOdRazu(t *testing.T) {
	h := newHarness(t)
	var utworzone zamowienieView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "do cofniecia", "site": "lab", "environment": "test", "max_uses": 5,
	}, &utworzone, http.StatusCreated)

	h.do(http.MethodPost, "/api/v1/enrollment-requests/"+utworzone.ID+"/revoke",
		nil, nil, http.StatusNoContent)

	var po zamowienieView
	h.get("/api/v1/enrollment-requests/"+utworzone.ID, &po)
	if po.Status != "revoked" {
		t.Fatalf("status po cofnieciu = %q", po.Status)
	}
	// Cofniecie jest idempotentne: druga proba nie moze skonczyc sie bledem
	// serwera, bo operator nie ma jak sprawdzic, czy pierwsza doszla.
	h.do(http.MethodPost, "/api/v1/enrollment-requests/"+utworzone.ID+"/revoke",
		nil, nil, http.StatusNoContent)
	h.do(http.MethodPost,
		"/api/v1/enrollment-requests/00000000-0000-4000-8000-000000000000/revoke",
		nil, nil, http.StatusNotFound)
}

// TestZamowienieOdtworzeniaTozsamosciWiazeSieZHostem pilnuje, ze wymiana
// tozsamosci jest zwiazana z konkretnym hostem, a nie z dowolna maszyna.
func TestZamowienieOdtworzeniaTozsamosciWiazeSieZHostem(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var zamowienie zamowienieView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery",
		map[string]any{"description": "po przeinstalowaniu"}, &zamowienie, http.StatusCreated)

	if zamowienie.Purpose != "replace_identity" {
		t.Fatalf("cel = %q", zamowienie.Purpose)
	}
	if zamowienie.ExpectedHostID != host.ID {
		t.Fatalf("zamowienie wskazuje hosta %q, chcemy %q", zamowienie.ExpectedHostID, host.ID)
	}
	// Odtworzenie dotyczy jednego hosta, wiec i jednego uzycia: token
	// wielokrotny bylby kluczem do tej samej maszyny na zapas.
	if zamowienie.MaxUses != 1 {
		t.Fatalf("liczba uzyc = %d", zamowienie.MaxUses)
	}
	if zamowienie.Token == "" {
		t.Fatal("zamowienie bez tokenu")
	}
	// Zakres bierze sie z hosta: odtworzenie tozsamosci nie jest okazja do
	// przeniesienia hosta do innego srodowiska.
	if zamowienie.Site != host.Site || zamowienie.Environment != host.Environment {
		t.Fatalf("zakres = %s/%s, host = %s/%s", zamowienie.Site, zamowienie.Environment,
			host.Site, host.Environment)
	}

	// Tego celu nie da sie zamowic zwyklym wejsciem: wymiana tozsamosci ma
	// wlasne prawo i wlasna droge.
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"purpose": "replace_identity", "site": "lab", "environment": "test",
	}, nil, http.StatusBadRequest)
}

// TestZamowienieMaGraniceCzasu pilnuje, ze token nie moze lezec tygodniami.
func TestZamowienieMaGraniceCzasu(t *testing.T) {
	h := newHarness(t)
	var utworzone zamowienieView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "domyslny czas", "site": "lab", "environment": "test",
	}, &utworzone, http.StatusCreated)
	if zostalo := time.Until(utworzone.ExpiresAt); zostalo > time.Hour {
		t.Fatalf("domyslny czas zycia = %s", zostalo)
	}
	// Powyzej doby token jest sekretem czekajacym na wyciek.
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "za dlugi", "site": "lab", "environment": "test",
		"ttl_minutes": 60 * 48,
	}, nil, http.StatusBadRequest)
}

// TestKwarantannaOdcinaHostaINieBlokujeGo pilnuje, ze odciecie dziala od razu
// i da sie je zdjac.
//
// Test przechodzi na hoscie floty testowej i przywraca go na koniec: pozostawiony
// w kwarantannie host wywrocilby wszystkie pozostale testy.
func TestKwarantannaOdcinaHostaINieBlokujeGo(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	var wynik struct {
		LifecycleState string `json:"lifecycle_state"`
		SessionClosed  bool   `json:"session_closed"`
		JobsCanceled   int    `json:"jobs_canceled"`
	}
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
			map[string]any{"reason": "koniec testu"}, nil, http.StatusOK)
		// Agent wraca dopiero po swoim backoffie. Bez czekania kolejne testy
		// zastaja host offline i przewracaja sie z powodu, ktory nie ma nic
		// wspolnego z tym, co sprawdzaja.
		h.poczekajNaPolaczenie(host.ID, time.Minute)
	})

	// Powod jest wymagany: host odciety bez powodu jest hostem, o ktorym za
	// tydzien nikt nie bedzie wiedzial, czemu nie pracuje.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine",
		map[string]any{}, nil, http.StatusBadRequest)

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine",
		map[string]any{"reason": "test kwarantanny"}, &wynik, http.StatusOK)
	if wynik.LifecycleState != "quarantined" {
		t.Fatalf("stan = %q", wynik.LifecycleState)
	}
	if !wynik.SessionClosed {
		t.Error("sesja hosta nie zostala zamknieta - kwarantanna sprawdzana " +
			"dopiero przy nastepnym polaczeniu nie odcina przejetej maszyny")
	}

	// Host w kwarantannie nie przyjmuje nowych operacji.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "journal.read",
			"payload": map[string]any{"journal": map[string]any{"lines": 5}}},
		nil, http.StatusConflict)
}

// TestWycofanieWymagaPrzepisaniaNazwy pilnuje, ze utraty zaufania nie da sie
// kliknac przez pomylke.
func TestWycofanieWymagaPrzepisaniaNazwy(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/decommission",
		map[string]any{"reason": "proba bez potwierdzenia"}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/decommission",
		map[string]any{"reason": "proba z cudza nazwa", "typed_confirmation": "inny-host"},
		nil, http.StatusBadRequest)

	// Hosta floty testowej nie wycofujemy naprawde: sprawdzamy sama bramke.
	// Pelne wycofanie ma wlasny test na maszynie syntetycznej.
}

// TestWycofanyHostNieWracaTokenem pilnuje, ze utrata zaufania jest decyzja
// panelu, a nie stanem, ktory da sie cofnac tokenem na hoscie.
func TestWycofanyHostNieWracaTokenem(t *testing.T) {
	h := newHarness(t)
	// Maszyny syntetycznej nie ma we flocie, wiec mozemy ja naprawde wycofac.
	host := h.zarejestrujSyntetycznyHost(t)

	var wynik struct {
		LifecycleState      string `json:"lifecycle_state"`
		CertificatesRevoked int    `json:"certificates_revoked"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/decommission",
		map[string]any{"reason": "maszyna oddana", "typed_confirmation": host.Hostname},
		&wynik, http.StatusOK)
	if wynik.LifecycleState != "retired" {
		t.Fatalf("stan = %q", wynik.LifecycleState)
	}
	// Wycofanie zawsze odwoluje certyfikaty: host nie moze wrocic sam
	// z waznym certyfikatem w reku.
	if wynik.CertificatesRevoked == 0 {
		t.Error("wycofanie nie odwolalo zadnego certyfikatu")
	}

	// Zamowienie odtworzenia dla wycofanego hosta jest obietnica bez pokrycia.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery",
		map[string]any{"description": "powrot"}, nil, http.StatusConflict)

	// Kwarantanny wycofanego hosta tez nie ma po co zdejmowac.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
		map[string]any{"reason": "proba powrotu"}, nil, http.StatusConflict)
}

// TestPostepInstalacjiOpisujeKroki pilnuje, ze ekran instalacji dostaje
// prawde o tym, co host juz zrobil.
//
// Kroki sa osobne, bo kazdy zawodzi z innego powodu: token moze wygasnac,
// certyfikat moze zostac odrzucony przy bledzie CSR, sesja moze nie dojsc
// przez zapore, a inwentarz moze nie przyjsc, gdy agent nie ma zdolnosci.
func TestPostepInstalacjiOpisujeKroki(t *testing.T) {
	h := newHarness(t)
	var utworzone zamowienieView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "test krokow", "site": "lab", "environment": "test",
	}, &utworzone, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+utworzone.ID+"/revoke",
			nil, nil, 0)
	})

	var przed zamowienieView
	h.get("/api/v1/enrollment-requests/"+utworzone.ID, &przed)
	if len(przed.Steps) != 4 {
		t.Fatalf("krokow = %d: %+v", len(przed.Steps), przed.Steps)
	}
	for _, krok := range przed.Steps {
		if krok.State != "waiting" {
			t.Fatalf("krok %s przed instalacja = %q", krok.Key, krok.State)
		}
	}

	// Maszyna syntetyczna rejestruje sie i na tym poprzestaje: nie laczy sie
	// sesja i nie przysyla inwentarza, wiec dwa pierwsze kroki maja byc
	// zrobione, a dwa kolejne dalej czekac.
	host := h.zarejestrujSyntetycznyHostZamowieniem(t, utworzone.Token)
	var po zamowienieView
	h.get("/api/v1/enrollment-requests/"+utworzone.ID, &po)
	stany := map[string]string{}
	for _, krok := range po.Steps {
		stany[krok.Key] = krok.State
	}
	if stany["token"] != "done" || stany["certificate"] != "done" {
		t.Fatalf("kroki po rejestracji = %v", stany)
	}
	if stany["connected"] != "waiting" || stany["inventory"] != "waiting" {
		t.Errorf("host bez sesji pokazany jako polaczony: %v", stany)
	}
	if po.EnrolledHostID != host.ID {
		t.Fatalf("zamowienie wskazuje hosta %q, chcemy %q", po.EnrolledHostID, host.ID)
	}
	if po.Status != "enrolled" {
		t.Fatalf("status po rejestracji = %q", po.Status)
	}
}

// TestWymianaAgentaKonczySiePowrotemHosta pilnuje wlasciwosci, dla ktorej ta
// operacja w ogole istnieje osobno: sukcesem jest host, ktory wrocil
// z oczekiwana wersja, a nie kod wyjscia menedzera pakietow.
//
// Agent wymienia sam siebie, wiec proces liczacy zadanie ginie w polowie.
// Gdyby panel czekal na jego wynik, kazda wymiana konczylaby sie limitem
// czasu - takze wtedy, gdy host wrocil sprawny.
func TestWymianaAgentaKonczySiePowrotemHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var przed struct {
		AgentVersion string `json:"agent_version"`
	}
	h.get("/api/v1/hosts/"+host.ID, &przed)
	// Cel bierzemy z repozytorium floty testowej: musi tam byc, bo inaczej
	// menedzer pakietow nie ma czego zainstalowac. Domyslnie jest to wersja
	// najnowsza - test, ktory cofalby hosta na stare wydanie, zostawialby
	// flote na kodzie sprzed zmiany i nie dalby sie powtorzyc.
	cel := os.Getenv("FLOTESTRO_TEST_AGENT_VERSION")
	if cel == "" {
		cel = h.najnowszaWersjaAgenta()
	}
	if przed.AgentVersion == cel {
		t.Skipf("host jest juz w wersji %s", cel)
	}

	job := h.createOperation(host.ID, map[string]any{
		"action":  "agent.upgrade",
		"payload": map[string]any{"agent_upgrade": map[string]any{"target_version": cel}},
	})
	if job.ID == "" {
		t.Fatal("nie powstalo zadanie wymiany agenta")
	}
	// Wymiana agenta jest operacja wysokiego ryzyka: odcina host od
	// zarzadzania na czas restartu, wiec wymaga zatwierdzenia.
	if !job.RequiresApprova {
		t.Fatal("wymiana agenta nie wymaga zatwierdzenia")
	}
	job = h.approve(job.ID, job.PayloadHash)

	// Wymiana trwa: pakiet, restart uslugi i powrot sesji. Panel rozstrzyga
	// dopiero po Hello z nowa wersja.
	koniec := time.Now().Add(4 * time.Minute)
	var stan jobView
	for time.Now().Before(koniec) {
		h.get("/api/v1/jobs/"+job.ID, &stan)
		if stan.State == "succeeded" || stan.State == "failed" {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if stan.State != "succeeded" {
		t.Fatalf("zadanie wymiany agenta w stanie %q (%s)", stan.State, stan.ResultMessage)
	}

	var po struct {
		AgentVersion string `json:"agent_version"`
	}
	h.get("/api/v1/hosts/"+host.ID, &po)
	if po.AgentVersion != cel {
		t.Fatalf("host zglasza wersje %q, oczekiwano %q", po.AgentVersion, cel)
	}
	h.poczekajNaPolaczenie(host.ID, time.Minute)
}

// najnowszaWersjaAgenta czyta z repozytorium floty testowej najwyzsza wersje
// pakietu agenta.
//
// Wersji nie zgadujemy ze stalej w tescie: repozytorium laboratorium rosnie
// przy kazdym wydaniu, a wersja wpisana na sztywno cofalaby hosta tym dalej,
// im dluzej zyje projekt. Brak odpowiedzi konczy test pominieciem z powodem -
// wymiana agenta na wersje, ktorej nie ma w repozytorium, nie jest testem.
func (h *harness) najnowszaWersjaAgenta() string {
	h.t.Helper()
	adres := envOr("FLOTESTRO_TEST_REPO", defaultRepo)
	response, err := h.client.Get(adres + "/deb/dists/stable/main/binary-amd64/Packages")
	if err != nil {
		h.t.Skipf("repozytorium floty testowej niedostepne (%s): %v", adres, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		h.t.Skipf("repozytorium floty testowej odpowiedzialo %s", response.Status)
	}
	tresc, err := io.ReadAll(response.Body)
	if err != nil {
		h.t.Skipf("indeks repozytorium nieczytelny: %v", err)
	}

	var pakiet string
	var najnowsza string
	for _, linia := range strings.Split(string(tresc), "\n") {
		switch {
		case strings.HasPrefix(linia, "Package: "):
			pakiet = strings.TrimSpace(strings.TrimPrefix(linia, "Package: "))
		case strings.HasPrefix(linia, "Version: ") && pakiet == "flotestro-agent":
			wersja := strings.TrimSpace(strings.TrimPrefix(linia, "Version: "))
			if najnowsza == "" || version.PorownajDeb(wersja, najnowsza) > 0 {
				najnowsza = wersja
			}
		}
	}
	if najnowsza == "" {
		h.t.Skip("repozytorium floty testowej nie ma pakietu agenta")
	}
	return najnowsza
}
