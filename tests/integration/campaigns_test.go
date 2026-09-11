//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

type campaignView struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	State            string `json:"state"`
	CanarySize       int    `json:"canary_size"`
	WaveSize         int    `json:"wave_size"`
	RequiresApproval bool   `json:"requires_approval"`
	// Odcisk tego, co zatwierdzajacy widzi. Zgoda bez niego dotyczylaby
	// samego identyfikatora kampanii.
	ApprovalFingerprint string `json:"approval_fingerprint"`
	PlanSetHash         string `json:"plan_set_hash"`
	CreatedBy           string `json:"created_by"`
	ApprovedBy          string `json:"approved_by"`
	PausedBy            string `json:"paused_by"`
	PauseReason         string `json:"pause_reason"`
}

type campaignTargetView struct {
	HostID    string `json:"host_id"`
	Hostname  string `json:"hostname"`
	Wave      int    `json:"wave"`
	State     string `json:"state"`
	ErrorCode string `json:"error_code"`
	JobID     string `json:"job_id"`
	PlanJobID string `json:"plan_job_id"`
}

type campaignReportView struct {
	State  string         `json:"state"`
	Totals map[string]int `json:"totals"`
	Waves  []struct {
		Wave      int            `json:"wave"`
		IsCanary  bool           `json:"is_canary"`
		Totals    map[string]int `json:"totals"`
		Completed bool           `json:"completed"`
	} `json:"waves"`
	Failures []campaignTargetView `json:"failures"`
}

func (h *harness) createCampaign(body map[string]any) campaignView {
	h.t.Helper()
	var campaign campaignView
	h.do(http.MethodPost, "/api/v1/campaigns", body, &campaign, http.StatusCreated)
	h.t.Cleanup(func() {
		// Kampania w toku zablokowalaby kolejne testy na tych samych hostach.
		h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
			map[string]any{"reason": "koniec testu"}, nil, 0)
	})
	return campaign
}

// approveCampaign zatwierdza kampanie jej wlasnym odciskiem.
func (h *harness) approveCampaign(campaign campaignView) campaignView {
	h.t.Helper()
	var zatwierdzona campaignView
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		map[string]any{"approval_fingerprint": campaign.ApprovalFingerprint},
		&zatwierdzona, http.StatusOK)
	return zatwierdzona
}

func (h *harness) campaign(id string) campaignView {
	h.t.Helper()
	var campaign campaignView
	h.get("/api/v1/campaigns/"+id, &campaign)
	return campaign
}

func (h *harness) campaignTargets(id string) []campaignTargetView {
	h.t.Helper()
	var result struct {
		Items []campaignTargetView `json:"items"`
	}
	h.get("/api/v1/campaigns/"+id+"/targets", &result)
	return result.Items
}

// awaitCampaign czeka na jeden z oczekiwanych stanow kampanii.
func (h *harness) awaitCampaign(id string, wanted map[string]bool, timeout time.Duration) campaignView {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	var last campaignView
	for time.Now().Before(deadline) {
		last = h.campaign(id)
		if wanted[last.State] {
			return last
		}
		time.Sleep(2 * time.Second)
	}
	h.t.Fatalf("kampania %s nie osiagnela oczekiwanego stanu (jest %s)", id, last.State)
	return last
}

func labCampaign(name, unit string, extra map[string]any) map[string]any {
	body := map[string]any{
		"name":                       name,
		"action":                     "unit.restart",
		"payload":                    unitPayload(unit),
		"selector":                   map[string]any{"site": "lab"},
		"canary_size":                1,
		"wave_size":                  1,
		"max_concurrent":             1,
		"failure_threshold_absolute": 0,
		"failure_threshold_percent":  0,
		"reboot_policy":              "never",
	}
	for key, value := range extra {
		body[key] = value
	}
	return body
}

// TestKampaniaTworzyMigawkeCelow sprawdza, ze selektor jest natychmiast
// zamieniany na niemutowalna liste hostow z podzialem na fale.
func TestKampaniaTworzyMigawkeCelow(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("migawka celow", "cron.service", nil))

	if campaign.State != "awaiting_approval" {
		t.Fatalf("stan = %s, oczekiwano awaiting_approval", campaign.State)
	}
	targets := h.campaignTargets(campaign.ID)
	if len(targets) < 2 {
		t.Fatalf("migawka ma %d celow, oczekiwano co najmniej 2", len(targets))
	}

	// Fala 0 jest canary i ma dokladnie tyle hostow, ile podano.
	canary := 0
	for _, target := range targets {
		if target.Wave == 0 {
			canary++
		}
		if target.State != "pending" {
			t.Errorf("cel %s ruszyl przed zatwierdzeniem: %s", target.Hostname, target.State)
		}
	}
	if canary != campaign.CanarySize {
		t.Errorf("canary ma %d hostow, oczekiwano %d", canary, campaign.CanarySize)
	}
}

// TestKampaniaCzekaNaZatwierdzenie sprawdza, ze samo utworzenie niczego nie
// uruchamia. Zatwierdzenie kampanii jest zgoda na zmiane na wielu hostach.
func TestKampaniaCzekaNaZatwierdzenie(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("czekanie na zgode", "cron.service", nil))

	time.Sleep(8 * time.Second)
	current := h.campaign(campaign.ID)
	if current.State != "awaiting_approval" {
		t.Fatalf("niezatwierdzona kampania zmienila stan na %s", current.State)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.State != "pending" {
			t.Errorf("cel %s ruszyl bez zatwierdzenia", target.Hostname)
		}
	}
}

// TestCanaryPoprzedzaKolejneFale sprawdza, ze fala 1 nie rusza, zanim canary
// sie nie zamknie.
func TestCanaryPoprzedzaKolejneFale(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("canary przed fala", "cron.service", nil))
	h.approveCampaign(campaign)

	// W chwili, gdy canary pracuje, kolejne fale musza czekac.
	deadline := time.Now().Add(60 * time.Second)
	sawCanaryFirst := false
	for time.Now().Before(deadline) {
		targets := h.campaignTargets(campaign.ID)
		canaryOpen, laterStarted := false, false
		for _, target := range targets {
			if target.Wave == 0 && (target.State == "running" || target.State == "pending") {
				canaryOpen = true
			}
			if target.Wave > 0 && target.State != "pending" {
				laterStarted = true
			}
		}
		if canaryOpen && laterStarted {
			t.Fatal("fala po canary ruszyla, zanim canary sie zamknelo")
		}
		if !canaryOpen {
			sawCanaryFirst = true
			break
		}
		time.Sleep(time.Second)
	}
	if !sawCanaryFirst {
		t.Skip("canary nie zamknelo sie w czasie testu")
	}
}

// TestProgBledowWstrzymujeKampanie jest testem najwazniejszego zabezpieczenia:
// bledna zmiana nie moze przejsc przez cala flote.
func TestProgBledowWstrzymujeKampanie(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("kampania z bledem", "nieistniejaca-jednostka.service",
		map[string]any{"failure_threshold_absolute": 1}))
	h.approveCampaign(campaign)

	paused := h.awaitCampaign(campaign.ID, map[string]bool{"paused": true}, 90*time.Second)
	if paused.PauseReason == "" {
		t.Error("kampania wstrzymana bez podania powodu")
	}
	if paused.PausedBy != "system" {
		t.Errorf("wstrzymal %q, oczekiwano system", paused.PausedBy)
	}

	targets := h.campaignTargets(campaign.ID)
	failed, untouched := 0, 0
	for _, target := range targets {
		switch {
		case target.State == "failed":
			failed++
			// Kod bledu musi dotrzec do kampanii, inaczej operator widzi samo
			// slowo "failed" bez przyczyny.
			if target.ErrorCode == "" {
				t.Errorf("cel %s padl bez kodu bledu", target.Hostname)
			}
		case target.State == "pending":
			untouched++
		}
	}
	if failed == 0 {
		t.Fatal("kampania wstrzymana, ale zaden host nie jest oznaczony jako bledny")
	}
	// Sedno progu: hosty kolejnych fal nie zostaly ruszone.
	if untouched == 0 {
		t.Error("po przekroczeniu progu nie zostal zaden nietkniety host")
	}
}

// TestRaportKampaniiOpisujeFale sprawdza kompletnosc raportu koncowego.
func TestRaportKampaniiOpisujeFale(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("raport", "nieistniejaca-jednostka.service",
		map[string]any{"failure_threshold_absolute": 1}))
	h.approveCampaign(campaign)
	h.awaitCampaign(campaign.ID, map[string]bool{"paused": true}, 90*time.Second)

	var report campaignReportView
	h.get("/api/v1/campaigns/"+campaign.ID+"/report", &report)

	if len(report.Waves) == 0 {
		t.Fatal("raport nie opisuje zadnej fali")
	}
	if !report.Waves[0].IsCanary {
		t.Error("pierwsza fala nie jest oznaczona jako canary")
	}
	if len(report.Failures) == 0 {
		t.Error("raport nie wymienia hostow, ktore padly")
	}
	if report.Totals["failed"] == 0 {
		t.Error("podsumowanie nie liczy bledow")
	}
}

// TestWstrzymanaKampaniaDaSieWznowicIAnulowac sprawdza sterowanie kampania.
func TestWstrzymanaKampaniaDaSieWznowicIAnulowac(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("sterowanie", "cron.service", nil))
	h.approveCampaign(campaign)

	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/pause",
		map[string]any{"reason": "test"}, nil, http.StatusOK)
	if state := h.campaign(campaign.ID).State; state != "paused" {
		t.Fatalf("stan po wstrzymaniu = %s", state)
	}

	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/resume", nil, nil, http.StatusOK)
	if state := h.campaign(campaign.ID).State; state == "paused" {
		t.Fatal("kampania pozostala wstrzymana po wznowieniu")
	}

	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
		map[string]any{"reason": "koniec"}, nil, http.StatusOK)
	final := h.campaign(campaign.ID)
	if final.State != "canceled" {
		t.Fatalf("stan po anulowaniu = %s", final.State)
	}
	// Anulowanie nie moze zostawic hostow czekajacych w kolejce.
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.State == "pending" {
			t.Errorf("cel %s zostal w stanie pending po anulowaniu", target.Hostname)
		}
	}
}

// TestOperatorNieZatwierdzaKampanii sprawdza rozdzial obowiazkow na poziomie
// kampanii: jedno zatwierdzenie uruchamia zmiane na wielu hostach.
func TestOperatorNieZatwierdzaKampanii(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	operator := h.withToken(h.createPrincipal(uniqueSubject("operator-kampanie"), []map[string]string{
		{"role": "operator", "site": host.Site, "environment": host.Environment},
	}))
	approver := h.withToken(h.createPrincipal(uniqueSubject("approver-kampanie"), []map[string]string{
		{"role": "approver", "site": host.Site, "environment": host.Environment},
	}))

	body := labCampaign("rozdzial obowiazkow", "cron.service", map[string]any{
		"selector": map[string]any{"host_ids": []string{host.ID}},
	})
	var campaign campaignView
	operator.do(http.MethodPost, "/api/v1/campaigns", body, &campaign, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
			map[string]any{"reason": "koniec testu"}, nil, 0)
	})

	zgoda := map[string]any{"approval_fingerprint": campaign.ApprovalFingerprint}
	// Operator prowadzi kampanie, ale jej nie zatwierdza.
	operator.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		zgoda, nil, http.StatusForbidden)
	// Approver zatwierdza, ale nie tworzy.
	approver.do(http.MethodPost, "/api/v1/campaigns", body, nil, http.StatusForbidden)
	approver.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		zgoda, nil, http.StatusOK)
}

// TestKampaniaPozaZakresemJestOdrzucana sprawdza, ze uprawnienie jest badane
// dla kazdego hosta z migawki, a nie tylko dla pierwszego.
func TestKampaniaPozaZakresemJestOdrzucana(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	obcy := h.withToken(h.createPrincipal(uniqueSubject("operator-obcy"), []map[string]string{
		{"role": "operator", "site": "inna-lokalizacja", "environment": "inne"},
	}))
	obcy.do(http.MethodPost, "/api/v1/campaigns",
		labCampaign("poza zakresem", "cron.service", map[string]any{
			"selector": map[string]any{"host_ids": []string{host.ID}},
		}), nil, http.StatusForbidden)
}

// TestKampaniaOdmawiaOperacjiBezTrybuMasowego pilnuje bramki, ktora oddziela
// operacje jednohostowe od flotowych. Odmowa ma przyjsc przy zlecaniu i miec
// wlasny kod: kampania, ktora zatwierdza jeden payload dla operacji liczacej
// inny plan na kazdym hoscie, zatwierdzalaby zmiane, ktorej nikt nie widzial.
func TestKampaniaOdmawiaOperacjiBezTrybuMasowego(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Rodziny, ktorych operacja "*.plan" czyta stan hosta zamiast liczyc diff
	// wobec stanu docelowego. Zapis pliku i profil sieci byly tu kiedys
	// przykladami i przestaly nimi byc, gdy dostaly prawdziwe planery - o to
	// w tej bramce chodzi: przepustka jest deklaracja i mechanizm, a nie
	// nazwa operacji.
	przypadki := map[string]map[string]any{
		"filesystem.resize": {"storage": map[string]any{
			"device": "/dev/sdb",
		}},
		"lvm.extend": {"storage": map[string]any{
			"device": "/dev/vg0/dane", "size": "+1G",
		}},
	}
	for akcja, payload := range przypadki {
		t.Run(akcja, func(t *testing.T) {
			var odpowiedz struct {
				Code   string `json:"code"`
				Detail string `json:"detail"`
			}
			h.do(http.MethodPost, "/api/v1/campaigns", map[string]any{
				"name": "tryb masowy " + akcja, "action": akcja, "payload": payload,
				"selector": map[string]any{"host_ids": []string{host.ID}},
			}, &odpowiedz, http.StatusBadRequest)
			if odpowiedz.Code != "campaign_mode_unsupported" {
				t.Fatalf("kod odmowy = %q (%s)", odpowiedz.Code, odpowiedz.Detail)
			}
			if odpowiedz.Detail == "" {
				t.Error("odmowa bez powodu wyglada jak brak funkcji")
			}
		})
	}
}

// TestZatwierdzenieDotyczyTegoCoWidac pilnuje inwariantu zgody: zatwierdzenie
// bez odcisku albo z cudzym odciskiem nie jest zgoda na te kampanie.
func TestZatwierdzenieDotyczyTegoCoWidac(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	campaign := h.createCampaign(labCampaign("odcisk zgody", "cron.service",
		map[string]any{"selector": map[string]any{"host_ids": []string{host.ID}}}))

	if campaign.ApprovalFingerprint == "" {
		t.Fatal("kampania bez odcisku zatwierdzenia")
	}
	// Bez odcisku i z cudzym odciskiem: jedno i drugie jest zgoda na cos
	// innego niz ta kampania.
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		map[string]any{}, nil, http.StatusConflict)
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		map[string]any{"approval_fingerprint": "0000000000000000"}, nil, http.StatusConflict)

	zatwierdzona := h.approveCampaign(campaign)
	if zatwierdzona.ApprovedBy == "" {
		t.Fatal("kampania zatwierdzona bez zapisania osoby")
	}
}

// TestKampaniaPracujeNaWieluHostachNaraz jest dowodem, ze multitasking
// naprawde dziala. Limit rownoleglosci wiekszy od jednego ma znaczyc, ze dwa
// hosty pracuja obok siebie, a nie ze kolejka idzie szybciej.
func TestKampaniaPracujeNaWieluHostachNaraz(t *testing.T) {
	h := newHarness(t)
	// Jedna rodzina systemow: kampania ma pokazac rownoleglosc, a nie
	// roznice w nazwach jednostek miedzy dystrybucjami.
	hosty := h.hosts()
	online := make([]string, 0, len(hosty))
	for _, host := range hosty {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			online = append(online, host.ID)
		}
	}
	if len(online) < 2 {
		t.Skip("flota ma mniej niz dwa podlaczone hosty rodziny debian")
	}

	// Bez canary i z jedna fala: caly zestaw ma ruszyc naraz.
	campaign := h.createCampaign(labCampaign("rownoleglosc", "cron.service", map[string]any{
		"selector":       map[string]any{"host_ids": online},
		"canary_size":    0,
		"wave_size":      len(online),
		"max_concurrent": len(online),
	}))
	h.approveCampaign(campaign)

	koncowa := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)
	if koncowa.State != "completed" {
		t.Fatalf("kampania skonczyla sie stanem %s (%s)", koncowa.State, koncowa.PauseReason)
	}

	// Rownoleglosc rozstrzygamy z czasow prob, a nie z odpytywania: dwie
	// operacje trwajace ulamek sekundy moglyby zmiescic sie miedzy jednym
	// zapytaniem a drugim, a i tak dzialalyby obok siebie.
	okna := make([]okno, 0, len(online))
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.JobID == "" {
			continue
		}
		for _, proba := range h.probyZadania(target.JobID) {
			if proba.DispatchedAt == nil || proba.FinishedAt == nil {
				continue
			}
			okna = append(okna, okno{od: *proba.DispatchedAt, do: *proba.FinishedAt})
		}
	}
	if len(okna) < 2 {
		t.Fatalf("kampania zostawila %d prob z czasami", len(okna))
	}
	if !zachodzaNaSiebie(okna) {
		t.Errorf("zadne dwie proby nie dzialaly obok siebie: %+v", okna)
	}
}

type okno struct{ od, do time.Time }

// zachodzaNaSiebie mowi, czy ktorekolwiek dwa okna maja wspolna chwile.
func zachodzaNaSiebie(okna []okno) bool {
	for i := range okna {
		for j := i + 1; j < len(okna); j++ {
			if okna[i].od.Before(okna[j].do) && okna[j].od.Before(okna[i].do) {
				return true
			}
		}
	}
	return false
}

// probyZadania zwraca proby wraz z czasami wyslania i zakonczenia.
func (h *harness) probyZadania(jobID string) []probaZCzasem {
	h.t.Helper()
	var odpowiedz struct {
		Items []probaZCzasem `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &odpowiedz)
	return odpowiedz.Items
}

type probaZCzasem struct {
	Status       string     `json:"status"`
	DispatchedAt *time.Time `json:"dispatched_at"`
	FinishedAt   *time.Time `json:"finished_at"`
}

// TestKolidujaceOperacjeNaHoscieSaSerializowane pilnuje blokad zasobow hosta.
//
// Trzy restarty tej samej jednostki zlecone naraz musza wykonac sie po kolei.
// Dowod jest w stanie jednostki: kazdy restart widzi przed soba proces, ktory
// zostawil poprzedni. Gdyby dwa restarty weszly obok siebie, ten lancuch by
// sie zerwal - a limit zadan hosta sam z siebie tego nie zapewnia, bo klasa
// ogolna ma wiecej niz jedno miejsce.
func TestKolidujaceOperacjeNaHoscieSaSerializowane(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	const ile = 3
	zadania := make([]string, 0, ile)
	for i := 0; i < ile; i++ {
		job := h.createOperation(host.ID, map[string]any{
			"action": "unit.restart", "reason": "test serializacji blokad zasobu",
			"payload": unitPayload("cron.service"),
		})
		if job.RequiresApprova {
			job = h.approve(job.ID, job.PayloadHash)
		}
		zadania = append(zadania, job.ID)
	}

	type wykonanie struct {
		koniec     time.Time
		pidPrzed   uint32
		pidPo      uint32
		stanPrzed  string
		identyfika string
	}
	wykonania := make([]wykonanie, 0, ile)
	for _, jobID := range zadania {
		zadanie := h.awaitTerminal(jobID, 3*time.Minute)
		if zadanie.State != "succeeded" {
			t.Fatalf("restart %s: stan = %s, kod = %s",
				jobID, zadanie.State, zadanie.ResultErrorCode)
		}
		proby := h.attempts(jobID)
		ostatnia := proby[len(proby)-1]
		if ostatnia.UnitStateBefore == nil || ostatnia.UnitStateAfter == nil {
			t.Fatalf("restart %s bez stanu jednostki", jobID)
		}
		czasy := h.probyZadania(jobID)
		koniec := czasy[len(czasy)-1].FinishedAt
		if koniec == nil {
			t.Fatalf("restart %s bez czasu zakonczenia", jobID)
		}
		wykonania = append(wykonania, wykonanie{
			koniec: *koniec, pidPrzed: ostatnia.UnitStateBefore.MainPID,
			pidPo: ostatnia.UnitStateAfter.MainPID, stanPrzed: ostatnia.UnitStateBefore.ActiveState,
			identyfika: jobID,
		})
	}

	sort.Slice(wykonania, func(i, j int) bool {
		return wykonania[i].koniec.Before(wykonania[j].koniec)
	})
	for i := 1; i < len(wykonania); i++ {
		if wykonania[i].pidPrzed != wykonania[i-1].pidPo {
			t.Errorf("restart %s zaczal od procesu %d, a poprzedni zostawil %d - operacje weszly na siebie",
				wykonania[i].identyfika, wykonania[i].pidPrzed, wykonania[i-1].pidPo)
		}
	}
}

// TestKampaniaPakietowLiczyPlanNaKazdymHoscie pilnuje najwazniejszej zmiany
// Campaigns v2: zgoda nie dotyczy jednego payloadu, tylko zestawu planow.
//
// Dwa hosty wybrane tym samym zamowieniem prawie nigdy nie maja tego samego
// diffu, wiec kampania najpierw pyta kazdy host, co u niego wyjdzie, a dopiero
// potem prosi o zgode. Odcisk zatwierdzenia zmienia sie po planowaniu -
// dowodem jest to, ze zgoda podana odciskiem sprzed planowania jest odrzucona.
func TestKampaniaPakietowLiczyPlanNaKazdymHoscie(t *testing.T) {
	h := newHarness(t)
	hosty := h.hosts()
	cele := make([]string, 0, 2)
	for _, host := range hosty {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			cele = append(cele, host.ID)
		}
	}
	if len(cele) < 2 {
		t.Skip("flota ma mniej niz dwa podlaczone hosty rodziny debian")
	}

	campaign := h.createCampaign(map[string]any{
		"name": "aktualizacja z planami", "action": "packages.upgrade",
		"payload":                    map[string]any{"package_upgrade": map[string]any{"security_only": true}},
		"selector":                   map[string]any{"host_ids": cele},
		"canary_size":                0,
		"wave_size":                  len(cele),
		"max_concurrent":             len(cele),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("kampania pakietowa zaczela od stanu %s", campaign.State)
	}
	odciskZamowienia := campaign.ApprovalFingerprint

	// Faza planowania konczy sie sama: kazdy host liczy swoj plan.
	poPlanowaniu := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if poPlanowaniu.State != "awaiting_approval" {
		t.Fatalf("planowanie skonczylo sie stanem %s (%s)",
			poPlanowaniu.State, poPlanowaniu.PauseReason)
	}
	if poPlanowaniu.PlanSetHash == "" {
		t.Fatal("kampania po planowaniu bez odcisku zestawu planow")
	}
	if poPlanowaniu.ApprovalFingerprint == odciskZamowienia {
		t.Error("zestaw planow nie zmienil odcisku zatwierdzenia")
	}

	// Zgoda podana odciskiem sprzed planowania dotyczy czegos innego.
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		map[string]any{"approval_fingerprint": odciskZamowienia}, nil, http.StatusConflict)

	// Kazdy cel ma zadanie planujace i wrocil do kolejki.
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.PlanJobID == "" {
			t.Errorf("cel %s bez zadania planujacego", target.Hostname)
		}
		if target.State != "pending" {
			t.Errorf("cel %s po planowaniu jest w stanie %s", target.Hostname, target.State)
		}
	}

	h.approveCampaign(poPlanowaniu)
	koncowa := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 5*time.Minute)
	if koncowa.State != "completed" {
		t.Fatalf("kampania skonczyla sie stanem %s (%s)", koncowa.State, koncowa.PauseReason)
	}
}

type budzetView struct {
	Klucz     string `json:"key"`
	Pojemnosc int    `json:"capacity"`
	Zajete    int    `json:"used"`
	Chetnych  int    `json:"claimants"`
}

// ustawBudzet zmienia pojemnosc budzetu na czas testu i przywraca ja potem.
func (h *harness) ustawBudzet(klucz string, pojemnosc, poTescie int) {
	h.t.Helper()
	h.do(http.MethodPut, "/api/v1/budgets/"+klucz,
		map[string]any{"capacity": pojemnosc, "note": "test integracyjny budzetow"},
		nil, http.StatusOK)
	h.t.Cleanup(func() {
		// Budzet zmieniony na czas testu musi wrocic: zostawiony na jedynce
		// spowolnilby kazdy nastepny przebieg i wygladalo by to na usterke.
		h.do(http.MethodPut, "/api/v1/budgets/"+klucz,
			map[string]any{"capacity": poTescie, "note": "po tescie"}, nil, 0)
	})
}

// TestBudzetLokalizacjiZatrzymujeNadmiarowaZmiane pilnuje inwariantu I-05:
// limit rownoleglosci kampanii nie jest jedynym limitem systemu.
//
// Kampania prosi o trzy hosty naraz i ma na to zgode - a mimo to lokalizacja
// dopuszcza jedna zmiane tej rodziny. Dowod jest w czasach prob: zadne dwie
// nie moga zachodzic na siebie. Dowodem drugim jest widocznosc: host, ktory
// czeka, musi to powiedziec, a nie stac w kolejce bez powodu.
//
// Kontrola negatywna stoi obok: TestKampaniaPracujeNaWieluHostachNaraz robi to
// samo na tej samej flocie przy domyslnej pojemnosci i wymaga, zeby okna sie
// zachodzily. Bez tej pary "brak zachodzenia" moglby znaczyc po prostu wolna
// flote, a nie dzialajacy budzet.
func TestBudzetLokalizacjiZatrzymujeNadmiarowaZmiane(t *testing.T) {
	h := newHarness(t)
	// Jedna rodzina systemow i jedna lokalizacja: dowod dotyczy budzetu,
	// a nie roznic w nazwach jednostek miedzy dystrybucjami.
	online := make([]hostView, 0, 3)
	lokalizacja := ""
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" || host.OSFamily != "debian" {
			continue
		}
		if lokalizacja == "" {
			lokalizacja = host.Site
		}
		if host.Site == lokalizacja {
			online = append(online, host)
		}
	}
	if len(online) < 2 || lokalizacja == "" {
		t.Skip("flota testowa ma mniej niz dwa podlaczone hosty rodziny debian w jednej lokalizacji")
	}

	// Jednostki sa najtansza mutacja, jaka mamy: dowod dotyczy budzetu,
	// a nie tego, co konkretnie robi operacja.
	klucz := "site:" + lokalizacja + ":units"
	const domyslnaPojemnosc = 10
	h.ustawBudzet(klucz, 1, domyslnaPojemnosc)

	cele := make([]string, 0, len(online))
	for _, host := range online {
		cele = append(cele, host.ID)
	}
	campaign := h.createCampaign(map[string]any{
		"name": "restart z budzetem", "action": "unit.restart",
		"reason":                     "test budzetu lokalizacji",
		"payload":                    unitPayload("cron.service"),
		"selector":                   map[string]any{"host_ids": cele},
		"canary_size":                0,
		"wave_size":                  len(cele),
		"max_concurrent":             len(cele),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State == "awaiting_approval" {
		campaign = h.approveCampaign(campaign)
	}

	// Po drodze przynajmniej jeden host musi zglosic, ze czeka na pojemnosc.
	// Sprawdzamy to w trakcie, bo stan jest przejsciowy.
	czekal := false
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		for _, target := range h.campaignTargets(campaign.ID) {
			if target.State == "awaiting_budget" {
				czekal = true
				if target.ErrorCode != "budget_capacity" && target.ErrorCode != "budget_fair_share" {
					t.Errorf("host czeka na budzet bez podanego powodu: %+v", target)
				}
			}
		}
		stan := h.campaign(campaign.ID)
		if stan.State == "completed" || stan.State == "failed" || stan.State == "paused" {
			break
		}
		time.Sleep(time.Second)
	}

	koncowa := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 4*time.Minute)
	if koncowa.State != "completed" {
		t.Fatalf("kampania skonczyla sie stanem %s (%s)", koncowa.State, koncowa.PauseReason)
	}
	if !czekal {
		t.Error("zaden host nie zglosil oczekiwania na pojemnosc - budzet nikogo nie zatrzymal")
	}

	okna := make([]okno, 0, len(cele))
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.JobID == "" {
			continue
		}
		for _, proba := range h.probyZadania(target.JobID) {
			if proba.DispatchedAt == nil || proba.FinishedAt == nil {
				continue
			}
			okna = append(okna, okno{od: *proba.DispatchedAt, do: *proba.FinishedAt})
		}
	}
	if len(okna) < 2 {
		t.Fatalf("kampania zostawila %d prob z czasami", len(okna))
	}
	// Sedno inwariantu: kampania miala zgode na trzy naraz, a lokalizacja
	// dopuszczala jedna. Zachodzace okna znaczylyby, ze budzet nie wiazal.
	if zachodzaNaSiebie(okna) {
		t.Errorf("dwie zmiany weszly obok siebie mimo budzetu 1: %+v", okna)
	}
}

// TestBudzetPokazujeZajetoscIOdmawiaZerowejPojemnosci pilnuje ekranu, bez
// ktorego kampania stojaca na budzecie wyglada jak kampania zapomniana.
func TestBudzetPokazujeZajetoscIOdmawiaZerowejPojemnosci(t *testing.T) {
	h := newHarness(t)
	var widok struct {
		Items []budzetView `json:"items"`
	}
	h.get("/api/v1/budgets", &widok)
	if len(widok.Items) == 0 {
		t.Fatal("panel nie ma ani jednego budzetu - pojemnosci nikt nie pilnuje")
	}
	znalezione := map[string]budzetView{}
	for _, budzet := range widok.Items {
		if budzet.Pojemnosc < 1 {
			t.Errorf("budzet %s o pojemnosci %d", budzet.Klucz, budzet.Pojemnosc)
		}
		znalezione[budzet.Klucz] = budzet
	}
	// Odczyt i mutacja maja osobne pojemnosci: sto odczytow stanu to nie to
	// samo obciazenie co sto transakcji pakietowych.
	for _, klucz := range []string{"global:mutations", "global:reads"} {
		if _, mamy := znalezione[klucz]; !mamy {
			t.Errorf("brak budzetu %s: %+v", klucz, widok.Items)
		}
	}

	// Pojemnosc zerowa nie jest polityka, tylko cichym zatrzymaniem wszystkiego.
	h.do(http.MethodPut, "/api/v1/budgets/global:mutations",
		map[string]any{"capacity": 0}, nil, http.StatusBadRequest)
}

// TestZmianaBudzetuWymagaUprawnienia pilnuje, ze pojemnosci nie podnosi sie
// po cichu: budzet podniesiony bez sladu odbiera znaczenie kazdemu limitowi
// ponizej.
func TestZmianaBudzetuWymagaUprawnienia(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	operatorToken := h.createPrincipal(uniqueSubject("bez-budzetow"),
		[]map[string]string{{"role": "approver", "site": host.Site, "environment": host.Environment}})
	bezPrawa := h.withToken(operatorToken)

	bezPrawa.do(http.MethodPut, "/api/v1/budgets/global:mutations",
		map[string]any{"capacity": 500}, nil, http.StatusForbidden)
}

type podgladView struct {
	Count        int      `json:"count"`
	Limit        int      `json:"limit"`
	Eligible     int      `json:"eligible"`
	Sample       []string `json:"sample"`
	CampaignMode string   `json:"campaign_mode"`
	RequiresPlan bool     `json:"requires_plan"`
	Excluded     []struct {
		Reason string   `json:"reason"`
		Count  int      `json:"count"`
		Sample []string `json:"sample"`
	} `json:"excluded"`
	Notes []struct {
		Reason string   `json:"reason"`
		Count  int      `json:"count"`
		Sample []string `json:"sample"`
	} `json:"notes"`
}

// TestPodgladOdrozniaGotowegoOdNiezdolnego pilnuje kryterium A-02: operator ma
// przed startem wiedziec, ktore hosty ruszaja i dlaczego pozostale nie.
//
// Flota testowa ma host Archa, ktory nie ma ani apta, ani dnf-a. Aktualizacja
// pakietow jest na nim niewykonalna i panel ma to powiedziec przed
// utworzeniem kampanii, a nie bledem przy wykonaniu. Ten sam host jest
// jednoczesnie gotowy do restartu jednostki - kwalifikacja zalezy od operacji,
// a nie od hosta.
func TestPodgladOdrozniaGotowegoOdNiezdolnego(t *testing.T) {
	h := newHarness(t)

	var restart podgladView
	h.get("/api/v1/campaigns/preview?action=unit.restart", &restart)
	if restart.Count == 0 {
		t.Fatal("podglad nie widzi ani jednego hosta")
	}
	if restart.Eligible == 0 {
		t.Fatalf("zaden host nie jest gotowy do restartu jednostki: %+v", restart)
	}
	if restart.CampaignMode != "same_payload" {
		t.Errorf("restart jednostki w trybie %q", restart.CampaignMode)
	}
	if restart.RequiresPlan {
		t.Error("restart jednostki nie liczy planu na hoscie")
	}

	var aktualizacja podgladView
	h.get("/api/v1/campaigns/preview?action=packages.upgrade", &aktualizacja)
	if !aktualizacja.RequiresPlan || aktualizacja.CampaignMode != "per_host_plan" {
		t.Errorf("aktualizacja pakietow opisana jako %q, plan=%v",
			aktualizacja.CampaignMode, aktualizacja.RequiresPlan)
	}
	// Ta sama flota, inna operacja: host bez adaptera pakietow ma byc
	// wykluczony z powodem, a nie policzony jako gotowy.
	if aktualizacja.Eligible >= restart.Eligible {
		t.Errorf("aktualizacja ma %d gotowych hostow przy %d gotowych do restartu - "+
			"host bez apta i dnf-a nie zostal rozpoznany",
			aktualizacja.Eligible, restart.Eligible)
	}
	brakAdaptera := 0
	for _, grupa := range aktualizacja.Excluded {
		if grupa.Reason == "capability_missing" {
			brakAdaptera = grupa.Count
			if len(grupa.Sample) == 0 {
				t.Error("wykluczenie bez ani jednej nazwy hosta")
			}
		}
	}
	if brakAdaptera == 0 {
		t.Errorf("podglad nie wyklucza ani jednego hosta bez adaptera: %+v", aktualizacja.Excluded)
	}
	if aktualizacja.Eligible+brakAdaptera > aktualizacja.Count {
		t.Errorf("gotowych %d i wykluczonych %d przy %d dopasowanych",
			aktualizacja.Eligible, brakAdaptera, aktualizacja.Count)
	}
}

// TestKampaniaZostawiaNiezdolnyHostWMigawce pilnuje doktryny: host, ktory nie
// wykona operacji, nie znika po cichu.
//
// Wykluczenie po cichu jest gorsze niz odmowa: operator zatwierdza kampanie na
// czterech hostach, a dowiaduje sie o trzech dopiero z raportu - albo nie
// dowiaduje sie wcale.
func TestKampaniaZostawiaNiezdolnyHostWMigawce(t *testing.T) {
	h := newHarness(t)
	cele := make([]string, 0, 4)
	niezdolne := 0
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		cele = append(cele, host.ID)
		if host.OSFamily == "arch" {
			niezdolne++
		}
	}
	if niezdolne == 0 {
		t.Skip("flota testowa nie ma hosta bez adaptera pakietow")
	}

	campaign := h.createCampaign(map[string]any{
		"name": "aktualizacja calej floty", "action": "packages.upgrade",
		"payload":                    map[string]any{"package_upgrade": map[string]any{"security_only": true}},
		"selector":                   map[string]any{"host_ids": cele},
		"canary_size":                0,
		"wave_size":                  len(cele),
		"max_concurrent":             len(cele),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})

	stany := map[string]int{}
	powody := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		stany[target.State]++
		if target.State == "ineligible" {
			powody[target.Hostname] = target.ErrorCode
		}
	}
	if stany["ineligible"] != niezdolne {
		t.Errorf("migawka ma %d hostow niezdolnych przy %d bez adaptera: %+v",
			stany["ineligible"], niezdolne, stany)
	}
	for hostname, kod := range powody {
		if kod != "capability_missing" {
			t.Errorf("host %s niezdolny bez podanego powodu: %q", hostname, kod)
		}
	}
	// Host niezdolny nie jest awaria: kampania ma isc dalej na pozostalych.
	if stany["pending"]+stany["planning"] == 0 {
		t.Errorf("kampania nie zostawila ani jednego hosta do pracy: %+v", stany)
	}
}

// TestKampaniaComposeNiesieDigestPlanuNaHosta pilnuje, ze faza planowania nie
// jest wlasnoscia pakietow: druga rodzina liczy plan na hoscie i dostaje go
// z powrotem razem ze zmiana.
//
// Digest planu Compose powstaje z manifestu i z digestow obrazow, ktore ten
// host naprawde widzi. Wdrozenie niesie go z powrotem, a host odmawia, gdy
// przestal pasowac - zgoda dotyczyla tamtego planu, nie tego.
func TestKampaniaComposeNiesieDigestPlanuNaHosta(t *testing.T) {
	h := newHarness(t)
	const projekt = "flotestro-kampania"
	manifest := "services:\n  web:\n    image: nginx:alpine\n"

	// Docker jest w tej flocie na jednym hoscie. To wystarczy, zeby pokazac
	// faze planowania, a pozostale hosty pokazuja przy okazji, ze niezdolnosc
	// nie jest awaria.
	cele := make([]string, 0, 4)
	zDockerem := 0
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		cele = append(cele, host.ID)
		// O zdolnosci mowi rejestr adapterow hosta, a nie zgadywanie po
		// dystrybucji: silnik kontenerow moze byc wszedzie albo nigdzie.
		for _, zdolnosc := range host.Capabilities {
			if zdolnosc.Name == "docker.compose" && zdolnosc.Available {
				zDockerem++
			}
		}
	}
	if zDockerem == 0 {
		t.Skip("flota testowa nie ma hosta z silnikiem kontenerow")
	}

	campaign := h.createCampaign(map[string]any{
		"name": "wdrozenie projektu", "action": "docker.compose.deploy",
		"reason":                     "test integracyjny planow Compose",
		"payload":                    map[string]any{"compose": map[string]any{"project": projekt, "manifest": manifest}},
		"selector":                   map[string]any{"host_ids": cele},
		"canary_size":                0,
		"wave_size":                  len(cele),
		"max_concurrent":             len(cele),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("kampania Compose zaczela od stanu %s", campaign.State)
	}
	odciskZamowienia := campaign.ApprovalFingerprint

	poPlanowaniu := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if poPlanowaniu.State != "awaiting_approval" {
		t.Fatalf("planowanie skonczylo sie stanem %s (%s)",
			poPlanowaniu.State, poPlanowaniu.PauseReason)
	}
	if poPlanowaniu.PlanSetHash == "" {
		t.Fatal("kampania Compose po planowaniu bez odcisku zestawu planow")
	}
	if poPlanowaniu.ApprovalFingerprint == odciskZamowienia {
		t.Error("zestaw planow nie zmienil odcisku zatwierdzenia")
	}

	// Host bez silnika kontenerow jest niezdolny, a nie zepsuty: nie liczy sie
	// do progu bledow i nie zatrzymuje kampanii.
	planowalo, niezdolnych := 0, 0
	for _, target := range h.campaignTargets(campaign.ID) {
		switch target.State {
		case "ineligible":
			niezdolnych++
		case "pending":
			planowalo++
			if target.PlanJobID == "" {
				t.Errorf("cel %s bez zadania planujacego", target.Hostname)
			}
		}
	}
	if planowalo != zDockerem {
		t.Errorf("plan policzylo %d hostow, silnik ma %d", planowalo, zDockerem)
	}
	if niezdolnych != len(cele)-zDockerem {
		t.Errorf("niezdolnych %d przy %d hostach bez silnika",
			niezdolnych, len(cele)-zDockerem)
	}

	// Sprzatanie idzie po kontenerach, bo panel nie ma operacji "zdejmij
	// projekt": wdrozenie jest deklaracja stanu, a nie poleceniem, ktore da
	// sie cofnac jednym rozkazem.
	t.Cleanup(func() {
		for _, hostID := range cele {
			for _, kontener := range kontenneryProjektu(h, hostID, projekt) {
				h.runOperation(hostID, map[string]any{
					"action": "docker.container.remove",
					"reason": "sprzatanie po tescie Compose",
					"payload": map[string]any{
						"docker_container": map[string]any{"container_id": kontener, "force": true},
					},
				}, 2*time.Minute)
			}
		}
	})

	h.approveCampaign(poPlanowaniu)
	koncowa := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 5*time.Minute)
	if koncowa.State != "completed" {
		t.Fatalf("kampania skonczyla sie stanem %s (%s)", koncowa.State, koncowa.PauseReason)
	}
}

// kontenneryProjektu zwraca identyfikatory kontenerow jednego projektu Compose.
func kontenneryProjektu(h *harness, hostID, projekt string) []string {
	h.t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/containers",
		nil, &fragment, http.StatusOK)
	if len(fragment.Payload) == 0 {
		return nil
	}
	var stan struct {
		Containers []struct {
			ID      string            `json:"id"`
			Labels  map[string]string `json:"labels"`
			Compose *struct {
				Project string `json:"project"`
			} `json:"compose"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		return nil
	}
	identyfikatory := []string{}
	for _, kontener := range stan.Containers {
		if (kontener.Compose != nil && kontener.Compose.Project == projekt) ||
			kontener.Labels["com.docker.compose.project"] == projekt {
			identyfikatory = append(identyfikatory, kontener.ID)
		}
	}
	return identyfikatory
}

type wpisPrzebieguView struct {
	ID         int64           `json:"id"`
	Aggregate  string          `json:"aggregate_type"`
	Type       string          `json:"event_type"`
	Payload    json.RawMessage `json:"payload"`
	OccurredAt time.Time       `json:"occurred_at"`
}

// TestPrzebiegKampaniiPrzezywaRestartPanelu pilnuje inwariantu I-14: przebieg
// kampanii da sie odtworzyc z trwalych zapisow, a nie tylko z powiadomien.
//
// Powiadomienie wyslane w chwili, gdy panel byl restartowany, nie istnieje juz
// nigdzie. Stan koncowy zostaje w tabelach, ale przebieg - to, co i kiedy sie
// stalo - znikal razem z nim. Kampania bez przebiegu jest raportem po fakcie,
// a nie kontrola nad rolloutem.
func TestPrzebiegKampaniiPrzezywaRestartPanelu(t *testing.T) {
	h := newHarness(t)
	online := make([]string, 0, 2)
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			online = append(online, host.ID)
		}
	}
	if len(online) < 2 {
		t.Skip("flota ma mniej niz dwa podlaczone hosty rodziny debian")
	}

	campaign := h.createCampaign(labCampaign("przebieg", "cron.service", map[string]any{
		"selector":       map[string]any{"host_ids": online},
		"canary_size":    1,
		"wave_size":      len(online),
		"max_concurrent": len(online),
	}))
	h.approveCampaign(campaign)
	koncowa := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)
	if koncowa.State != "completed" {
		t.Fatalf("kampania skonczyla sie stanem %s (%s)", koncowa.State, koncowa.PauseReason)
	}

	var przebieg struct {
		Items []wpisPrzebieguView `json:"items"`
	}
	h.get("/api/v1/campaigns/"+campaign.ID+"/timeline", &przebieg)
	if len(przebieg.Items) == 0 {
		t.Fatal("kampania bez ani jednego zdarzenia w przebiegu")
	}

	// Przebieg ma nazwac fazy kampanii i losy hostow. Sam stan koncowy widac
	// w tabelach; tutaj chodzi o to, jak do niego doszlo.
	rodzaje := map[string]int{}
	for _, wpis := range przebieg.Items {
		rodzaje[wpis.Type]++
		if wpis.OccurredAt.IsZero() {
			t.Errorf("zdarzenie %s bez czasu", wpis.Type)
		}
		if len(wpis.Payload) == 0 {
			t.Errorf("zdarzenie %s bez tresci", wpis.Type)
		}
	}
	for _, wymagane := range []string{
		"campaign.canary", "campaign.running", "campaign.completed",
		"target.running", "target.succeeded",
	} {
		if rodzaje[wymagane] == 0 {
			t.Errorf("przebieg bez zdarzenia %s: %+v", wymagane, rodzaje)
		}
	}
	if rodzaje["target.succeeded"] != len(online) {
		t.Errorf("zdarzen target.succeeded %d przy %d hostach",
			rodzaje["target.succeeded"], len(online))
	}

	// Kolejnosc jest czescia odpowiedzi: canary poprzedza pozostale fale.
	for i := 1; i < len(przebieg.Items); i++ {
		if przebieg.Items[i].ID <= przebieg.Items[i-1].ID {
			t.Fatalf("przebieg nie jest uporzadkowany: %d po %d",
				przebieg.Items[i].ID, przebieg.Items[i-1].ID)
		}
	}
}

// TestMetrykiPokazujaMaszynerieKampanii pilnuje obserwowalnosci tej czesci
// systemu, ktora bez niej jest niewidzialna.
//
// Kampania stojaca na budzecie i kampania, ktora idzie, wygladaja z zewnatrz
// tak samo: obie sa "w toku". Tylko jedna z nich wymaga reakcji, a rozroznia
// je kod powodu przy hostach i zajetosc budzetu.
func TestMetrykiPokazujaMaszynerieKampanii(t *testing.T) {
	h := newHarness(t)
	tekst := h.tekst("/metrics")

	// Budzety sa opisane zawsze - takze wtedy, gdy nic ich nie zajmuje.
	// Pojemnosc podana dopiero wtedy, gdy jest problem, nie pozwolilaby
	// zobaczyc, jak blisko granicy pracuje flota.
	for _, fragment := range []string{
		"flotestro_budget_tokens",
		`flotestro_budget_tokens{budget="global:mutations",status="capacity"}`,
		`flotestro_budget_tokens{budget="global:mutations",status="used"}`,
	} {
		if !strings.Contains(tekst, fragment) {
			t.Errorf("metryki bez %q", fragment)
		}
	}

	online := make([]string, 0, 2)
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			online = append(online, host.ID)
		}
	}
	if len(online) < 2 {
		t.Skip("flota ma mniej niz dwa podlaczone hosty rodziny debian")
	}

	campaign := h.createCampaign(labCampaign("metryki", "cron.service", map[string]any{
		"selector":       map[string]any{"host_ids": online},
		"canary_size":    0,
		"wave_size":      len(online),
		"max_concurrent": len(online),
	}))
	// Kampania czekajaca na zatwierdzenie jest kampania w toku: ktos musi
	// podjac decyzje, a metryka ma to pokazac.
	tekst = h.tekst("/metrics")
	if !strings.Contains(tekst, `flotestro_campaigns_active{action="unit.restart"`) {
		t.Errorf("metryki nie widza kampanii w toku:\n%s", wyciagnij(tekst, "flotestro_campaigns_active"))
	}
	if !strings.Contains(tekst, "flotestro_campaign_targets{") {
		t.Errorf("metryki nie widza hostow kampanii:\n%s",
			wyciagnij(tekst, "flotestro_campaign_targets"))
	}

	h.approveCampaign(campaign)
	h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)
}

// wyciagnij zwraca wiersze metryki o danej nazwie - do komunikatu bledu.
func wyciagnij(tekst, nazwa string) string {
	wiersze := []string{}
	for _, wiersz := range strings.Split(tekst, "\n") {
		if strings.Contains(wiersz, nazwa) {
			wiersze = append(wiersze, wiersz)
		}
	}
	return strings.Join(wiersze, "\n")
}

// TestKampaniaPlikowLiczyDiffNaKazdymHoscie pilnuje tego, co odroznia plik od
// operacji o przenosnej intencji.
//
// Ten sam stan docelowy znaczy na dwoch hostach co innego: jeden ma plik
// o innej tresci, drugi nie ma go wcale. Kampania musi zapytac kazdy host
// z osobna, zgoda ma dotyczyc zestawu tych odpowiedzi, a zapis ma wrocic na
// host z odciskiem tresci, ktora operator ogladal - inaczej zmiana zrobiona
// miedzy planem a zapisem znikneloby bez sladu.
func TestKampaniaPlikowLiczyDiffNaKazdymHoscie(t *testing.T) {
	h := newHarness(t)
	const sciezka = "/etc/flotestro-kampania-plikow.conf"
	cele := make([]string, 0, 2)
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			cele = append(cele, host.ID)
		}
	}
	if len(cele) < 2 {
		t.Skip("flota ma mniej niz dwa podlaczone hosty rodziny debian")
	}

	t.Cleanup(func() {
		for _, hostID := range cele {
			h.runOperation(hostID, map[string]any{
				"action": "file.remove", "reason": "sprzatanie po tescie planow plikowych",
				"payload": map[string]any{"file": map[string]any{"path": sciezka}},
			}, 2*time.Minute)
		}
	})

	// Pierwszy host dostaje plik z inna trescia; drugi zostaje bez niego. Od
	// tej chwili ten sam stan docelowy to dwie rozne zmiany.
	zadanie, proby := h.runOperation(cele[0], map[string]any{
		"action": "file.ensure", "reason": "przygotowanie testu planow plikowych",
		"payload": map[string]any{"file": map[string]any{
			"path": sciezka, "content": "stara tresc\n", "mode": "0644"}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("przygotowanie pliku: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	campaign := h.createCampaign(map[string]any{
		"name": "wspolny plik konfiguracyjny", "action": "file.ensure",
		"reason": "test integracyjny planow plikowych",
		"payload": map[string]any{"file": map[string]any{
			"path": sciezka, "content": "nowa tresc\n", "mode": "0644"}},
		"selector":                   map[string]any{"host_ids": cele},
		"canary_size":                0,
		"wave_size":                  len(cele),
		"max_concurrent":             len(cele),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("kampania plikowa zaczela od stanu %s", campaign.State)
	}
	odciskZamowienia := campaign.ApprovalFingerprint

	poPlanowaniu := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if poPlanowaniu.State != "awaiting_approval" {
		t.Fatalf("planowanie skonczylo sie stanem %s (%s)",
			poPlanowaniu.State, poPlanowaniu.PauseReason)
	}
	if poPlanowaniu.PlanSetHash == "" {
		t.Fatal("kampania plikowa po planowaniu bez odcisku zestawu planow")
	}
	if poPlanowaniu.ApprovalFingerprint == odciskZamowienia {
		t.Error("zestaw planow nie zmienil odcisku zatwierdzenia")
	}

	// Sedno: dwa hosty, dwa rozne plany. Jeden tworzy plik, drugi go zmienia.
	dzialania := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.PlanJobID == "" {
			t.Fatalf("cel %s bez zadania planujacego", target.Hostname)
		}
		dzialania[target.Hostname] = dzialaniePlanu(h, target.PlanJobID)
	}
	rodzaje := map[string]int{}
	for _, dzialanie := range dzialania {
		rodzaje[dzialanie]++
	}
	if rodzaje["create"] == 0 || rodzaje["update"] == 0 {
		t.Errorf("plany hostow nie roznia sie: %+v", dzialania)
	}

	h.approveCampaign(poPlanowaniu)
	koncowa := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)
	if koncowa.State != "completed" {
		t.Fatalf("kampania skonczyla sie stanem %s (%s)", koncowa.State, koncowa.PauseReason)
	}

	// Oba hosty doszly do tego samego stanu docelowego, choc szly do niego
	// z dwoch roznych miejsc. Plan liczony teraz nie ma juz nic do zrobienia.
	for _, hostID := range cele {
		zadanie, proby := h.runOperation(hostID, map[string]any{
			"action": "file.plan", "reason": "sprawdzenie stanu po kampanii",
			"payload": map[string]any{"file": map[string]any{
				"path": sciezka, "content": "nowa tresc\n", "mode": "0644"}},
		}, 2*time.Minute)
		if zadanie.State != "succeeded" {
			t.Fatalf("plan koncowy: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
		}
		if dzialanie := dzialaniePlanu(h, zadanie.ID); dzialanie != "no_change" {
			t.Errorf("po kampanii host %s ma jeszcze do zrobienia: %s", hostID[:8], dzialanie)
		}
		_ = proby
	}
}

// dzialaniePlanu czyta z wyniku zadania planujacego to, co plan ma zrobic.
func dzialaniePlanu(h *harness, jobID string) string {
	h.t.Helper()
	var odpowiedz struct {
		Items []struct {
			Detail struct {
				Kind string `json:"kind"`
				Plan struct {
					Action string `json:"action"`
				} `json:"plan"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &odpowiedz)
	for i := len(odpowiedz.Items) - 1; i >= 0; i-- {
		if odpowiedz.Items[i].Detail.Kind == "file_plan" {
			return odpowiedz.Items[i].Detail.Plan.Action
		}
	}
	return ""
}

// TestKampaniaZaporyLiczyDiffIOdmawiaPrzedZgoda pilnuje dwoch rzeczy naraz.
//
// Pierwsza: regula zapory zamowiona na dwoch hostach to dwie rozne zmiany -
// jeden host ja tworzy, drugi zmienia - i kazda wraca na host z odciskiem
// zestawu regul, ktory ten host mial przy planowaniu.
//
// Druga: regula, ktora odcielaby kanal zarzadzania, ma odpasc na etapie
// planu, zanim ktokolwiek cokolwiek zatwierdzi. Odmowa przy wykonaniu na
// polowie floty bylaby odpowiedzia spozniona.
func TestKampaniaZaporyLiczyDiffIOdmawiaPrzedZgoda(t *testing.T) {
	h := newHarness(t)
	const nazwa = "test-kampanii-zapory"
	cele := make([]string, 0, 2)
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			cele = append(cele, host.ID)
		}
	}
	if len(cele) < 2 {
		t.Skip("flota ma mniej niz dwa podlaczone hosty rodziny debian")
	}
	if !migawkaZaporyHosta(t, h, cele[0]).Writable {
		t.Skip("host nie pozwala zmieniac zapory")
	}

	t.Cleanup(func() {
		for _, hostID := range cele {
			h.runOperation(hostID, map[string]any{
				"action": "firewall.rule.remove", "reason": "sprzatanie po tescie kampanii zapory",
				"payload": map[string]any{"firewall": map[string]any{
					"rule_id": nazwa, "rollback_seconds": 60}},
			}, 2*time.Minute)
		}
	})

	// Pierwszy host dostaje regule na inny port; drugi zostaje bez niej.
	stan := migawkaZaporyHosta(t, h, cele[0])
	zadanie, proby := h.runOperation(cele[0], map[string]any{
		"action": "firewall.rule.ensure", "reason": "przygotowanie testu kampanii zapory",
		"payload": map[string]any{"firewall": map[string]any{
			"rule_id": nazwa, "chain": "wejscie", "action": "drop",
			"protocol": "tcp", "ports": []string{"2525"},
			"sources": []string{"10.10.0.0/16"}, "rollback_seconds": 60,
			"expected_hash": stan.Hash}},
	}, 3*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("przygotowanie reguly: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	regula := map[string]any{
		"rule_id": nazwa, "chain": "wejscie", "action": "drop",
		"protocol": "tcp", "ports": []string{"25"},
		"sources": []string{"10.10.0.0/16"}, "rollback_seconds": 60,
	}
	campaign := h.createCampaign(map[string]any{
		"name": "regula na calej flocie", "action": "firewall.rule.ensure",
		"reason":                     "test integracyjny planow zapory",
		"payload":                    map[string]any{"firewall": regula},
		"selector":                   map[string]any{"host_ids": cele},
		"canary_size":                0,
		"wave_size":                  len(cele),
		"max_concurrent":             len(cele),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("kampania zapory zaczela od stanu %s", campaign.State)
	}

	poPlanowaniu := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if poPlanowaniu.State != "awaiting_approval" {
		t.Fatalf("planowanie skonczylo sie stanem %s (%s)",
			poPlanowaniu.State, poPlanowaniu.PauseReason)
	}
	dzialania := map[string]int{}
	for _, target := range h.campaignTargets(campaign.ID) {
		dzialania[dzialaniePlanuZapory(h, target.PlanJobID)]++
	}
	if dzialania["create"] == 0 || dzialania["update"] == 0 {
		t.Errorf("plany hostow nie roznia sie: %+v", dzialania)
	}

	h.approveCampaign(poPlanowaniu)
	koncowa := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 4*time.Minute)
	if koncowa.State != "completed" {
		t.Fatalf("kampania skonczyla sie stanem %s (%s)", koncowa.State, koncowa.PauseReason)
	}
	for _, hostID := range cele {
		po := regulaPanelu(t, h, hostID, nazwa)
		if !strings.Contains(po.Text, "tcp dport 25") {
			t.Errorf("host %s po kampanii ma regule %q", hostID[:8], po.Text)
		}
	}

	// Regula odcinajaca panel: plan ma ja odrzucic na kazdym hoscie, a kampania
	// ma sie zatrzymac bez zgody, bo nie zostal zaden host do pracy.
	odcinajaca := h.createCampaign(map[string]any{
		"name": "regula odcinajaca", "action": "firewall.rule.ensure",
		"reason": "test odmowy planu zapory",
		"payload": map[string]any{"firewall": map[string]any{
			"rule_id": "test-odciecia-kampania", "chain": "wejscie", "action": "drop",
			"protocol": "tcp", "ports": []string{"8000-9000"}, "rollback_seconds": 60}},
		"selector":    map[string]any{"host_ids": cele},
		"canary_size": 0, "wave_size": len(cele), "max_concurrent": len(cele),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	stanOdmowy := h.awaitCampaign(odcinajaca.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if stanOdmowy.State == "awaiting_approval" {
		t.Fatal("kampania z regula odcinajaca panel doszla do zgody")
	}
	for _, target := range h.campaignTargets(odcinajaca.ID) {
		if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
			t.Errorf("cel %s po odmowie planu: %s/%s", target.Hostname, target.State, target.ErrorCode)
		}
	}
}

// dzialaniePlanuZapory czyta z wyniku zadania planujacego, co plan ma zrobic.
func dzialaniePlanuZapory(h *harness, jobID string) string {
	h.t.Helper()
	var odpowiedz struct {
		Items []struct {
			Detail struct {
				Kind string `json:"kind"`
				Plan struct {
					Action string `json:"action"`
				} `json:"plan"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &odpowiedz)
	for i := len(odpowiedz.Items) - 1; i >= 0; i-- {
		if odpowiedz.Items[i].Detail.Kind == "firewall_plan" {
			return odpowiedz.Items[i].Detail.Plan.Action
		}
	}
	return ""
}

// TestKampaniaMontowaniaRozwiazujeUUIDNaKazdymHoscie sprawdza, ze zamowienie
// "zamontuj /dev/sdb" nie jedzie na hosty jako sciezka: kazdy host rozwiazuje
// ja do UUID filesystemu, ktory naprawde ma, i ten UUID wraca w zmianie.
// Dwa hosty z ta sama sciezka maja dwa rozne filesystemy - i dwa rozne UUID.
func TestKampaniaMontowaniaRozwiazujeUUIDNaKazdymHoscie(t *testing.T) {
	h := newHarness(t)
	const cel = "/mnt/flotestro-kampania"

	// Hosty rodziny debian z wolnym filesystemem pod ta sama sciezka.
	zrodla := map[string]string{}
	var hosty []string
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" || host.OSFamily != "debian" {
			continue
		}
		stan := migawkaPrzestrzeniHosta(t, h, host.ID)
		for _, urzadzenie := range stan.Devices {
			if urzadzenie.FSType == "ext4" && urzadzenie.UUID != "" &&
				len(urzadzenie.Mountpoints) == 0 && !wFstab(stan, urzadzenie) {
				zrodla[host.ID] = urzadzenie.Path
				hosty = append(hosty, host.ID)
				break
			}
		}
	}
	if len(hosty) < 2 {
		t.Skip("flota ma mniej niz dwa hosty debian z wolnym filesystemem ext4")
	}
	hosty = hosty[:2]
	if zrodla[hosty[0]] != zrodla[hosty[1]] {
		t.Skipf("wolne filesystemy maja rozne sciezki: %s i %s",
			zrodla[hosty[0]], zrodla[hosty[1]])
	}
	sciezka := zrodla[hosty[0]]

	t.Cleanup(func() {
		for _, hostID := range hosty {
			h.runOperation(hostID, map[string]any{
				"action": "mount.remove", "reason": "sprzatanie po tescie kampanii montowania",
				"payload": map[string]any{"storage": map[string]any{"target": cel}},
			}, 2*time.Minute)
		}
	})

	campaign := h.createCampaign(map[string]any{
		"name": "dysk danych na flocie", "action": "mount.ensure",
		"reason": "test integracyjny planow montowania",
		"payload": map[string]any{"storage": map[string]any{
			"source": sciezka, "target": cel, "fs_type": "ext4",
			"options": "defaults,noatime", "persist": true}},
		"selector":                   map[string]any{"host_ids": hosty},
		"canary_size":                0,
		"wave_size":                  len(hosty),
		"max_concurrent":             len(hosty),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("kampania montowania zaczela od stanu %s", campaign.State)
	}
	poPlanowaniu := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if poPlanowaniu.State != "awaiting_approval" {
		t.Fatalf("planowanie skonczylo sie stanem %s (%s)",
			poPlanowaniu.State, poPlanowaniu.PauseReason)
	}

	rozwiazane := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := planMontowania(h, target.PlanJobID)
		if plan.Action != "create" {
			t.Errorf("host %s planuje %q zamiast create", target.Hostname, plan.Action)
		}
		if !strings.HasPrefix(plan.ResolvedSource, "UUID=") {
			t.Errorf("host %s nie rozwiazal zrodla do UUID: %q", target.Hostname, plan.ResolvedSource)
		}
		rozwiazane[target.Hostname] = plan.ResolvedSource
	}
	if len(rozwiazane) != 2 {
		t.Fatalf("plany dla %d hostow zamiast 2", len(rozwiazane))
	}
	var uuidy []string
	for _, uuid := range rozwiazane {
		uuidy = append(uuidy, uuid)
	}
	if uuidy[0] == uuidy[1] {
		t.Fatalf("dwa hosty rozwiazaly %s do tego samego UUID %s", sciezka, uuidy[0])
	}

	h.approveCampaign(poPlanowaniu)
	koncowa := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 4*time.Minute)
	if koncowa.State != "completed" {
		t.Fatalf("kampania skonczyla sie stanem %s (%s)", koncowa.State, koncowa.PauseReason)
	}

	// Zmiana, ktora weszla na host, ma niesc UUID tego hosta, a nie sciezke
	// z zamowienia - i host ma po niej montowanie zapisane w fstab.
	for _, target := range h.campaignTargets(campaign.ID) {
		var zadanie struct {
			Payload struct {
				Storage struct {
					Source string `json:"source"`
				} `json:"storage"`
			} `json:"payload"`
		}
		h.get("/api/v1/jobs/"+target.JobID, &zadanie)
		if zadanie.Payload.Storage.Source != rozwiazane[target.Hostname] {
			t.Errorf("host %s dostal zrodlo %q, plan mial %q",
				target.Hostname, zadanie.Payload.Storage.Source, rozwiazane[target.Hostname])
		}
		if !montowanieHosta(t, h, target.HostID, cel) {
			t.Errorf("host %s po kampanii nie ma %s zamontowanego i w fstab", target.Hostname, cel)
		}
	}
}

// montowanieHosta czeka, az inwentarz hosta pokaze cel zamontowany i w fstab.
// Fragment przestrzeni pochodzi z cyklu inwentarza, wiec po zmianie trzeba
// go odswiezyc, a zapis fragmentu jest asynchroniczny wzgledem zadania.
func montowanieHosta(t *testing.T, h *harness, hostID, cel string) bool {
	t.Helper()
	h.runOperation(hostID, map[string]any{
		"action": "inventory.refresh", "reason": "test kampanii montowania",
		"payload": map[string]any{"inventory": map[string]any{"modules": []string{"storage"}}},
	}, 2*time.Minute)
	deadline := time.Now().Add(60 * time.Second)
	for {
		for _, montowanie := range migawkaPrzestrzeniHosta(t, h, hostID).Mounts {
			if montowanie.Target == cel && montowanie.Mounted && montowanie.InFstab {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
}

// wFstab mowi, czy urzadzenie ma wpis w fstab pod jakimkolwiek celem.
func wFstab(stan migawkaPrzestrzeni, urzadzenie urzadzenieView) bool {
	for _, montowanie := range stan.Mounts {
		if !montowanie.InFstab {
			continue
		}
		if montowanie.Source == urzadzenie.Path ||
			montowanie.Source == "UUID="+urzadzenie.UUID {
			return true
		}
	}
	return false
}

// planMontowania czyta z wyniku zadania planujacego plan montowania.
func planMontowania(h *harness, jobID string) (plan struct {
	Action         string `json:"action"`
	ResolvedSource string `json:"resolved_source"`
	Refusal        string `json:"refusal"`
}) {
	h.t.Helper()
	var odpowiedz struct {
		Items []struct {
			Detail struct {
				Kind string          `json:"kind"`
				Plan json.RawMessage `json:"plan"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &odpowiedz)
	for i := len(odpowiedz.Items) - 1; i >= 0; i-- {
		if odpowiedz.Items[i].Detail.Kind == "mount_plan" {
			_ = json.Unmarshal(odpowiedz.Items[i].Detail.Plan, &plan)
			return plan
		}
	}
	return plan
}

// TestKampaniaSieciLiczyDiffIOdmawiaPrzedZgoda sprawdza, ze zmiana sieci
// w kampanii dostaje plan policzony na hoscie: roznice wobec profilu, ktory
// host ma, odcisk tej roznicy w zmianie i odmowe przed zgoda tam, gdzie
// zmiana nie ma na czym wejsc.
func TestKampaniaSieciLiczyDiffIOdmawiaPrzedZgoda(t *testing.T) {
	h := newHarness(t)

	// Hosty z mechanizmem zapisu i wskazanym interfejsem zarzadzania.
	interfejsy := map[string]string{}
	var cele []string
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		stan := migawkaSieciHosta(t, h, host.ID)
		if stan.WriteAdapter == "" || stan.ManagementInterface == "" {
			continue
		}
		interfejsy[host.ID] = stan.ManagementInterface
		cele = append(cele, host.ID)
	}
	if len(cele) == 0 {
		t.Skip("flota nie ma hosta z mechanizmem zapisu konfiguracji sieci")
	}
	// Zamowienie wskazuje jeden interfejs, a hosty nazywaja go roznie.
	// Kampania idzie na te, ktore maja go pod ta sama nazwa.
	liczebnosc := map[string]int{}
	for _, nazwa := range interfejsy {
		liczebnosc[nazwa]++
	}
	interfejs := ""
	for nazwa, ile := range liczebnosc {
		if ile > liczebnosc[interfejs] || (ile == liczebnosc[interfejs] && nazwa < interfejs) {
			interfejs = nazwa
		}
	}
	wybrane := cele[:0]
	for _, hostID := range cele {
		if interfejsy[hostID] == interfejs {
			wybrane = append(wybrane, hostID)
		}
	}
	cele = wybrane

	t.Cleanup(func() {
		for _, hostID := range cele {
			h.runOperation(hostID, map[string]any{
				"action": "network.mtu.set", "reason": "sprzatanie po tescie kampanii sieci",
				"payload": map[string]any{"network": map[string]any{
					"interface": interfejs, "mtu": "auto", "rollback_seconds": 60}},
			}, 3*time.Minute)
		}
	})

	campaign := h.createCampaign(map[string]any{
		"name": "MTU na flocie", "action": "network.mtu.set",
		"reason": "test integracyjny planow sieci",
		"payload": map[string]any{"network": map[string]any{
			"interface": interfejs, "mtu": "1400", "rollback_seconds": 60}},
		"selector":                   map[string]any{"host_ids": cele},
		"canary_size":                0,
		"wave_size":                  len(cele),
		"max_concurrent":             len(cele),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("kampania sieci zaczela od stanu %s", campaign.State)
	}
	poPlanowaniu := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if poPlanowaniu.State != "awaiting_approval" {
		t.Fatalf("planowanie skonczylo sie stanem %s (%s)",
			poPlanowaniu.State, poPlanowaniu.PauseReason)
	}
	odciski := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := planZRodzaju(h, target.PlanJobID, "network_plan")
		if plan.Action != "update" || len(plan.Changes) != 1 ||
			!strings.Contains(plan.Changes[0], "MTU") {
			t.Errorf("host %s planuje %q %v zamiast zmiany MTU", target.Hostname, plan.Action, plan.Changes)
		}
		if plan.PlanHash == "" {
			t.Errorf("host %s nie podal odcisku planu", target.Hostname)
		}
		odciski[target.Hostname] = plan.PlanHash
	}

	h.approveCampaign(poPlanowaniu)
	koncowa := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 5*time.Minute)
	if koncowa.State != "completed" {
		t.Fatalf("kampania skonczyla sie stanem %s (%s)", koncowa.State, koncowa.PauseReason)
	}
	// Zmiana, ktora weszla na host, niesie odcisk planu tego hosta: host
	// liczyl plan jeszcze raz przed zmiana i mial z czym porownac.
	for _, target := range h.campaignTargets(campaign.ID) {
		var zadanie struct {
			Payload struct {
				Network struct {
					PlanHash string `json:"plan_hash"`
				} `json:"network"`
			} `json:"payload"`
		}
		h.get("/api/v1/jobs/"+target.JobID, &zadanie)
		if zadanie.Payload.Network.PlanHash != odciski[target.Hostname] {
			t.Errorf("host %s dostal odcisk %q, plan mial %q",
				target.Hostname, zadanie.Payload.Network.PlanHash, odciski[target.Hostname])
		}
	}

	// Interfejs bez profilu: plan ma odmowic na kazdym hoscie, a kampania
	// zatrzymac sie bez zgody, bo nie zostal zaden host do pracy.
	bezProfilu := h.createCampaign(map[string]any{
		"name": "MTU na interfejsie, ktorego nie ma", "action": "network.mtu.set",
		"reason": "test odmowy planu sieci",
		"payload": map[string]any{"network": map[string]any{
			"interface": "flotestro9", "mtu": "1400", "rollback_seconds": 60}},
		"selector":    map[string]any{"host_ids": cele},
		"canary_size": 0, "wave_size": len(cele), "max_concurrent": len(cele),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	stanOdmowy := h.awaitCampaign(bezProfilu.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if stanOdmowy.State == "awaiting_approval" {
		t.Fatal("kampania na interfejsie bez profilu doszla do zgody")
	}
	for _, target := range h.campaignTargets(bezProfilu.ID) {
		if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
			t.Errorf("cel %s po odmowie planu: %s/%s", target.Hostname, target.State, target.ErrorCode)
		}
	}
}

// TestKampaniaStrefyFirewalldLiczyDiffIOdmawiaPrzedZgoda sprawdza, ze wpis
// w strefie firewalld w kampanii dostaje plan policzony na hoscie: czy port
// juz jest otwarty, w ktorej strefie i wobec jakiego zestawu regul - a strefa,
// ktorej host nie ma, jest odmowa przed zgoda.
func TestKampaniaStrefyFirewalldLiczyDiffIOdmawiaPrzedZgoda(t *testing.T) {
	h := newHarness(t)
	const port = "9445"

	strefy := map[string]string{}
	var cele []string
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		stan := migawkaZaporyHosta(t, h, host.ID)
		if stan.Adapter != "firewalld" {
			continue
		}
		for _, strefa := range stan.Zones {
			if strefa.Active {
				strefy[host.ID] = strefa.Name
				cele = append(cele, host.ID)
				break
			}
		}
	}
	if len(cele) == 0 {
		t.Skip("flota nie ma hosta z firewalld i aktywna strefa")
	}
	strefa := strefy[cele[0]]
	wybrane := cele[:0]
	for _, hostID := range cele {
		if strefy[hostID] == strefa {
			wybrane = append(wybrane, hostID)
		}
	}
	cele = wybrane

	t.Cleanup(func() {
		for _, hostID := range cele {
			h.runOperation(hostID, map[string]any{
				"action": "firewall.zone.port", "reason": "sprzatanie po tescie kampanii stref",
				"payload": map[string]any{"firewall": map[string]any{
					"zone": strefa, "ports": []string{port}, "protocol": "tcp", "enable": false}},
			}, 2*time.Minute)
		}
	})

	otwarcie := map[string]any{"firewall": map[string]any{
		"zone": strefa, "ports": []string{port}, "protocol": "tcp", "enable": true}}
	campaign := h.createCampaign(map[string]any{
		"name": "port w strefie na flocie", "action": "firewall.zone.port",
		"reason":                     "test integracyjny planow stref",
		"payload":                    otwarcie,
		"selector":                   map[string]any{"host_ids": cele},
		"canary_size":                0,
		"wave_size":                  len(cele),
		"max_concurrent":             len(cele),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	poPlanowaniu := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if poPlanowaniu.State != "awaiting_approval" {
		t.Fatalf("planowanie skonczylo sie stanem %s (%s)",
			poPlanowaniu.State, poPlanowaniu.PauseReason)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := planStrefy(h, target.PlanJobID)
		if plan.Action != "create" || plan.Present || plan.Entry != port+"/tcp" || plan.RulesetHash == "" {
			t.Errorf("host %s planuje %+v zamiast otwarcia portu", target.Hostname, plan)
		}
	}

	h.approveCampaign(poPlanowaniu)
	koncowa := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 4*time.Minute)
	if koncowa.State != "completed" {
		t.Fatalf("kampania skonczyla sie stanem %s (%s)", koncowa.State, koncowa.PauseReason)
	}

	// Ten sam wpis raz jeszcze: plan ma powiedziec, ze port juz jest otwarty.
	powtorka := h.createCampaign(map[string]any{
		"name": "port w strefie raz jeszcze", "action": "firewall.zone.port",
		"reason": "test planu bez zmian", "payload": otwarcie,
		"selector":    map[string]any{"host_ids": cele},
		"canary_size": 0, "wave_size": len(cele), "max_concurrent": len(cele),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	poPowtorce := h.awaitCampaign(powtorka.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if poPowtorce.State != "awaiting_approval" {
		t.Fatalf("powtorka: planowanie skonczylo sie stanem %s (%s)",
			poPowtorce.State, poPowtorce.PauseReason)
	}
	for _, target := range h.campaignTargets(powtorka.ID) {
		if plan := planStrefy(h, target.PlanJobID); plan.Action != "no_change" || !plan.Present {
			t.Errorf("host %s po otwarciu planuje %+v", target.Hostname, plan)
		}
	}
	h.do(http.MethodPost, "/api/v1/campaigns/"+powtorka.ID+"/cancel",
		map[string]any{"reason": "test planu bez zmian"}, nil, 0)

	// Strefa, ktorej host nie ma: odmowa w planie na kazdym hoscie.
	bezStrefy := h.createCampaign(map[string]any{
		"name": "port w strefie, ktorej nie ma", "action": "firewall.zone.port",
		"reason": "test odmowy planu strefy",
		"payload": map[string]any{"firewall": map[string]any{
			"zone": "flotestro-nie-ma", "ports": []string{port}, "protocol": "tcp", "enable": true}},
		"selector":    map[string]any{"host_ids": cele},
		"canary_size": 0, "wave_size": len(cele), "max_concurrent": len(cele),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	stanOdmowy := h.awaitCampaign(bezStrefy.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if stanOdmowy.State == "awaiting_approval" {
		t.Fatal("kampania na strefie, ktorej nie ma, doszla do zgody")
	}
	for _, target := range h.campaignTargets(bezStrefy.ID) {
		if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
			t.Errorf("cel %s po odmowie planu: %s/%s", target.Hostname, target.State, target.ErrorCode)
		}
	}
}

// planStrefy czyta z wyniku zadania planujacego plan strefy firewalld.
func planStrefy(h *harness, jobID string) (plan struct {
	Action      string `json:"action"`
	Entry       string `json:"entry"`
	Present     bool   `json:"present"`
	Refusal     string `json:"refusal"`
	RulesetHash string `json:"ruleset_hash"`
}) {
	h.t.Helper()
	var odpowiedz struct {
		Items []struct {
			Detail struct {
				Kind string          `json:"kind"`
				Plan json.RawMessage `json:"plan"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &odpowiedz)
	for i := len(odpowiedz.Items) - 1; i >= 0; i-- {
		if odpowiedz.Items[i].Detail.Kind == "firewall_plan" {
			_ = json.Unmarshal(odpowiedz.Items[i].Detail.Plan, &plan)
			return plan
		}
	}
	return plan
}

// TestKampaniaResolveraLiczyDiffIOdmawiaPrzedZgoda sprawdza, ze zmiana
// resolvera w kampanii dostaje plan policzony na hoscie wobec profilu,
// ktory host ma, i wraca z jego odciskiem - a interfejs bez profilu jest
// odmowa przed zgoda.
func TestKampaniaResolveraLiczyDiffIOdmawiaPrzedZgoda(t *testing.T) {
	h := newHarness(t)
	const serwer = "192.168.56.50"

	interfejsy := map[string]string{}
	var cele []string
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		stan := migawkaSieciHosta(t, h, host.ID)
		if stan.WriteAdapter == "" || stan.ManagementInterface == "" {
			continue
		}
		interfejsy[host.ID] = stan.ManagementInterface
		cele = append(cele, host.ID)
	}
	if len(cele) == 0 {
		t.Skip("flota nie ma hosta z mechanizmem zapisu konfiguracji sieci")
	}
	interfejs := interfejsy[cele[0]]
	wybrane := cele[:0]
	for _, hostID := range cele {
		if interfejsy[hostID] == interfejs {
			wybrane = append(wybrane, hostID)
		}
	}
	cele = wybrane

	// Sprzatanie zostawia serwer bez domen wyszukiwania: resolver bez
	// serwera jest odmowa, wiec pustego profilu nie da sie tu przywrocic.
	t.Cleanup(func() {
		for _, hostID := range cele {
			h.runOperation(hostID, map[string]any{
				"action": "dns.host.apply", "reason": "sprzatanie po tescie kampanii resolvera",
				"payload": map[string]any{"dns": map[string]any{
					"interface": interfejs, "servers": []string{serwer}, "rollback_seconds": 60}},
			}, 3*time.Minute)
		}
	})

	campaign := h.createCampaign(map[string]any{
		"name": "resolver na flocie", "action": "dns.host.apply",
		"reason": "test integracyjny planow resolvera",
		"payload": map[string]any{"dns": map[string]any{
			"interface": interfejs, "servers": []string{serwer},
			"search_domains": []string{"flotestro.test"}, "rollback_seconds": 60}},
		"selector":                   map[string]any{"host_ids": cele},
		"canary_size":                0,
		"wave_size":                  len(cele),
		"max_concurrent":             len(cele),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	poPlanowaniu := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if poPlanowaniu.State != "awaiting_approval" {
		t.Fatalf("planowanie skonczylo sie stanem %s (%s)",
			poPlanowaniu.State, poPlanowaniu.PauseReason)
	}
	odciski := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := planZRodzaju(h, target.PlanJobID, "dns_plan")
		if plan.Action != "update" || plan.PlanHash == "" {
			t.Errorf("host %s planuje %+v zamiast zmiany resolvera", target.Hostname, plan)
		}
		var oDomenach bool
		for _, zmiana := range plan.Changes {
			oDomenach = oDomenach || strings.Contains(zmiana, "domeny wyszukiwania")
		}
		if !oDomenach {
			t.Errorf("host %s nie widzi zmiany domen wyszukiwania: %v", target.Hostname, plan.Changes)
		}
		odciski[target.Hostname] = plan.PlanHash
	}

	h.approveCampaign(poPlanowaniu)
	koncowa := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 5*time.Minute)
	if koncowa.State != "completed" {
		t.Fatalf("kampania skonczyla sie stanem %s (%s)", koncowa.State, koncowa.PauseReason)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		var zadanie struct {
			Payload struct {
				DNS struct {
					PlanHash string `json:"plan_hash"`
				} `json:"dns"`
			} `json:"payload"`
		}
		h.get("/api/v1/jobs/"+target.JobID, &zadanie)
		if zadanie.Payload.DNS.PlanHash != odciski[target.Hostname] {
			t.Errorf("host %s dostal odcisk %q, plan mial %q",
				target.Hostname, zadanie.Payload.DNS.PlanHash, odciski[target.Hostname])
		}
	}

	bezProfilu := h.createCampaign(map[string]any{
		"name": "resolver na interfejsie, ktorego nie ma", "action": "dns.host.apply",
		"reason": "test odmowy planu resolvera",
		"payload": map[string]any{"dns": map[string]any{
			"interface": "flotestro9", "servers": []string{serwer}, "rollback_seconds": 60}},
		"selector":    map[string]any{"host_ids": cele},
		"canary_size": 0, "wave_size": len(cele), "max_concurrent": len(cele),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	stanOdmowy := h.awaitCampaign(bezProfilu.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if stanOdmowy.State == "awaiting_approval" {
		t.Fatal("kampania na interfejsie bez profilu doszla do zgody")
	}
	for _, target := range h.campaignTargets(bezProfilu.ID) {
		if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
			t.Errorf("cel %s po odmowie planu: %s/%s", target.Hostname, target.State, target.ErrorCode)
		}
	}
}

// planZRodzaju czyta z wyniku zadania planujacego plan o danym rodzaju.
func planZRodzaju(h *harness, jobID, rodzaj string) (plan struct {
	Action   string   `json:"action"`
	Changes  []string `json:"changes"`
	Refusal  string   `json:"refusal"`
	PlanHash string   `json:"plan_hash"`
}) {
	h.t.Helper()
	var odpowiedz struct {
		Items []struct {
			Detail struct {
				Kind string          `json:"kind"`
				Plan json.RawMessage `json:"plan"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &odpowiedz)
	for i := len(odpowiedz.Items) - 1; i >= 0; i-- {
		if odpowiedz.Items[i].Detail.Kind == rodzaj {
			_ = json.Unmarshal(odpowiedz.Items[i].Detail.Plan, &plan)
			return plan
		}
	}
	return plan
}
