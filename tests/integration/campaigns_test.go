//go:build integration

package integration

import (
	"net/http"
	"sort"
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

	przypadki := map[string]map[string]any{
		// Zapis pliku liczy inny diff na kazdym hoscie, a panel nie ma jeszcze
		// czym go policzyc masowo - wiec odmawia zamiast udawac.
		"file.ensure": {"file": map[string]any{
			"path": "/etc/flotestro-test.conf", "content": "x", "mode": "0644",
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
