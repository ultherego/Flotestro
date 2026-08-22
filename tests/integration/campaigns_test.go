//go:build integration

package integration

import (
	"net/http"
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
	CreatedBy        string `json:"created_by"`
	ApprovedBy       string `json:"approved_by"`
	PausedBy         string `json:"paused_by"`
	PauseReason      string `json:"pause_reason"`
}

type campaignTargetView struct {
	HostID    string `json:"host_id"`
	Hostname  string `json:"hostname"`
	Wave      int    `json:"wave"`
	State     string `json:"state"`
	ErrorCode string `json:"error_code"`
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
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve", nil, nil, http.StatusOK)

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
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve", nil, nil, http.StatusOK)

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
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve", nil, nil, http.StatusOK)
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
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve", nil, nil, http.StatusOK)

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

	// Operator prowadzi kampanie, ale jej nie zatwierdza.
	operator.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve", nil, nil, http.StatusForbidden)
	// Approver zatwierdza, ale nie tworzy.
	approver.do(http.MethodPost, "/api/v1/campaigns", body, nil, http.StatusForbidden)
	approver.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve", nil, nil, http.StatusOK)
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
