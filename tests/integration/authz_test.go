//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// uniqueSubject daje nazwe unikalna dla przebiegu, zeby testy nie zderzaly sie
// z tozsamosciami z poprzednich uruchomien.
func uniqueSubject(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// TestBrakTokenuBlokujeDostep sprawdza, ze API nie jest otwarte.
func TestBrakTokenuBlokujeDostep(t *testing.T) {
	h := newHarness(t)
	anonymous := h.withToken("")

	for _, path := range []string{
		"/api/v1/hosts", "/api/v1/jobs", "/api/v1/audit",
		"/api/v1/actions", "/api/v1/enrollment-tokens",
	} {
		anonymous.do(http.MethodGet, path, nil, nil, http.StatusUnauthorized)
	}
}

// TestNieprawidlowyTokenJestOdrzucany sprawdza, ze zmyslony token nie dziala.
func TestNieprawidlowyTokenJestOdrzucany(t *testing.T) {
	h := newHarness(t)
	h.withToken("flta_nieistniejacy-token").
		do(http.MethodGet, "/api/v1/hosts", nil, nil, http.StatusUnauthorized)
}

// TestOperatorNieZatwierdzaWlasnychZmian jest testem rozdzialu obowiazkow.
func TestOperatorNieZatwierdzaWlasnychZmian(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	operatorToken := h.createPrincipal(uniqueSubject("operator"), []map[string]string{
		{"role": "operator", "site": host.Site, "environment": host.Environment},
	})
	operator := h.withToken(operatorToken)

	job := operator.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	t.Cleanup(func() {
		operator.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
			map[string]any{"reason": "koniec testu"}, nil, http.StatusOK)
	})

	// Operator moze zlecic zmiane, ale nie ma uprawnienia do zatwierdzania.
	operator.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/approve",
		map[string]any{"payload_hash": job.PayloadHash}, nil, http.StatusForbidden)

	if state := h.job(job.ID).State; state != "awaiting_approval" {
		t.Fatalf("odrzucone zatwierdzenie zmienilo stan na %s", state)
	}
}

// TestApproverNieZlecaZmian sprawdza druga strone rozdzialu obowiazkow.
func TestApproverNieZlecaZmian(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	approverToken := h.createPrincipal(uniqueSubject("approver"), []map[string]string{
		{"role": "approver", "site": host.Site, "environment": host.Environment},
	})

	h.withToken(approverToken).do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "unit.restart", "payload": unitPayload("cron.service")},
		nil, http.StatusForbidden)
}

// TestOperatorIApproverRazemWykonujaZmiane sprawdza pelna sciezke z podzialem
// rol: jeden zleca, drugi zatwierdza.
func TestOperatorIApproverRazemWykonujaZmiane(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	scope := []map[string]string{
		{"role": "operator", "site": host.Site, "environment": host.Environment},
	}
	operator := h.withToken(h.createPrincipal(uniqueSubject("operator"), scope))
	approver := h.withToken(h.createPrincipal(uniqueSubject("approver"), []map[string]string{
		{"role": "approver", "site": host.Site, "environment": host.Environment},
	}))

	job := operator.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	approver.approve(job.ID, job.PayloadHash)

	final := h.awaitTerminal(job.ID, 90*time.Second)
	if final.State != "succeeded" {
		t.Fatalf("stan = %s, kod bledu = %s", final.State, final.ResultErrorCode)
	}
	if final.ApprovedBy == final.CreatedBy {
		t.Error("zlecajacy i zatwierdzajacy to ta sama tozsamosc")
	}
}

// TestZakresOgraniczaWidocznoscFloty sprawdza, ze operator jednego srodowiska
// nie widzi hostow spoza swojego zakresu.
func TestZakresOgraniczaWidocznoscFloty(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	obcy := h.withToken(h.createPrincipal(uniqueSubject("obcy-zakres"), []map[string]string{
		{"role": "operator", "site": "inna-lokalizacja", "environment": "inne-srodowisko"},
	}))

	var listing struct {
		Items []hostView `json:"items"`
		Count int        `json:"count"`
	}
	obcy.get("/api/v1/hosts", &listing)
	if listing.Count != 0 {
		t.Errorf("tozsamosc spoza zakresu widzi %d hostow", listing.Count)
	}

	// Bezposredni dostep do hosta tez musi byc odmowiony.
	obcy.do(http.MethodGet, "/api/v1/hosts/"+host.ID, nil, nil, http.StatusForbidden)
	obcy.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "unit.restart", "payload": unitPayload("cron.service")},
		nil, http.StatusForbidden)
}

// TestViewerNiczegoNieZmienia sprawdza, ze rola odczytu jest naprawde tylko
// do odczytu.
func TestViewerNiczegoNieZmienia(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	viewer := h.withToken(h.createPrincipal(uniqueSubject("viewer"), []map[string]string{
		{"role": "viewer", "site": host.Site, "environment": host.Environment},
	}))

	// Odczyt dziala.
	viewer.do(http.MethodGet, "/api/v1/hosts/"+host.ID, nil, nil, http.StatusOK)

	// Zmiany i audyt nie.
	viewer.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "journal.read",
			"payload": map[string]any{"journal": map[string]any{"lines": 5}}},
		nil, http.StatusForbidden)
	viewer.do(http.MethodGet, "/api/v1/audit", nil, nil, http.StatusForbidden)
	viewer.do(http.MethodPost, "/api/v1/enrollment-tokens",
		map[string]any{"description": "proba"}, nil, http.StatusForbidden)
	viewer.do(http.MethodGet, "/api/v1/principals", nil, nil, http.StatusForbidden)
}

// TestUprawnienieJestPerOperacja sprawdza, ze prawo do jednej operacji nie
// daje prawa do innej. Rola bez uprawnien do jednostek moze czytac dziennik.
func TestUprawnienieJestPerOperacja(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Auditor ma prawo odczytu, ale nie ma job.create, wiec nie zleci nawet
	// operacji niemutujacej.
	auditor := h.withToken(h.createPrincipal(uniqueSubject("auditor"), []map[string]string{
		{"role": "auditor", "site": host.Site, "environment": host.Environment},
	}))

	// Audyt hosta w swoim zakresie czyta.
	auditor.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/audit", nil, nil, http.StatusOK)

	// Ale globalny dziennik obejmuje cala flote, wiec wymaga uprawnienia
	// w zakresie globalnym, ktorego auditor jednego srodowiska nie ma.
	auditor.do(http.MethodGet, "/api/v1/audit", nil, nil, http.StatusForbidden)

	auditor.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "journal.read",
			"payload": map[string]any{"journal": map[string]any{"lines": 5}}},
		nil, http.StatusForbidden)
}

// TestAudytorGlobalnyCzytaCalyDziennik potwierdza, ze uprawnienie globalne
// daje dostep do dziennika calej floty.
func TestAudytorGlobalnyCzytaCalyDziennik(t *testing.T) {
	h := newHarness(t)
	auditor := h.withToken(h.createPrincipal(uniqueSubject("auditor-globalny"), []map[string]string{
		{"role": "auditor", "site": "*", "environment": "*"},
	}))
	auditor.do(http.MethodGet, "/api/v1/audit", nil, nil, http.StatusOK)
}

// TestProdukcjaWymagaDrugiejOsoby sprawdza zasade czterech oczu. Host jest na
// czas testu przenoszony do srodowiska produkcyjnego.
func TestProdukcjaWymagaDrugiejOsoby(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")

	if _, err := pool.Exec(ctx,
		`update hosts set environment = 'prod' where id = $1`, host.ID); err != nil {
		t.Fatalf("nie przeniesiono hosta do produkcji: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`update hosts set environment = $2 where id = $1`, host.ID, host.Environment)
	})

	// Tozsamosc z obiema rolami: sam rozdzial rol nie wystarcza, bo jedna
	// osoba moze miec obie.
	obie := h.withToken(h.createPrincipal(uniqueSubject("operator-approver"), []map[string]string{
		{"role": "operator", "site": host.Site, "environment": "prod"},
		{"role": "approver", "site": host.Site, "environment": "prod"},
	}))

	job := obie.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
			map[string]any{"reason": "koniec testu"}, nil, http.StatusOK)
	})

	// Ma uprawnienie do zatwierdzania, ale nie wlasnej zmiany.
	obie.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/approve",
		map[string]any{"payload_hash": job.PayloadHash}, nil, http.StatusForbidden)

	if state := h.job(job.ID).State; state != "awaiting_approval" {
		t.Fatalf("samozatwierdzenie zmienilo stan na %s", state)
	}
}

// TestOdmowaZostawiaSladAudytowy sprawdza, ze proba bez uprawnien jest
// odnotowana. Audyt pokazujacy tylko sukcesy jest bezuzyteczny przy incydencie.
func TestOdmowaZostawiaSladAudytowy(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	subject := uniqueSubject("viewer-audyt")

	viewer := h.withToken(h.createPrincipal(subject, []map[string]string{
		{"role": "viewer", "site": host.Site, "environment": host.Environment},
	}))
	viewer.do(http.MethodGet, "/api/v1/audit", nil, nil, http.StatusForbidden)

	var events struct {
		Items []struct {
			ActorID string `json:"actor_id"`
			Action  string `json:"action"`
			Outcome string `json:"outcome"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?limit=100", &events)

	found := false
	for _, event := range events.Items {
		if event.ActorID == subject && event.Outcome == "denied" {
			found = true
		}
	}
	if !found {
		t.Fatalf("brak zdarzenia audytowego o odmowie dla %s", subject)
	}
}
