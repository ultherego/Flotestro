//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// sesjaWidok opisuje wpis sesji agenta w bazie.
type sesjaWidok struct {
	ID        string
	Epoka     int64
	Zamknieta bool
	Powod     string
}

// TestNowaSesjaZastepujeStara pilnuje wlasciwosci, dla ktorej epoka sesji
// w ogole istnieje: host ma w danej chwili dokladnie jedna wlasciwa sesje.
//
// Bez tego dwie bramy uwazalyby sie za wlasciwe dla tego samego hosta i to
// samo zadanie pojechaloby dwa razy - a operacje nieodwracalne wykonalyby sie
// podwojnie. Test wymusza ponowne polaczenie kwarantanna, bo to jedyna droga
// zerwania sesji przez API.
func TestNowaSesjaZastepujeStara(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	ctx := context.Background()
	h.database(ctx)

	przed := h.sesjeHosta(t, host.ID)
	if len(przed) == 0 {
		t.Fatal("host nie ma zadnej sesji")
	}
	otwarte := 0
	for _, sesja := range przed {
		if !sesja.Zamknieta {
			otwarte++
		}
	}
	if otwarte != 1 {
		t.Fatalf("host ma %d otwartych sesji; wlasciwa jest dokladnie jedna", otwarte)
	}
	najwyzsza := przed[0].Epoka

	// Sprzatanie zdejmuje kwarantanne tylko wtedy, gdy test nie zdazyl jej
	// zdjac sam: zwolnienie hosta, ktory jest juz aktywny, jest konfliktem
	// stanu i przykryloby prawdziwy powod niepowodzenia.
	t.Cleanup(func() {
		var stan struct {
			LifecycleState string `json:"lifecycle_state"`
		}
		h.get("/api/v1/hosts/"+host.ID, &stan)
		if stan.LifecycleState == "quarantined" {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
				map[string]any{"reason": "koniec testu"}, nil, http.StatusOK)
		}
		h.poczekajNaPolaczenie(host.ID, 2*time.Minute)
	})
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine",
		map[string]any{"reason": "test epoki sesji"}, nil, http.StatusOK)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
		map[string]any{"reason": "test epoki sesji"}, nil, http.StatusOK)
	h.poczekajNaPolaczenie(host.ID, 2*time.Minute)

	po := h.sesjeHosta(t, host.ID)
	if po[0].Epoka <= najwyzsza {
		t.Fatalf("epoka po ponownym polaczeniu = %d, przed = %d", po[0].Epoka, najwyzsza)
	}
	if po[0].Zamknieta {
		t.Fatal("najnowsza sesja jest zamknieta")
	}
	for _, sesja := range po[1:] {
		if !sesja.Zamknieta {
			t.Fatalf("starsza sesja %s (epoka %d) zostala otwarta", sesja.ID, sesja.Epoka)
		}
	}
}

// sesjeHosta zwraca sesje hosta od najnowszej epoki.
func (h *harness) sesjeHosta(t *testing.T, hostID string) []sesjaWidok {
	t.Helper()
	ctx := context.Background()
	wiersze, err := h.database(ctx).Query(ctx, `
		select id::text, epoch, ended_at is not null, coalesce(end_reason, '')
		from agent_sessions where host_id = $1::uuid
		order by epoch desc limit 20`, hostID)
	if err != nil {
		t.Fatal(err)
	}
	defer wiersze.Close()

	var sesje []sesjaWidok
	for wiersze.Next() {
		var sesja sesjaWidok
		if err := wiersze.Scan(&sesja.ID, &sesja.Epoka, &sesja.Zamknieta, &sesja.Powod); err != nil {
			t.Fatal(err)
		}
		sesje = append(sesje, sesja)
	}
	if err := wiersze.Err(); err != nil {
		t.Fatal(err)
	}
	return sesje
}
