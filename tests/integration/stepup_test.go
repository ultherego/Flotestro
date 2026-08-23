//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// TestZmianaRegulDostepuWymagaPowodu sprawdza warunek operacji o najwiekszym
// wplywie. Mapowanie grupy na role decyduje, kogo dostawca tozsamosci wpuszcza
// i z jakimi uprawnieniami, wiec nie moze zostac wykonane bez uzasadnienia
// zapisanego w audycie.
func TestZmianaRegulDostepuWymagaPowodu(t *testing.T) {
	h := newHarness(t)
	grupa := uniqueSubject("flotestro-test-grupa")

	for nazwa, powod := range map[string]string{
		"brak powodu":     "",
		"powod za krotki": "bo tak",
	} {
		t.Run(nazwa, func(t *testing.T) {
			var problem struct {
				Code string `json:"code"`
			}
			h.do(http.MethodPost, "/api/v1/group-mappings", map[string]any{
				"group_name": grupa, "role": "viewer", "reason": powod,
				// Brak powodu jest brakiem w zadaniu, a nie w sesji: ponowne
				// uwierzytelnienie by go nie naprawilo.
			}, &problem, http.StatusBadRequest)
			if problem.Code != "reason_required" {
				t.Errorf("kod = %q, oczekiwano reason_required", problem.Code)
			}
		})
	}

	var mapping struct {
		ID string `json:"id"`
	}
	powod := "nadanie roli viewer zespolowi testowemu"
	h.do(http.MethodPost, "/api/v1/group-mappings", map[string]any{
		"group_name": grupa, "role": "viewer", "reason": powod,
	}, &mapping, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/group-mappings/"+mapping.ID+"?reason=sprzatanie+po+tescie+integracyjnym",
			nil, nil, http.StatusNoContent)
	})

	// Usuniecie jest ta sama zmiana reguly dostepu, wiec warunek jest ten sam.
	var problem struct {
		Code string `json:"code"`
	}
	h.do(http.MethodDelete, "/api/v1/group-mappings/"+mapping.ID, nil, &problem, http.StatusBadRequest)
	if problem.Code != "reason_required" {
		t.Errorf("usuniecie bez powodu: kod = %q", problem.Code)
	}

	// Slad audytowy musi niesc powod i to, na jakiej podstawie operacja
	// przeszla. Tozsamosc automatyczna nie moze byc opisana jako uwierzytelniona
	// ponownie, bo nie ma za nia czlowieka.
	var audyt struct {
		Items []struct {
			Action  string         `json:"action"`
			Outcome string         `json:"outcome"`
			Detail  map[string]any `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?limit=50", &audyt)

	znaleziony := false
	for _, zdarzenie := range audyt.Items {
		if zdarzenie.Action != "group_mapping.create" || zdarzenie.Outcome != "success" {
			continue
		}
		if zdarzenie.Detail["group"] != grupa {
			continue
		}
		znaleziony = true
		if zdarzenie.Detail["purpose"] != powod {
			t.Errorf("audyt nie niesie powodu: %+v", zdarzenie.Detail)
		}
		if zdarzenie.Detail["authentication"] != "api_token" {
			t.Errorf("audyt nie odroznia tokenu od sesji: %+v", zdarzenie.Detail)
		}
		if zdarzenie.Detail["reauthenticated"] != false {
			t.Errorf("audyt przypisuje tokenowi ponowne uwierzytelnienie: %+v", zdarzenie.Detail)
		}
		if _, obecny := zdarzenie.Detail["acr"]; obecny {
			t.Errorf("audyt przypisuje tokenowi poziom uwierzytelnienia: %+v", zdarzenie.Detail)
		}
	}
	if !znaleziony {
		t.Fatalf("brak wpisu audytu o utworzeniu mapowania grupy %s", grupa)
	}

	// Odmowa tez zostawia slad: proba zmiany reguly dostepu jest zdarzeniem
	// wartym odnotowania niezaleznie od wyniku.
	odmowy := 0
	for _, zdarzenie := range audyt.Items {
		if zdarzenie.Action == "group_mapping.create" && zdarzenie.Outcome == "denied" {
			odmowy++
		}
	}
	if odmowy == 0 {
		t.Error("odmowy z braku powodu nie trafily do audytu")
	}
}
