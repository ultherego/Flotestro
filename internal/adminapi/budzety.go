package adminapi

import (
	"encoding/json"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// handleListBudgets pokazuje pojemnosc floty i to, ile z niej zajete.
//
// Bez tego ekranu host stojacy na budzecie wyglada jak host zapomniany:
// kampania nie posuwa sie do przodu, a nic nie mowi dlaczego. Liczba chetnych
// jest tu rownie wazna jak zajetosc - to ona tlumaczy, czemu wolne tokeny nie
// trafiaja do jednej kampanii.
func (s *Server) handleListBudgets(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermBudgetRead, "budget"); !ok {
		return
	}
	if s.budzety == nil {
		problem(w, http.StatusNotImplemented, "budgets_disabled",
			"budgets are disabled in this installation")
		return
	}
	stany, err := s.budzety.Stany(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": stany})
}

// handleSetBudget zmienia pojemnosc jednego budzetu.
//
// Pojemnosc jest polityka instalacji, a nie stala w kodzie: lokalizacja
// z jednym laczem uniesie co innego niz serwerownia. Zmiana jest osobnym
// uprawnieniem i trafia do audytu, bo podniesiona po cichu odbiera znaczenie
// kazdemu limitowi ponizej.
func (s *Server) handleSetBudget(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermBudgetWrite, "budget")
	if !ok {
		return
	}
	if s.budzety == nil {
		problem(w, http.StatusNotImplemented, "budgets_disabled",
			"budgets are disabled in this installation")
		return
	}
	klucz := r.PathValue("key")
	if klucz == "" {
		problem(w, http.StatusBadRequest, "invalid_request", "budget key is required")
		return
	}

	var request struct {
		Capacity int    `json:"capacity"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// Pojemnosc zerowa nie jest polityka, tylko zatrzymaniem wszystkiego bez
	// powiedzenia tego wprost. Budzet, ktory ma nic nie przepuszczac, jest
	// wstrzymaniem kampanii - i tak sie nazywa.
	if request.Capacity < 1 {
		problem(w, http.StatusBadRequest, "invalid_request",
			"capacity must be at least 1; to stop work, pause the campaign")
		return
	}

	if err := s.budzety.UstawPojemnosc(r.Context(), klucz, request.Capacity, request.Note); err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: string(authz.PermBudgetWrite), TargetType: "budget", TargetID: klucz,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"capacity": request.Capacity, "note": request.Note},
	})
	writeJSON(w, http.StatusOK, map[string]any{"key": klucz, "capacity": request.Capacity})
}
