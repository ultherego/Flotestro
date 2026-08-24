package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// MaksymalneOkno ogranicza dlugosc okna serwisowego.
//
// Okno bez konca konczy sie hostem, o ktorym wszyscy zapomnieli: kampanie go
// omijaja, alerty z niego nie budza nikogo, i po pol roku nikt nie pamieta,
// dlaczego ta maszyna nie dostaje poprawek. Termin wymusza decyzje.
const MaksymalneOkno = 30 * 24 * time.Hour

type oknoSerwisoweRequest struct {
	// Until albo DurationMinutes: interfejs wysyla jedno z nich.
	Until           string `json:"until,omitempty"`
	DurationMinutes int    `json:"duration_minutes,omitempty"`
	Reason          string `json:"reason,omitempty"`
	// Clear zamyka okno przed czasem.
	Clear bool `json:"clear,omitempty"`
}

// handleSetMaintenance otwiera albo zamyka okno serwisowe hosta.
//
// To nie jest operacja na hoscie i nie idzie przez kolejke zadan: zmienia
// wylacznie to, co panel o hoscie sadzi. Zadanie jest czyms, co host wykonuje,
// a host nie ma tu nic do zrobienia - dlatego wlasny punkt wejscia, wlasne
// uprawnienie i wlasny slad audytowy.
func (s *Server) handleSetMaintenance(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostMaintenanceWrite, scope, "host", hostID)
	if !ok {
		return
	}

	var request oknoSerwisoweRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}

	var doKiedy *time.Time
	powod := strings.TrimSpace(request.Reason)
	if !request.Clear {
		termin, err := terminOkna(request)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_window", err.Error())
			return
		}
		if powod == "" {
			problem(w, http.StatusBadRequest, "reason_required",
				"a maintenance window needs a reason; it is what the next person on call will read")
			return
		}
		doKiedy = &termin
	}

	zaktualizowany, err := s.hosts.UstawOknoSerwisowe(r.Context(), hostID, doKiedy, powod, principal.Subject)
	if err != nil {
		s.fail(w, err)
		return
	}

	szczegoly := map[string]any{"cleared": request.Clear, "reason": powod}
	if doKiedy != nil {
		szczegoly["until"] = doKiedy.Format(time.RFC3339)
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.maintenance", TargetType: "host", TargetID: host.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess, Detail: szczegoly,
	})
	writeJSON(w, http.StatusOK, zaktualizowany)
}

// terminOkna wylicza koniec okna z tego, co przyslal interfejs.
func terminOkna(request oknoSerwisoweRequest) (time.Time, error) {
	teraz := time.Now().UTC()
	termin := time.Time{}
	switch {
	case request.Until != "":
		parsowany, err := time.Parse(time.RFC3339, request.Until)
		if err != nil {
			return time.Time{}, errWindow("until must be an RFC 3339 timestamp")
		}
		termin = parsowany.UTC()
	case request.DurationMinutes > 0:
		termin = teraz.Add(time.Duration(request.DurationMinutes) * time.Minute)
	default:
		return time.Time{}, errWindow("a maintenance window needs an end: pass until or duration_minutes")
	}
	if !termin.After(teraz) {
		return time.Time{}, errWindow("the window ends in the past")
	}
	if termin.Sub(teraz) > MaksymalneOkno {
		return time.Time{}, errWindow("a maintenance window lasts at most 30 days")
	}
	return termin, nil
}

type bladOkna string

func (b bladOkna) Error() string { return string(b) }

func errWindow(komunikat string) error { return bladOkna(komunikat) }
