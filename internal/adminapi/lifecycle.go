package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// zmianaCykluZycia jest trescia zadania zmiany stanu hosta.
type zmianaCykluZycia struct {
	// Reason jest wymagany zawsze. Host odciety bez powodu jest hostem,
	// o ktorym za tydzien nikt nie bedzie wiedzial, czemu nie pracuje.
	Reason string `json:"reason"`
	// RevokeCertificates stosuje sie przy podejrzeniu wycieku klucza. Bez
	// tego certyfikat zostaje kryptograficznie wazny i jest blokowany samym
	// stanem w bazie - to wystarcza, dopoki klucz jest u wlasciciela.
	RevokeCertificates bool `json:"revoke_certificates"`
	// TypedConfirmation jest jawnym przepisaniem nazwy hosta przy wycofaniu.
	TypedConfirmation string `json:"typed_confirmation"`
}

// handleQuarantineHost odcina host od floty natychmiast.
func (s *Server) handleQuarantineHost(w http.ResponseWriter, r *http.Request) {
	s.zmienCyklZycia(w, r, cyklZycia{
		Permission: authz.PermHostQuarantine,
		ZStanow:    []string{hosts.StateActive, hosts.StateQuarantined},
		Nowy:       hosts.StateQuarantined,
		Akcja:      "host.quarantine",
		// Zadania juz wyslane zostaja: agent moze byc w polowie operacji,
		// ktorej nie da sie przerwac, a panel nie ma jak jej cofnac.
		AnulujZadania: true,
		ZamknijSesje:  true,
	})
}

// handleReleaseHost przywraca host po ocenie incydentu.
func (s *Server) handleReleaseHost(w http.ResponseWriter, r *http.Request) {
	s.zmienCyklZycia(w, r, cyklZycia{
		Permission: authz.PermHostQuarantineRelease,
		ZStanow:    []string{hosts.StateQuarantined},
		Nowy:       hosts.StateActive,
		Akcja:      "host.quarantine.release",
	})
}

// handleDecommissionHost konczy zaufanie do hosta po stronie panelu.
//
// Rekord hosta, inwentarz i audyt zostaja: wycofanie jest utrata zaufania,
// a nie kasowaniem historii. Fizyczne usuniecie danych to osobna sprawa
// polityki retencji.
func (s *Server) handleDecommissionHost(w http.ResponseWriter, r *http.Request) {
	s.zmienCyklZycia(w, r, cyklZycia{
		Permission:          authz.PermHostDecommission,
		ZStanow:             []string{hosts.StateActive, hosts.StateQuarantined, hosts.StateRetiring},
		Nowy:                hosts.StateRetired,
		Akcja:               "host.decommission",
		WymagaPotwierdzenia: true,
		// Wycofanie zawsze odwoluje certyfikaty: host, ktory odchodzi
		// z floty, nie moze wrocic sam z waznym certyfikatem w reku.
		ZawszeOdwoluj: true,
		AnulujZadania: true,
		ZamknijSesje:  true,
	})
}

// cyklZycia opisuje jedno przejscie stanu.
type cyklZycia struct {
	Permission          authz.Permission
	ZStanow             []string
	Nowy                string
	Akcja               string
	WymagaPotwierdzenia bool
	ZawszeOdwoluj       bool
	AnulujZadania       bool
	ZamknijSesje        bool
}

// zmienCyklZycia wykonuje przejscie razem ze skutkami ubocznymi.
//
// Wszystko w jednej transakcji: host, ktory jest juz w kwarantannie, ale ma
// zadania czekajace w kolejce, jest hostem odcietym tylko z nazwy.
func (s *Server) zmienCyklZycia(w http.ResponseWriter, r *http.Request, przejscie cyklZycia) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, przejscie.Permission, scope, "host", hostID)
	if !ok {
		return
	}

	var req zmianaCykluZycia
	if r.ContentLength > 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
			return
		}
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		problem(w, http.StatusBadRequest, "reason_required",
			"a lifecycle change must state its reason")
		return
	}
	// Przepisanie nazwy hosta jest jedynym miejscem, w ktorym operator musi
	// spojrzec, ktory host wycofuje. Kliknieciem w liscie latwo trafic obok.
	if przejscie.WymagaPotwierdzenia && req.TypedConfirmation != host.Hostname {
		problem(w, http.StatusBadRequest, "confirmation_mismatch",
			"type the hostname to confirm this change")
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := s.hosts.ChangeLifecycleState(r.Context(), tx, hostID, przejscie.ZStanow,
		przejscie.Nowy, req.Reason, principal.Subject); err != nil {
		if errors.Is(err, hosts.ErrForbiddenTransition) {
			problem(w, http.StatusConflict, "lifecycle_conflict",
				"the host is not in a state that allows this change")
			return
		}
		s.fail(w, err)
		return
	}

	anulowanych := 0
	if przejscie.AnulujZadania {
		anulowanych, err = s.jobs.CancelUndelivered(r.Context(), tx, hostID,
			principal.Subject, przejscie.Akcja)
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	odwolanych := 0
	if przejscie.ZawszeOdwoluj || req.RevokeCertificates {
		odwolanych, err = s.hosts.RevokeCertificates(r.Context(), tx, hostID, req.Reason)
		if err != nil {
			s.fail(w, err)
			return
		}
	}

	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: przejscie.Akcja, TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"reason": req.Reason, "state": przejscie.Nowy,
			"certificates_revoked": odwolanych, "jobs_canceled": anulowanych,
		},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}

	// Sesja konczy sie dopiero po zapisie: gdyby transakcja sie nie udala,
	// host zostalby rozlaczony bez powodu zapisanego w panelu.
	rozlaczony := false
	if przejscie.ZamknijSesje && s.registry != nil {
		rozlaczony = s.registry.ZakonczSesje(hostID, przejscie.Akcja)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host_id": hostID, "lifecycle_state": przejscie.Nowy, "reason": req.Reason,
		"jobs_canceled": anulowanych, "certificates_revoked": odwolanych,
		"session_closed": rozlaczony,
	})
}
