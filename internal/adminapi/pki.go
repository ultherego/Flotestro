package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// handlePKIStatus opisuje zbior CA floty wraz z liczba hostow, ktore nadal
// maja certyfikat wydany kazdym z nich.
//
// Bez tej liczby wycofanie CA byloby zgadywaniem: operator nie wiedzialby,
// ilu hostom odbiera dostep.
func (s *Server) handlePKIStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermPKIRead, authz.GlobalScope, "pki", ""); !ok {
		return
	}
	if s.trust == nil {
		problem(w, http.StatusNotImplemented, "pki_unavailable", "this panel does not manage the fleet CA")
		return
	}

	uzycie, err := s.hosts.CertificateIssuers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}

	lista := make([]map[string]any, 0)
	for _, ca := range s.trust.Authorities() {
		wpis := map[string]any{
			"subject": ca.Subject, "serial": ca.Serial, "fingerprint": ca.Fingerprint,
			"not_before": ca.NotBefore, "not_after": ca.NotAfter, "state": ca.State,
			"hosts_using": uzycie[ca.Subject+" "+ca.Serial],
		}
		if ca.State == "pending" {
			// Przy CA przygotowanym liczy sie co innego niz liczba hostow,
			// ktore go uzywaja: ile hostow jeszcze go nie zna.
			brakujace, err := s.hosts.HostsWithoutCertificateSince(r.Context(), ca.PreparedAt)
			if err != nil {
				s.fail(w, err)
				return
			}
			wpis["prepared_at"] = ca.PreparedAt
			wpis["hosts_missing"] = brakujace
			wpis["ready_to_activate"] = brakujace == 0
		}
		lista = append(lista, wpis)
	}
	writeJSON(w, http.StatusOK, map[string]any{"authorities": lista})
}

type pkiRequest struct {
	Reason string `json:"reason"`
}

// handlePrepareCA tworzy nowe CA floty i wlacza je do zbioru zaufania,
// jeszcze bez prawa podpisywania.
//
// To pierwsza z dwoch faz wymiany. Nowe CA trafia do bundla, ktory agent
// dostaje przy odnowieniu certyfikatu, wiec flota poznaje je sama - bez
// osobnej dystrybucji i bez okna, w ktorym host nie ufa panelowi.
func (s *Server) handlePrepareCA(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.pkiActor(w, r)
	if !ok {
		return
	}
	var request pkiRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	dowod, ok := s.requireStepUp(w, r, actor, request.Reason, "pki.ca.prepare", "pki", "")
	if !ok {
		return
	}

	nowe, err := s.trust.Prepare()
	if err != nil {
		problem(w, http.StatusConflict, "prepare_failed", err.Error())
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.prepare", TargetType: "pki", TargetID: nowe.Fingerprint,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"serial": nowe.Serial, "not_after": nowe.NotAfter,
		}, dowod),
	})
	s.log.Warn("przygotowano nowe CA floty; przejmie podpisywanie dopiero po zatwierdzeniu",
		"serial", nowe.Serial)

	writeJSON(w, http.StatusCreated, nowe)
}

// handleActivateCA przekazuje podpisywanie przygotowanemu CA.
//
// Panel odmawia, dopoki istnieje host, ktory nie dostal jeszcze nowego CA.
// Taki host po restarcie panelu nie uznalby certyfikatu serwera i wypadlby
// z floty - a wymiana CA ma byc niewidoczna dla operacji.
func (s *Server) handleActivateCA(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.pkiActor(w, r)
	if !ok {
		return
	}
	var request pkiRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	dowod, ok := s.requireStepUp(w, r, actor, request.Reason, "pki.ca.activate", "pki", "")
	if !ok {
		return
	}

	pending, przygotowaneO := s.trust.Pending()
	if pending == nil {
		problem(w, http.StatusConflict, "no_pending_ca", "no CA is prepared for handover")
		return
	}
	brakujace, err := s.hosts.HostsWithoutCertificateSince(r.Context(), przygotowaneO)
	if err != nil {
		s.fail(w, err)
		return
	}
	if brakujace > 0 {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor.Subject,
			Action: "pki.ca.activate", TargetType: "pki", TargetID: "",
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{"reason": "hosts_missing_ca", "hosts_missing": brakujace},
		})
		problem(w, http.StatusConflict, "hosts_missing_ca", fmt.Sprintf(
			"%d hosts do not have the new CA yet; wait for their certificates to renew",
			brakujace))
		return
	}

	aktywne, err := s.trust.Activate()
	if err != nil {
		problem(w, http.StatusConflict, "activate_failed", err.Error())
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.activate", TargetType: "pki", TargetID: aktywne.Fingerprint,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"serial": aktywne.Serial, "not_after": aktywne.NotAfter,
		}, dowod),
	})
	// Certyfikat serwera pochodzi jeszcze od poprzedniego CA; nowy powstanie
	// przy najblizszym starcie panelu i bedzie uznany przez cala flote.
	s.log.Warn("nowe CA floty przejelo podpisywanie", "serial", aktywne.Serial)

	writeJSON(w, http.StatusOK, aktywne)
}

// pkiActor sprawdza uprawnienie i dostepnosc modulu PKI.
func (s *Server) pkiActor(w http.ResponseWriter, r *http.Request) (authz.Principal, bool) {
	actor, ok := s.authorize(w, r, authz.PermPKIRotate, authz.GlobalScope, "pki", "")
	if !ok {
		return actor, false
	}
	if s.trust == nil {
		problem(w, http.StatusNotImplemented, "pki_unavailable", "this panel does not manage the fleet CA")
		return actor, false
	}
	return actor, true
}

// handleRetireCA usuwa wycofane CA ze zbioru zaufania.
func (s *Server) handleRetireCA(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.pkiActor(w, r)
	if !ok {
		return
	}
	fingerprint := r.PathValue("fingerprint")

	dowod, ok := s.requireStepUp(w, r, actor, r.URL.Query().Get("reason"),
		"pki.ca.retire", "pki", fingerprint)
	if !ok {
		return
	}

	uzycie, err := s.hosts.CertificateIssuers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	// Liczbe hostow bierzemy z bazy, a nie z zadania: operator nie moze
	// obejsc zabezpieczenia, podajac wlasna liczbe.
	hostow := 0
	for _, ca := range s.trust.Authorities() {
		if ca.Fingerprint == fingerprint {
			hostow = uzycie[ca.Subject+" "+ca.Serial]
		}
	}

	if err := s.trust.Retire(fingerprint, hostow); err != nil {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor.Subject,
			Action: "pki.ca.retire", TargetType: "pki", TargetID: fingerprint,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{"reason": err.Error(), "hosts_using": hostow},
		})
		problem(w, http.StatusConflict, "ca_in_use", err.Error())
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.retire", TargetType: "pki", TargetID: fingerprint,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{}, dowod),
	})
	w.WriteHeader(http.StatusNoContent)
}
