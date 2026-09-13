package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// handlePKIStatus describes the set of fleet CAs together with the number
// of hosts that still have a certificate issued by each of them.
//
// Without this number retiring a CA would be guessing: the operator would
// not know how many hosts they take access away from.
func (s *Server) handlePKIStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermPKIRead, authz.GlobalScope, "pki", ""); !ok {
		return
	}
	if s.trust == nil {
		problem(w, http.StatusNotImplemented, "pki_unavailable", "this panel does not manage the fleet CA")
		return
	}

	usage, err := s.hosts.CertificateIssuers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}

	list := make([]map[string]any, 0)
	for _, ca := range s.trust.Authorities() {
		entry := map[string]any{
			"subject": ca.Subject, "serial": ca.Serial, "fingerprint": ca.Fingerprint,
			"not_before": ca.NotBefore, "not_after": ca.NotAfter, "state": ca.State,
			"hosts_using": usage[ca.Subject+" "+ca.Serial],
		}
		if ca.State == "pending" {
			// For a prepared CA something else counts than the number of hosts
			// using it: how many hosts do not know it yet.
			missing, err := s.hosts.HostsWithoutCertificateSince(r.Context(), ca.PreparedAt)
			if err != nil {
				s.fail(w, err)
				return
			}
			entry["prepared_at"] = ca.PreparedAt
			entry["hosts_missing"] = missing
			entry["ready_to_activate"] = missing == 0
		}
		list = append(list, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"authorities": list})
}

type pkiRequest struct {
	Reason string `json:"reason"`
}

// handlePrepareCA creates a new fleet CA and adds it to the trust set,
// without the right to sign yet.
//
// This is the first of the two rotation phases. The new CA goes into the
// bundle the agent receives at certificate renewal, so the fleet learns it
// on its own - without a separate distribution and without a window in
// which a host does not trust the panel.
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
	evidence, ok := s.requireStepUp(w, r, actor, request.Reason, "pki.ca.prepare", "pki", "")
	if !ok {
		return
	}

	prepared, err := s.trust.Prepare()
	if err != nil {
		problem(w, http.StatusConflict, "prepare_failed", err.Error())
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.prepare", TargetType: "pki", TargetID: prepared.Fingerprint,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"serial": prepared.Serial, "not_after": prepared.NotAfter,
		}, evidence),
	})
	s.log.Warn("a new fleet CA was prepared; it takes over signing only after approval",
		"serial", prepared.Serial)

	writeJSON(w, http.StatusCreated, prepared)
}

// handleActivateCA hands signing over to the prepared CA.
//
// The panel refuses while a host exists that has not received the new CA
// yet. Such a host would not accept the server certificate after a panel
// restart and would drop out of the fleet - and a CA rotation is meant to
// be invisible to operations.
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
	evidence, ok := s.requireStepUp(w, r, actor, request.Reason, "pki.ca.activate", "pki", "")
	if !ok {
		return
	}

	pending, preparedAt := s.trust.Pending()
	if pending == nil {
		problem(w, http.StatusConflict, "no_pending_ca", "no CA is prepared for handover")
		return
	}
	missing, err := s.hosts.HostsWithoutCertificateSince(r.Context(), preparedAt)
	if err != nil {
		s.fail(w, err)
		return
	}
	if missing > 0 {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor.Subject,
			Action: "pki.ca.activate", TargetType: "pki", TargetID: "",
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{"reason": "hosts_missing_ca", "hosts_missing": missing},
		})
		problem(w, http.StatusConflict, "hosts_missing_ca", fmt.Sprintf(
			"%d hosts do not have the new CA yet; wait for their certificates to renew",
			missing))
		return
	}

	active, err := s.trust.Activate()
	if err != nil {
		problem(w, http.StatusConflict, "activate_failed", err.Error())
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.activate", TargetType: "pki", TargetID: active.Fingerprint,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"serial": active.Serial, "not_after": active.NotAfter,
		}, evidence),
	})
	// The server certificate still comes from the previous CA; a new one is
	// made at the next panel start and is accepted by the whole fleet.
	s.log.Warn("the new fleet CA took over signing", "serial", active.Serial)

	writeJSON(w, http.StatusOK, active)
}

// pkiActor checks the permission and the availability of the PKI module.
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

// handleRetireCA removes a retired CA from the trust set.
func (s *Server) handleRetireCA(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.pkiActor(w, r)
	if !ok {
		return
	}
	fingerprint := r.PathValue("fingerprint")

	evidence, ok := s.requireStepUp(w, r, actor, r.URL.Query().Get("reason"),
		"pki.ca.retire", "pki", fingerprint)
	if !ok {
		return
	}

	usage, err := s.hosts.CertificateIssuers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	// The host count is taken from the database, not from the request: the
	// operator must not bypass the safeguard by giving their own number.
	hostCount := 0
	for _, ca := range s.trust.Authorities() {
		if ca.Fingerprint == fingerprint {
			hostCount = usage[ca.Subject+" "+ca.Serial]
		}
	}

	if err := s.trust.Retire(fingerprint, hostCount); err != nil {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor.Subject,
			Action: "pki.ca.retire", TargetType: "pki", TargetID: fingerprint,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{"reason": err.Error(), "hosts_using": hostCount},
		})
		problem(w, http.StatusConflict, "ca_in_use", err.Error())
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.retire", TargetType: "pki", TargetID: fingerprint,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{}, evidence),
	})
	w.WriteHeader(http.StatusNoContent)
}
