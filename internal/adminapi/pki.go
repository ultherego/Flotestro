package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// handlePKIStatus describes the set of fleet CAs together with the number of
// hosts that still have a certificate issued by each of them.
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
			missing, err := s.hosts.HostsWithoutCertificateSince(r.Context(), ca.PreparedAt,
				s.trust.Active().IssuerID())
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
	// IdempotencyKey is what tells a repeated request from a second change. The
	// header of the same name serves too; one of them is required, because a
	// change to what the fleet trusts must not happen twice on a lost answer.
	IdempotencyKey string `json:"idempotency_key"`
}

// handlePrepareCA creates a new fleet CA and adds it to the trust set, without
// the right to sign yet.
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
	// The trail first, and committed: a CA on disk that nobody began is a CA
	// nobody can account for.
	key, ok := s.beganChange(w, r, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.prepare", TargetType: "pki", TargetID: "",
		RequestID: requestIDOf(r),
		Detail:    withStepUp(map[string]any{"reason": request.Reason}, evidence),
	}, request.IdempotencyKey)
	if !ok {
		return
	}

	prepared, err := s.trust.Prepare()
	if err != nil {
		// What the trail records is what the trust store shows, not what the call
		// returned: a preparation that failed halfway may still have left material
		// behind, and a terminal "failure" over it would be read later as a change
		// that never happened.
		outcome, found := s.trustState(audit.Intent{Action: "pki.ca.prepare"})
		if !s.finishedChange(w, r, audit.Event{
			ActorType: audit.ActorUser, ActorID: actor.Subject,
			Action: "pki.ca.prepare", TargetType: "pki", TargetID: "",
			RequestID: requestIDOf(r), Outcome: outcome,
			Detail: map[string]any{"error": err.Error(), "found": found},
		}, key, "the preparation of a CA failed") {
			return
		}
		problem(w, http.StatusConflict, "prepare_failed", err.Error())
		return
	}

	if !s.finishedChange(w, r, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.prepare", TargetType: "pki", TargetID: prepared.Fingerprint,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"serial": prepared.Serial, "not_after": prepared.NotAfter,
		}, evidence),
	}, key, "a new fleet CA was prepared") {
		return
	}
	s.log.Warn("a new fleet CA was prepared; it takes over signing only after approval",
		"serial", prepared.Serial)

	writeJSON(w, http.StatusCreated, prepared)
}

// handleActivateCA hands signing over to the prepared CA. The panel refuses
// while a host exists that has not received the new CA yet.
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
	// The authority that signs is read now and not at the start: this instance
	// may have followed another one into a handover since.
	missing, err := s.hosts.HostsWithoutCertificateSince(r.Context(), preparedAt,
		s.trust.Active().IssuerID())
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

	// Everything that could refuse has refused by now, so the next step changes
	// the fleet's trust: the beginning is written and committed first.
	key, ok := s.beganChange(w, r, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.activate", TargetType: "pki", TargetID: pending.FingerprintHex(),
		RequestID: requestIDOf(r),
		Detail: withStepUp(map[string]any{
			"reason": request.Reason, "serial": pending.Certificate.SerialNumber.String(),
		}, evidence),
	}, request.IdempotencyKey)
	if !ok {
		return
	}

	active, err := s.trust.Activate()
	if err != nil {
		// The trail says what signs now, not what the call returned: a handover
		// that failed after the swap would otherwise be recorded as one that never
		// happened.
		outcome, found := s.trustState(audit.Intent{
			Action: "pki.ca.activate", TargetID: pending.FingerprintHex()})
		if !s.finishedChange(w, r, audit.Event{
			ActorType: audit.ActorUser, ActorID: actor.Subject,
			Action: "pki.ca.activate", TargetType: "pki", TargetID: pending.FingerprintHex(),
			RequestID: requestIDOf(r), Outcome: outcome,
			Detail: map[string]any{"error": err.Error(), "found": found},
		}, key, "the handover of signing failed") {
			return
		}
		problem(w, http.StatusConflict, "activate_failed", err.Error())
		return
	}

	if !s.finishedChange(w, r, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.activate", TargetType: "pki", TargetID: active.Fingerprint,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"serial": active.Serial, "not_after": active.NotAfter,
		}, evidence),
	}, key, "the new fleet CA took over signing") {
		return
	}
	// Each panel issues its own serving certificate from the CA that signs, and
	// does so at the handshake after it has seen the handover, so no restart is
	// needed for the fleet to go on recognising the panel.
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

// authorityUsage counts what would stop trusting an authority if it were taken
// out of the trust set.
//
// A prepared authority has signed nothing: it waits beside the one that signs
// and takes over only when somebody hands the signing to it. Abandoning it is
// allowed - and it was not, because a relay is attributed to an authority by
// subject alone, which a prepared authority shares with the one it would
// replace. It inherited those relays and could never be taken back out.
func authorityUsage(state, subject, serial string, hosts, relays map[string]int) int {
	if state == "pending" {
		return 0
	}
	// A relay enrolled before the issuer was recorded counts here too: what
	// nobody can attribute is not evidence that nobody uses it.
	return hosts[subject+" "+serial] + relays[subject] + relays[""]
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
	// A relay is signed by the same authority and lives in another table. The
	// count used to be of hosts alone, so an authority underwriting every relay
	// of the fleet retired cleanly and the relays stopped verifying.
	relayUsage := map[string]int{}
	if s.relays != nil {
		relayUsage, err = s.relays.CertificateIssuers(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	// The count is taken from the database, not from the request: the operator
	// must not bypass the safeguard by giving their own number.
	hostCount := 0
	for _, ca := range s.trust.Authorities() {
		if ca.Fingerprint == fingerprint {
			hostCount = authorityUsage(ca.State, ca.Subject, ca.Serial, usage, relayUsage)
		}
	}

	// Taking an authority out of the trust set is the same kind of change as
	// putting one in, and it is written down before it happens.
	key, ok := s.beganChange(w, r, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.retire", TargetType: "pki", TargetID: fingerprint,
		RequestID: requestIDOf(r),
		Detail: withStepUp(map[string]any{
			"reason": r.URL.Query().Get("reason"), "hosts_using": hostCount,
		}, evidence),
	}, r.URL.Query().Get("idempotency_key"))
	if !ok {
		return
	}

	if err := s.trust.Retire(fingerprint, hostCount); err != nil {
		// A refusal by the policy leaves the trust set as it was, and a failure
		// halfway may not have: the trail takes the answer from the set itself.
		outcome, found := s.trustState(audit.Intent{
			Action: "pki.ca.retire", TargetID: fingerprint})
		if outcome == audit.OutcomeFailure {
			outcome = audit.OutcomeDenied
		}
		if !s.finishedChange(w, r, audit.Event{
			ActorType: audit.ActorUser, ActorID: actor.Subject,
			Action: "pki.ca.retire", TargetType: "pki", TargetID: fingerprint,
			RequestID: requestIDOf(r), Outcome: outcome,
			Detail: map[string]any{"reason": err.Error(), "hosts_using": hostCount, "found": found},
		}, key, "the CA was not retired") {
			return
		}
		problem(w, http.StatusConflict, "ca_in_use", err.Error())
		return
	}

	if !s.finishedChange(w, r, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "pki.ca.retire", TargetType: "pki", TargetID: fingerprint,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{}, evidence),
	}, key, "the fleet CA was retired") {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
