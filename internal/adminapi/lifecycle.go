package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/gateway"
	"github.com/ultherego/flotestro/internal/hosts"
)

// lifecycleChange is the body of a host state change request.
type lifecycleChange struct {
	// Reason is always required. A host cut off without a reason is a host
	// nobody will know in a week why it is not working.
	Reason string `json:"reason"`
	// RevokeCertificates applies on a suspected key leak. Without it the
	// certificate stays cryptographically valid and is blocked by the state
	// in the database alone - that is enough as long as the key is with its
	// owner.
	RevokeCertificates bool `json:"revoke_certificates"`
	// TypedConfirmation is the explicit retyping of the hostname at
	// decommissioning.
	TypedConfirmation string `json:"typed_confirmation"`
}

// handleQuarantineHost cuts a host off from the fleet immediately.
func (s *Server) handleQuarantineHost(w http.ResponseWriter, r *http.Request) {
	s.changeLifecycle(w, r, lifecycleTransition{
		Permission: authz.PermHostQuarantine,
		// A host in recovery can be quarantined too: a key change under way
		// does not rule out a theft found meanwhile.
		FromStates: []string{hosts.StateActive, hosts.StateRecovery, hosts.StateQuarantined},
		To:         hosts.StateQuarantined,
		Action:     "host.quarantine",
		// Tasks already delivered stay: the agent may be half-way through an
		// operation that cannot be interrupted, and the panel has no way to
		// undo it.
		CancelJobs:   true,
		CloseSession: true,
	})
}

// handleReleaseHost restores a host after the incident assessment.
func (s *Server) handleReleaseHost(w http.ResponseWriter, r *http.Request) {
	s.changeLifecycle(w, r, lifecycleTransition{
		Permission: authz.PermHostQuarantineRelease,
		FromStates: []string{hosts.StateQuarantined},
		To:         hosts.StateActive,
		Action:     "host.quarantine.release",
		// A release with a revoked certificate would be a release in name
		// only - the host cannot connect - and would hide that the
		// identity is still to be recovered.
		RequiresLiveCertificate: true,
	})
}

// decommissionRequest is the body of a decommission order.
type decommissionRequest struct {
	lifecycleChange
	// LocalIdentityWipe asks the agent to remove its identity and journal
	// and to disable its service once the panel has revoked the
	// certificates. Default true: a host leaving the fleet is not to keep a
	// key that used to open the panel.
	LocalIdentityWipe *bool `json:"local_identity_wipe"`
	// RevokeImmediatelyIfOffline revokes the certificates of a host that
	// has no session, without waiting for it. Default true. Off, the
	// certificates are revoked at the host's first contact instead.
	RevokeImmediatelyIfOffline *bool `json:"revoke_immediately_if_offline"`
}

// handleDecommissionHost ends the trust in a host on the panel side.
//
// A connected host is asked to stop first: it finishes what it started,
// drops its secret leases, reports it is ready, and only then are its
// certificates revoked and its identity wiped. A host without a session, or
// one that does not answer in time, is retired all the same - with the
// cleanup marked as unconfirmed, in the answer and in the audit trail, so
// nobody takes a machine on a shelf for a machine that wiped itself.
//
// The host record, the inventory and the audit log stay: decommissioning is
// a loss of trust, not deleting history. Physically removing the data is a
// separate matter of the retention policy.
func (s *Server) handleDecommissionHost(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostDecommission, scope, "host", hostID)
	if !ok {
		return
	}

	var req decommissionRequest
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
	if req.TypedConfirmation != host.Hostname {
		problem(w, http.StatusBadRequest, "confirmation_mismatch",
			"type the hostname to confirm this change")
		return
	}
	evidence, ok := s.requireStepUp(w, r, principal, req.Reason, "host.decommission", "host", hostID)
	if !ok {
		return
	}

	outcome, err := s.decommissioner.Run(r.Context(), gateway.Decommission{
		HostID: hostID, Reason: req.Reason, Actor: principal.Subject,
		// A host in recovery is decommissioned like any other: the recovery
		// order it had becomes moot, and the token issued for it is refused
		// at enrollment as the token of a retired host.
		FromStates: []string{hosts.StateActive, hosts.StateQuarantined,
			hosts.StateRecovery, hosts.StateRetiring},
		LocalIdentityWipe:          defaultTrue(req.LocalIdentityWipe),
		RevokeImmediatelyIfOffline: defaultTrue(req.RevokeImmediatelyIfOffline),
		StepUp:                     evidence,
	})
	if err != nil {
		if gateway.IsForbiddenTransition(err) {
			problem(w, http.StatusConflict, "lifecycle_conflict",
				"the host is not in a state that allows this change")
			return
		}
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host_id": hostID, "lifecycle_state": outcome.State, "reason": req.Reason,
		"phase":                      outcome.Phase,
		"remote_cleanup_unconfirmed": outcome.RemoteCleanupUnconfirmed,
		"running_tasks":              outcome.RunningTasks,
		"leases_dropped":             outcome.LeasesDropped,
		"jobs_canceled":              outcome.JobsCanceled,
		"certificates_revoked":       outcome.CertificatesRevoked,
		"session_closed":             outcome.SessionClosed,
	})
}

// defaultTrue reads an optional flag whose absence means yes.
func defaultTrue(flag *bool) bool { return flag == nil || *flag }

// lifecycleTransition describes one state transition.
type lifecycleTransition struct {
	Permission           authz.Permission
	FromStates           []string
	To                   string
	Action               string
	RequiresConfirmation bool
	// RequiresLiveCertificate refuses the transition when every certificate
	// of the host is revoked or expired.
	RequiresLiveCertificate bool
	AlwaysRevoke            bool
	CancelJobs              bool
	CloseSession            bool
}

// changeLifecycle performs the transition together with its side effects.
//
// Everything in one transaction: a host that is already in quarantine but
// has tasks waiting in the queue is a host cut off in name only.
func (s *Server) changeLifecycle(w http.ResponseWriter, r *http.Request, transition lifecycleTransition) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, transition.Permission, scope, "host", hostID)
	if !ok {
		return
	}

	var req lifecycleChange
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
	// Retyping the hostname is the only place where the operator has to
	// look at which host they decommission. A click in a list easily lands
	// next to the target.
	if transition.RequiresConfirmation && req.TypedConfirmation != host.Hostname {
		problem(w, http.StatusBadRequest, "confirmation_mismatch",
			"type the hostname to confirm this change")
		return
	}
	// Every lifecycle decision is taken with fresh authentication: cutting
	// a host off, letting it back in and ending the trust in it are the
	// decisions an attacker with a stolen session would want most.
	evidence, ok := s.requireStepUp(w, r, principal, req.Reason, transition.Action, "host", hostID)
	if !ok {
		return
	}
	// A host whose certificates were revoked does not return by lifting
	// the quarantine: the key was suspect, and the state in the database
	// was never what kept it out. Its return is identity recovery.
	if transition.RequiresLiveCertificate {
		live, err := s.hosts.HasLiveCertificate(r.Context(), hostID)
		if err != nil {
			s.fail(w, err)
			return
		}
		if !live {
			problem(w, http.StatusConflict, "identity_revoked",
				"the certificates of this host were revoked; recover its identity before releasing it")
			return
		}
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := s.hosts.ChangeLifecycleState(r.Context(), tx, hostID, transition.FromStates,
		transition.To, req.Reason, principal.Subject); err != nil {
		if errors.Is(err, hosts.ErrForbiddenTransition) {
			problem(w, http.StatusConflict, "lifecycle_conflict",
				"the host is not in a state that allows this change")
			return
		}
		s.fail(w, err)
		return
	}

	canceled := 0
	if transition.CancelJobs {
		canceled, err = s.jobs.CancelUndelivered(r.Context(), tx, hostID,
			principal.Subject, transition.Action)
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	revoked := 0
	if transition.AlwaysRevoke || req.RevokeCertificates {
		revoked, err = s.hosts.RevokeCertificates(r.Context(), tx, hostID, req.Reason)
		if err != nil {
			s.fail(w, err)
			return
		}
	}

	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: transition.Action, TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"reason": req.Reason, "state": transition.To,
			"certificates_revoked": revoked, "jobs_canceled": canceled,
		}, evidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}

	// The session ends only after the write: had the transaction failed,
	// the host would be disconnected without a reason recorded in the
	// panel.
	disconnected := false
	if transition.CloseSession && s.registry != nil {
		disconnected = s.registry.EndSession(hostID, transition.Action)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host_id": hostID, "lifecycle_state": transition.To, "reason": req.Reason,
		"jobs_canceled": canceled, "certificates_revoked": revoked,
		"session_closed": disconnected,
	})
}
