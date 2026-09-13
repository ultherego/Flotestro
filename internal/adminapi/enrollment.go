package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/enrollment"
	"github.com/ultherego/flotestro/internal/hosts"
)

// enrollmentRequestBody is the body of an enrollment order.
type enrollmentRequestBody struct {
	Description string `json:"description"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	// Kind decides what may be registered: an agent or a relay.
	Kind string `json:"kind"`
	// Purpose decides what may be done with a machine the panel already
	// knows. Empty means a new host - and such a token does not take over
	// the identity of a running machine.
	Purpose           string `json:"purpose"`
	ExpectedMachineID string `json:"expected_machine_id"`
	// RelayID confines the order to one site: the token works only through
	// this relay. Empty means no route restriction - and stays so for
	// installations without relays.
	RelayID    string `json:"relay_id"`
	MaxUses    int    `json:"max_uses"`
	TTLMinutes int    `json:"ttl_minutes"`
	// Reason is the purpose of an order that requires fresh authentication:
	// production, a batch token or a relay. The description stands in for
	// it when it says enough.
	Reason string `json:"reason"`
}

// handleCreateEnrollmentRequest issues an order and shows the token once.
func (s *Server) handleCreateEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	var req enrollmentRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	req.Site, req.Environment = orderPlacement(req.Site, req.Environment)
	// The order is authorised where the machine will live: an operator of
	// one site invites machines into that site, not into the whole fleet.
	// A relay is a separate right - it carries the traffic of a site.
	permission := authz.PermHostEnrollCreate
	if req.Kind == enrollment.KindRelay {
		permission = authz.PermRelayEnrollCreate
	}
	scope := authz.Scope{Site: req.Site, Environment: req.Environment}
	principal, ok := s.authorize(w, r, permission, scope, "enrollment_request", "")
	if !ok {
		return
	}
	// Identity recovery has its own entry on the host and its own
	// permission: only orders for new machines and relays are accepted
	// here.
	if req.Purpose == enrollment.PurposeReplace {
		problem(w, http.StatusBadRequest, "purpose_not_allowed",
			"identity recovery is requested on the host itself")
		return
	}
	// Enrollment opens the way to root on the machine through the helper.
	// An order for production, a token good for many machines or a relay
	// requires fresh authentication, like any change of that weight.
	var stepUpEvidence map[string]any
	if s.requiresSecondPerson(req.Environment) || req.MaxUses > 1 || req.Kind == enrollment.KindRelay {
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = strings.TrimSpace(req.Description)
		}
		evidence, ok := s.requireStepUp(w, r, principal, reason,
			"host.enrollment.create", "enrollment_request", "")
		if !ok {
			return
		}
		stepUpEvidence = evidence
	}

	order, err := s.createOrder(r, req, principal.Subject, "")
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.enrollment.create", TargetType: "enrollment_request",
		TargetID: order.ID, Outcome: audit.OutcomeSuccess,
		// The token value does not go to the audit log: it is a secret, and
		// the audit log is read by more people than the one who ordered the
		// installation.
		Detail: withStepUp(map[string]any{
			"site": order.Site, "environment": order.Environment,
			"kind": order.Kind, "purpose": order.Purpose,
			"relay_id": order.RelayID,
			"max_uses": order.MaxUses, "expires_at": order.ExpiresAt,
		}, stepUpEvidence),
	})
	writeJSON(w, http.StatusCreated, order)
}

// orderPlacement fills in the site and the environment of an order that
// names none: a machine has to land somewhere, and "unassigned" says
// honestly that nobody decided yet.
func orderPlacement(site, environment string) (string, string) {
	if site == "" {
		site = "default"
	}
	if environment == "" {
		environment = "unassigned"
	}
	return site, environment
}

// createOrder assembles the store input from the HTTP request.
func (s *Server) createOrder(r *http.Request, req enrollmentRequestBody, actor,
	hostID string) (*enrollment.Request, error) {
	req.Site, req.Environment = orderPlacement(req.Site, req.Environment)
	ttl := time.Duration(req.TTLMinutes) * time.Minute
	if req.TTLMinutes <= 0 {
		ttl = 15 * time.Minute
	}
	return s.tokens.Create(r.Context(), enrollment.CreateInput{
		Description: req.Description, Site: req.Site, Environment: req.Environment,
		Kind: req.Kind, Purpose: req.Purpose,
		ExpectedMachineID: req.ExpectedMachineID, ExpectedHostID: hostID,
		RelayID: req.RelayID,
		MaxUses: req.MaxUses, TTL: ttl, CreatedBy: actor,
	})
}

// installationStep is one stage visible on the installation screen.
//
// The stages are separate, because each fails for a different reason and
// is fixed differently: the token may expire, the certificate may be
// rejected on a CSR error, the session may not get through a firewall, and
// the inventory may not arrive when the agent has no capabilities yet.
type installationStep struct {
	Key   string `json:"key"`
	State string `json:"state"`
}

// Host installation stages.
const (
	StepToken       = "token"
	StepCertificate = "certificate"
	StepConnected   = "connected"
	StepInventory   = "inventory"
	StateWaiting    = "waiting"
	StateDone       = "done"
	StateFailed     = "failed"
)

// orderWithSteps attaches the installation progress to the order.
type orderWithSteps struct {
	*enrollment.Request
	Steps []installationStep `json:"steps"`
}

// installationSteps computes the installation progress from what the panel
// really sees.
//
// Nothing here is an agent declaration: a used token follows from the use
// counter, the certificate from the saved host, the session from the
// connection state, and the inventory from the fragments that have already
// arrived.
func (s *Server) installationSteps(r *http.Request,
	order *enrollment.Request) []installationStep {
	failed := order.Status == enrollment.StatusExpired ||
		order.Status == enrollment.StatusRevoked ||
		order.Status == enrollment.StatusFailed

	stepState := func(done bool) string {
		switch {
		case done:
			return StateDone
		case failed:
			// An order closed without this step will not do it any more.
			return StateFailed
		default:
			return StateWaiting
		}
	}

	steps := []installationStep{
		{Key: StepToken, State: stepState(order.Uses > 0)},
		{Key: StepCertificate, State: stepState(order.EnrolledHostID != "")},
	}
	connected, withInventory := false, false
	if order.EnrolledHostID != "" {
		if host, err := s.hosts.Get(r.Context(), order.EnrolledHostID); err == nil && host != nil {
			connected = host.ConnectionState == "online"
			withInventory = host.CurrentInventoryRevision != ""
		}
	}
	steps = append(steps,
		installationStep{Key: StepConnected, State: stepState(connected)},
		installationStep{Key: StepInventory, State: stepState(withInventory)})
	return steps
}

// handleListEnrollmentRequests shows the pending and closed installations.
func (s *Server) handleListEnrollmentRequests(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermHostEnrollRead, authz.GlobalScope,
		"enrollment_request", ""); !ok {
		return
	}
	orders, err := s.tokens.List(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": orders, "count": len(orders)})
}

// handleGetEnrollmentRequest shows one order.
func (s *Server) handleGetEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermHostEnrollRead, authz.GlobalScope,
		"enrollment_request", r.PathValue("id")); !ok {
		return
	}
	order, err := s.tokens.Request(r.Context(), r.PathValue("id"))
	if errors.Is(err, enrollment.ErrUnknownRequest) {
		problem(w, http.StatusNotFound, "not_found", "enrollment request not found")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, orderWithSteps{
		Request: order, Steps: s.installationSteps(r, order),
	})
}

// handleRevokeEnrollmentRequest blocks the remaining uses immediately.
func (s *Server) handleRevokeEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorize(w, r, authz.PermHostEnrollRevoke, authz.GlobalScope,
		"enrollment_request", r.PathValue("id"))
	if !ok {
		return
	}
	err := s.tokens.Revoke(r.Context(), r.PathValue("id"))
	if errors.Is(err, enrollment.ErrUnknownRequest) {
		problem(w, http.StatusNotFound, "not_found", "enrollment request not found")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.enrollment.revoke", TargetType: "enrollment_request",
		TargetID: r.PathValue("id"), Outcome: audit.OutcomeSuccess,
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleIdentityRecovery orders the identity recovery of an existing host.
//
// A separate entry and a separate permission, because this is not an
// invitation for a new machine: the token from this order fits only the
// named host, and it returns to the panel with the same history, not as a
// second row next to a dead twin.
func (s *Server) handleIdentityRecovery(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostIdentityReplace, scope, "host", hostID)
	if !ok {
		return
	}

	// A retired host does not return to the fleet with a token. An order
	// that cannot be used anyway would be an empty promise - the return
	// starts with reversing the decommissioning decision.
	if host.LifecycleState == hosts.StateRetired {
		problem(w, http.StatusConflict, "host_retired",
			"a retired host cannot be brought back with a recovery token")
		return
	}

	var req struct {
		enrollmentRequestBody
		// RevokeOldImmediately cuts the old key off now, for a suspected
		// theft. Without it the old certificate stays valid until the new
		// session confirms the replacement - a planned key change.
		RevokeOldImmediately bool `json:"revoke_old_immediately"`
		TTLSeconds           int  `json:"ttl_seconds"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
			return
		}
	}
	// The scope comes from the host, not from the request: identity
	// recovery is not an occasion to move the host to another site or
	// environment.
	req.Site, req.Environment = host.Site, host.Environment
	req.Kind, req.Purpose = enrollment.KindAgent, enrollment.PurposeReplace
	req.MaxUses = 1
	if req.TTLSeconds > 0 && req.TTLMinutes <= 0 {
		req.TTLMinutes = (req.TTLSeconds + 59) / 60
	}

	// Taking over the identity of a machine in the fleet is a change of
	// the highest weight: fresh authentication, with the reason recorded.
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = strings.TrimSpace(req.Description)
	}
	evidence, ok := s.requireStepUp(w, r, principal, reason, "host.identity.recovery", "host", hostID)
	if !ok {
		return
	}

	order, err := s.createOrder(r, req.enrollmentRequestBody, principal.Subject, hostID)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	revoked := 0
	if req.RevokeOldImmediately {
		revoked, err = s.revokeNow(r, hostID, reason)
		if err != nil {
			s.fail(w, err)
			return
		}
		if s.registry != nil {
			s.registry.EndSession(hostID, "identity_recovery")
		}
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.identity.recovery", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"request_id": order.ID, "expires_at": order.ExpiresAt,
			"expected_machine_id": order.ExpectedMachineID,
			"reason":              reason, "revoke_old_immediately": req.RevokeOldImmediately,
			"certificates_revoked": revoked,
		}, evidence),
	})
	writeJSON(w, http.StatusCreated, order)
}

// revokeNow revokes every live certificate of the host in its own
// transaction. The old certificate record stays with the revocation reason:
// history is not deleted.
func (s *Server) revokeNow(r *http.Request, hostID, reason string) (int, error) {
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	revoked, err := s.hosts.RevokeCertificates(r.Context(), tx, hostID, reason)
	if err != nil {
		return 0, err
	}
	return revoked, tx.Commit(r.Context())
}
