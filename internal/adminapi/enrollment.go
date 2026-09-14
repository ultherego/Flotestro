package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/enrollment"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/relays"
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
	if errors.Is(err, enrollment.ErrRepeated) {
		// The same order again, from a caller that lost the first answer.
		// The token is not repeated: it was shown once. A caller that
		// needs a new one revokes this order and places another.
		writeJSON(w, http.StatusOK, orderView{Request: order, ConfigURL: configURL(order.ID)})
		return
	}
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
	writeJSON(w, http.StatusCreated, orderView{Request: order, ConfigURL: configURL(order.ID)})
}

// configURL points at the ready configuration of an order. The
// configuration carries no token: it can be fetched as many times as the
// installation needs, the token cannot.
func configURL(orderID string) string {
	return "/api/v1/enrollment-requests/" + orderID + "/config"
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
		IdempotencyKey: idempotencyKeyOf(r, ""),
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
	// ErrorCode names why the step does not go on, when the panel knows:
	// a refused attempt recorded against the order, or a readiness gate
	// the host has not passed in time. Detail says the same in a sentence.
	ErrorCode string `json:"error_code,omitempty"`
	Detail    string `json:"detail,omitempty"`
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

// The readiness gates on the host side of the installation. The panel
// cannot see the host, only its absence: a certificate without a session
// after a while, a session without an inventory after a while.
const (
	GateEnrolledNotConnected = "enrolled_not_connected"
	GateInventoryUnavailable = "inventory_unavailable"
	// readinessPatience is how long a step may wait before its silence is
	// named. An agent starts within seconds; two minutes covers a slow
	// package manager and a first reconnect backoff.
	readinessPatience = 2 * time.Minute
)

// orderView is the order as the API answers it: with the address of its
// ready configuration and, when read back, the installation progress.
type orderView struct {
	*enrollment.Request
	ConfigURL string             `json:"config_url"`
	Steps     []installationStep `json:"steps,omitempty"`
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

	// A refused attempt names the reason on the step it stopped at. Only a
	// step that is not done carries it: a batch order that admitted one
	// host and refused another is still an order that works.
	if code, detail := s.lastDenial(r, order.ID); code != "" {
		index := 1
		if tokenDenial(code) {
			index = 0
		}
		if steps[index].State != StateDone {
			steps[index].ErrorCode, steps[index].Detail = code, detail
		}
	}
	// The gates on the host side. The panel sees no error there, only
	// silence - and names it once it has lasted long enough to mean
	// something.
	if order.EnrolledHostID != "" && !connected && !failed &&
		time.Since(order.UpdatedAt) > readinessPatience {
		steps[2].ErrorCode = GateEnrolledNotConnected
		steps[2].Detail = "the certificate was issued, but the agent has opened no session; " +
			"check that the service runs and that the gateway address is reachable"
	}
	if connected && !withInventory && time.Since(s.sessionStart(order)) > readinessPatience {
		steps[3].ErrorCode = GateInventoryUnavailable
		steps[3].Detail = "the agent is connected, but no inventory has arrived; " +
			"check the agent journal for a module that fails to read the host"
	}
	return steps
}

// sessionStart is the moment the inventory clock starts: the start of the
// session this gateway holds, or - when another gateway holds it - the
// moment the certificate was issued.
func (s *Server) sessionStart(order *enrollment.Request) time.Time {
	if s.registry != nil {
		if session, ok := s.registry.Get(order.EnrolledHostID); ok && session != nil {
			return session.StartedAt
		}
	}
	return order.UpdatedAt
}

// tokenDenial says whether a refusal stopped the installation at the token
// - before the panel considered the machine at all.
func tokenDenial(code string) bool {
	switch code {
	case enrollment.DenialTokenExpired, enrollment.DenialTokenRevoked,
		enrollment.DenialRequestReused, enrollment.DenialMachineMismatch,
		enrollment.DenialRelayScope:
		return true
	}
	return false
}

// lastDenial reads the newest refused attempt recorded against an order.
//
// The audit trail is the record: the gateway writes every refusal there
// with the order as its target, and nothing else about a refusal survives
// - the agent gets a uniform answer by design. A few newest events are
// read, because the same target also carries the refusals of the panel's
// own authorisation, which say nothing about the host.
func (s *Server) lastDenial(r *http.Request, orderID string) (string, string) {
	page, err := s.audit.ListPaged(r.Context(), audit.ListFilter{
		TargetType: "enrollment_request", TargetID: orderID,
	}, audit.Cursor{}, 10)
	if err != nil {
		s.log.Warn("the refusals of an enrollment order could not be read",
			"order", orderID, "err", err)
		return "", ""
	}
	for _, record := range page.Items {
		if record.Action != "host.enroll" || record.Outcome == string(audit.OutcomeSuccess) {
			continue
		}
		var detail struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(record.Detail, &detail); err != nil || detail.Reason == "" {
			continue
		}
		return detail.Reason, detail.Message
	}
	return "", ""
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
	order, ok := s.readableOrder(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, orderView{
		Request: order, ConfigURL: configURL(order.ID), Steps: s.installationSteps(r, order),
	})
}

// readableOrder loads an order and authorises reading it where the machine
// will live. The one who placed an order for a site is to follow it without
// a global right: the installation screen polls this until the host is
// ready.
func (s *Server) readableOrder(w http.ResponseWriter, r *http.Request) (*enrollment.Request, bool) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		problem(w, http.StatusNotFound, "not_found", "enrollment request not found")
		return nil, false
	}
	order, err := s.tokens.Request(r.Context(), id)
	if errors.Is(err, enrollment.ErrUnknownRequest) {
		problem(w, http.StatusNotFound, "not_found", "enrollment request not found")
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	scope := authz.Scope{Site: order.Site, Environment: order.Environment}
	if _, ok := s.authorize(w, r, authz.PermHostEnrollRead, scope, "enrollment_request", id); !ok {
		return nil, false
	}
	return order, true
}

// handleEnrollmentConfig serves the ready configuration file of an order.
//
// The file is the same the installation profile composes for the order's
// placement, so it can be fetched with curl on the host instead of pasted.
// It never carries the token: the token was shown once, and a file that
// can be fetched again must not be a second way to it.
func (s *Server) handleEnrollmentConfig(w http.ResponseWriter, r *http.Request) {
	order, ok := s.readableOrder(w, r)
	if !ok {
		return
	}
	// A relay connects to the panel directly, whatever the order says
	// about routes: it is the route of its site, not a host behind one.
	relayID := order.RelayID
	if order.Kind == enrollment.KindRelay {
		relayID = ""
	}
	connection, err := s.installationConnection(r, order.Site, relayID)
	if err != nil {
		s.installationProblem(w, err)
		return
	}
	content := agentConfigText(order.Kind, order.Site, order.Environment, connection)
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(content))
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
	// A revoked recovery order may have been the only thing a host in
	// recovery was waiting for; it comes back to active at once rather than
	// at the next sweep.
	s.lapseRecoveries(r.Context(), principal.Subject)
	w.WriteHeader(http.StatusNoContent)
}

// lapseRecoveries returns to active the hosts whose recovery has nothing
// left to wait for, and puts each return on the trail.
func (s *Server) lapseRecoveries(ctx context.Context, actor string) {
	lapsed, err := s.hosts.LapseRecoveries(ctx)
	if err != nil {
		s.log.Error("the lapsed recoveries were not closed", "err", err)
		return
	}
	for _, hostID := range lapsed {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "host.identity.recovery.lapsed", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeSuccess,
			Detail: map[string]any{
				"state": hosts.StateActive, "reason": "the recovery order lapsed without a new certificate",
			},
		})
	}
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
	if host.LifecycleState == hosts.StateRetired || host.LifecycleState == hosts.StateRetiring {
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
	if errors.Is(err, enrollment.ErrRepeated) {
		writeJSON(w, http.StatusOK, orderView{Request: order, ConfigURL: configURL(order.ID)})
		return
	}
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
	// An active host enters recovery: no operation and no secret until the
	// new certificate opens its first session, while the old one may still
	// connect for the overlap. A quarantined host stays quarantined - the
	// quarantine is the stronger "no", and its release is a decision of its
	// own once the identity is back.
	state := host.LifecycleState
	canceled := 0
	if host.LifecycleState == hosts.StateActive {
		canceled, err = s.enterRecovery(r, hostID, reason, principal.Subject)
		if err != nil {
			s.fail(w, err)
			return
		}
		state = hosts.StateRecovery
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.identity.recovery", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"request_id": order.ID, "expires_at": order.ExpiresAt,
			"expected_machine_id": order.ExpectedMachineID,
			"reason":              reason, "revoke_old_immediately": req.RevokeOldImmediately,
			"certificates_revoked": revoked, "state": state, "jobs_canceled": canceled,
		}, evidence),
	})
	writeJSON(w, http.StatusCreated, orderView{Request: order, ConfigURL: configURL(order.ID)})
}

// enterRecovery moves an active host into the recovery state and cancels
// what was queued for it, as a quarantine does: a host whose key is being
// replaced takes no mutation until the new key has proven it works. A host
// that is no longer active when the write lands - a quarantine placed a
// moment earlier - is left as it is: that decision is the stronger one.
func (s *Server) enterRecovery(r *http.Request, hostID, reason, actor string) (int, error) {
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	err = s.hosts.ChangeLifecycleState(r.Context(), tx, hostID, []string{hosts.StateActive},
		hosts.StateRecovery, reason, actor)
	if errors.Is(err, hosts.ErrForbiddenTransition) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	canceled, err := s.jobs.CancelUndelivered(r.Context(), tx, hostID, actor, "host.identity.recovery")
	if err != nil {
		return 0, err
	}
	return canceled, tx.Commit(r.Context())
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

// Installation describes how a new host reaches this panel and where it
// takes its packages from. The installation profile is composed from it;
// the panel knows nothing else about the network around it.
type Installation struct {
	// AdvertisedAddresses are the names and addresses the agents see the
	// control plane under, in order of preference. They are in the server
	// certificate of the gateway, so any other address fails TLS.
	AdvertisedAddresses []string
	// GatewayAddr and EnrollmentAddr are the listen addresses; only their
	// ports matter here.
	GatewayAddr    string
	EnrollmentAddr string
	// PackageRepositoryURL is the base of the signed package repository.
	// Empty means the instructions name a placeholder the operator replaces.
	PackageRepositoryURL string
}

// SetInstallation tells the panel how the hosts reach it.
func (s *Server) SetInstallation(installation Installation) { s.installation = installation }

// SetRelays attaches the relay registry. Without it a host installs only
// directly against the panel.
func (s *Server) SetRelays(store *relays.Store) { s.relays = store }

// The paths and accounts the packages set up on a host. They are part of
// the instructions, so they live next to them rather than in the package
// scripts alone.
const (
	agentConfigPath = "/etc/flotestro/agent.yaml"
	agentCAPath     = "/var/lib/flotestro-agent/ca.pem"
	agentAccount    = "flotestro-agent"
	relayConfigPath = "/etc/flotestro/relay.yaml"
	relayCAPath     = "/var/lib/flotestro-relay/ca.pem"
	relayAccount    = "flotestro-relay"
	// relayPort is the port a relay listens on for the agents of its site.
	// The panel does not know the listen address of a relay; the package
	// configures this one, and a relay on another port advertises it in
	// its name.
	relayPort = "8453"
	// repositoryPlaceholder stands in the commands of an installation
	// without a configured repository.
	repositoryPlaceholder = "https://your-repository.example"
	defaultChannel        = "stable"
)

// installationArchitectures are the architectures the release builds.
var installationArchitectures = []string{"amd64", "arm64"}

// installationProfile is everything a host needs before it holds a token:
// the addresses, the trust, the packages and the commands, per family.
type installationProfile struct {
	Kind         string `json:"kind"`
	Site         string `json:"site"`
	Environment  string `json:"environment"`
	Architecture string `json:"architecture"`
	Channel      string `json:"channel"`
	// ReasonRequired says the order for this placement is refused without
	// a reason: the environment is a production one. A batch token and a
	// relay require one as well, whatever the environment.
	ReasonRequired bool                   `json:"reason_required"`
	Connection     installationConnection `json:"connection"`
	Config         installationFile       `json:"config"`
	CA             installationCA         `json:"ca"`
	Repository     installationRepository `json:"repository"`
	Architectures  []string               `json:"architectures"`
	Families       []installationFamily   `json:"families"`
	// Warnings name what the profile could compose only in part.
	Warnings []string `json:"warnings,omitempty"`
}

// installationConnection is where the host connects: the panel itself or
// the relay of its site.
type installationConnection struct {
	EnrollmentURL string        `json:"enrollment_url"`
	GatewayURLs   []string      `json:"gateway_urls"`
	Relay         *relaySummary `json:"relay,omitempty"`
}

type relaySummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Site string `json:"site"`
}

// installationFile is a file the host is to hold, with the path it goes to.
type installationFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// installationCA is the bootstrap trust of the host. The fingerprint is
// what the operator compares on the host after saving the file.
type installationCA struct {
	Path              string    `json:"path"`
	PEM               string    `json:"pem"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	Subject           string    `json:"subject"`
	NotAfter          time.Time `json:"not_after"`
}

// installationRepository names the package source. Configured says whether
// the address is real or a placeholder to replace.
type installationRepository struct {
	Configured bool   `json:"configured"`
	URL        string `json:"url"`
	KeyURL     string `json:"key_url"`
	Package    string `json:"package"`
}

// installationFamily is the set of commands for one family of
// distributions. The keys of the steps are stable: the screen names them.
type installationFamily struct {
	Key            string                `json:"key"`
	Label          string                `json:"label"`
	PackageManager string                `json:"package_manager"`
	Steps          []installationCommand `json:"steps"`
}

type installationCommand struct {
	Key     string `json:"key"`
	Command string `json:"command"`
}

// The step keys of the installation commands.
const (
	CommandRepository = "repository"
	CommandPackage    = "package"
	CommandConfig     = "config"
	CommandCA         = "ca"
	CommandEnroll     = "enroll"
	CommandStart      = "start"
)

// The reasons an installation profile cannot be composed.
var (
	errNoAdvertisedAddress = errors.New("the control plane advertises no address the agents could " +
		"connect to; set FLOTESTRO_ADVERTISE")
	errRelayUnknown = errors.New("the relay does not exist")
	errRelayRevoked = errors.New("the relay was revoked and mediates no registrations")
	errRelayUnnamed = errors.New("the relay advertises no network name; the agents have no " +
		"address to reach it under")
	errRelaySite        = errors.New("the relay belongs to another site")
	errTrustUnavailable = errors.New("the fleet CA is not available in this installation")
)

// installationProblem answers a profile that could not be composed.
func (s *Server) installationProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errRelayUnknown):
		problem(w, http.StatusNotFound, "relay_not_found", err.Error())
	case errors.Is(err, errRelayRevoked), errors.Is(err, errRelayUnnamed):
		problem(w, http.StatusConflict, "relay_unusable", err.Error())
	case errors.Is(err, errRelaySite):
		problem(w, http.StatusConflict, "relay_site_mismatch", err.Error())
	case errors.Is(err, errNoAdvertisedAddress), errors.Is(err, errTrustUnavailable):
		problem(w, http.StatusServiceUnavailable, "installation_unconfigured", err.Error())
	default:
		s.fail(w, err)
	}
}

// handleInstallationProfile composes what a host of the given placement
// needs: the configuration, the trust, the repository and the commands.
//
// Nothing here is secret. The token is ordered separately and shown once;
// the profile can be read as often as an installation needs, which is why
// it is a read of the placement rather than part of the order.
func (s *Server) handleInstallationProfile(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	site, environment := orderPlacement(query.Get("site"), query.Get("environment"))
	kind := query.Get("kind")
	if kind == "" {
		kind = enrollment.KindAgent
	}
	if kind != enrollment.KindAgent && kind != enrollment.KindRelay {
		problem(w, http.StatusBadRequest, "invalid_kind", "kind is agent or relay")
		return
	}
	// The profile is read where the machine will live, like the order is
	// placed: the addresses and the CA are the same for the whole fleet,
	// but the right to prepare an installation is not.
	scope := authz.Scope{Site: site, Environment: environment}
	if _, ok := s.authorize(w, r, authz.PermHostEnrollRead, scope, "installation_profile", ""); !ok {
		return
	}
	relayID := strings.TrimSpace(query.Get("relay_id"))
	if kind == enrollment.KindRelay && relayID != "" {
		problem(w, http.StatusBadRequest, "relay_through_relay",
			"a relay connects to the panel directly, not through another relay")
		return
	}
	architecture := query.Get("architecture")
	if architecture == "" {
		architecture = installationArchitectures[0]
	}
	if !slices.Contains(installationArchitectures, architecture) {
		problem(w, http.StatusBadRequest, "unsupported_architecture",
			"the release builds "+strings.Join(installationArchitectures, " and "))
		return
	}
	channel, err := installationChannel(query.Get("channel"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_channel", err.Error())
		return
	}

	connection, err := s.installationConnection(r, site, relayID)
	if err != nil {
		s.installationProblem(w, err)
		return
	}
	ca, err := s.installationCA(kind)
	if err != nil {
		s.installationProblem(w, err)
		return
	}
	config := installationFile{
		Path:    agentConfigPath,
		Content: agentConfigText(kind, site, environment, connection),
	}
	if kind == enrollment.KindRelay {
		config.Path = relayConfigPath
	}
	repository := s.installationRepository(kind)

	profile := installationProfile{
		Kind:           kind,
		Site:           site,
		Environment:    environment,
		Architecture:   architecture,
		Channel:        channel,
		ReasonRequired: s.requiresSecondPerson(environment) || kind == enrollment.KindRelay,
		Connection:     connection,
		Config:         config,
		CA:             ca,
		Repository:     repository,
		Architectures:  installationArchitectures,
		Families:       installationFamilies(kind, repository, channel, config, ca),
	}
	if !repository.Configured {
		profile.Warnings = append(profile.Warnings,
			"no package repository is configured (FLOTESTRO_PACKAGE_REPOSITORY_URL); "+
				"the commands name a placeholder to replace")
	}
	if onlyLoopback(s.installation.AdvertisedAddresses) && connection.Relay == nil {
		profile.Warnings = append(profile.Warnings,
			"the panel advertises only the loopback address; "+
				"a host on another machine cannot reach it (FLOTESTRO_ADVERTISE)")
	}
	writeJSON(w, http.StatusOK, profile)
}

// installationChannel guards the repository channel: it goes into a
// shell command and a path, so it is a bare word or nothing.
func installationChannel(value string) (string, error) {
	if value == "" {
		return defaultChannel, nil
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return "", fmt.Errorf("the channel is a bare word: %q is not", value)
		}
	}
	return value, nil
}

// installationConnection settles where a host of the site connects: the
// panel under its advertised addresses, or the relay named by the order.
//
// A relay stands in for both the enrollment and the gateway: it mediates
// the registration and terminates the session afterwards, on one port.
func (s *Server) installationConnection(r *http.Request, site, relayID string) (installationConnection, error) {
	if relayID == "" {
		addresses := s.reachableAddresses()
		if len(addresses) == 0 {
			return installationConnection{}, errNoAdvertisedAddress
		}
		gatewayPort := portOf(s.installation.GatewayAddr, "8443")
		gateways := make([]string, 0, len(addresses))
		for _, address := range addresses {
			gateways = append(gateways, "https://"+net.JoinHostPort(address, gatewayPort))
		}
		return installationConnection{
			EnrollmentURL: "https://" + net.JoinHostPort(addresses[0],
				portOf(s.installation.EnrollmentAddr, "8444")),
			GatewayURLs: gateways,
		}, nil
	}

	if s.relays == nil {
		return installationConnection{}, errRelayUnknown
	}
	if _, err := uuid.Parse(relayID); err != nil {
		return installationConnection{}, errRelayUnknown
	}
	relay, err := s.relays.Get(r.Context(), relayID)
	if errors.Is(err, relays.ErrNotFound) {
		return installationConnection{}, errRelayUnknown
	}
	if err != nil {
		return installationConnection{}, err
	}
	if relay.RevokedAt != nil {
		return installationConnection{}, errRelayRevoked
	}
	// The route is part of the scope: an order of one site does not pass
	// through the relay of another, so a profile that suggested it would
	// describe an installation that cannot succeed.
	if site != "" && relay.Site != site {
		return installationConnection{}, fmt.Errorf("%w: %s", errRelaySite, relay.Site)
	}
	names, err := s.relays.Names(r.Context(), relayID)
	if err != nil && !errors.Is(err, relays.ErrNotFound) {
		return installationConnection{}, err
	}
	urls := make([]string, 0, len(names))
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" {
			urls = append(urls, "https://"+relayAddress(name))
		}
	}
	if len(urls) == 0 {
		return installationConnection{}, errRelayUnnamed
	}
	return installationConnection{
		EnrollmentURL: urls[0], GatewayURLs: urls,
		Relay: &relaySummary{ID: relay.ID, Name: relay.Name, Site: relay.Site},
	}, nil
}

// reachableAddresses are the advertised addresses a host on another
// machine can use. The loopback stays only when nothing else is there:
// then the profile is at least right for a host on the panel's machine,
// and the warning says the rest.
func (s *Server) reachableAddresses() []string {
	var addresses, loopback []string
	for _, address := range s.installation.AdvertisedAddresses {
		address = strings.TrimSpace(address)
		switch {
		case address == "":
		case isLoopback(address):
			loopback = append(loopback, address)
		default:
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return loopback
	}
	return addresses
}

func isLoopback(address string) bool {
	if address == "localhost" {
		return true
	}
	ip := net.ParseIP(address)
	return ip != nil && ip.IsLoopback()
}

func onlyLoopback(addresses []string) bool {
	for _, address := range addresses {
		if address = strings.TrimSpace(address); address != "" && !isLoopback(address) {
			return false
		}
	}
	return true
}

// portOf reads the port of a listen address; the host part says where
// the panel listens, not where the agents connect.
func portOf(listen, fallback string) string {
	if _, port, err := net.SplitHostPort(listen); err == nil && port != "" {
		return port
	}
	return fallback
}

// relayAddress adds the relay port to an advertised name that names none.
func relayAddress(name string) string {
	if _, _, err := net.SplitHostPort(name); err == nil {
		return name
	}
	return net.JoinHostPort(name, relayPort)
}

// installationCA is the trust the host starts with: the whole bundle, so a
// CA prepared for an exchange is already there, and the fingerprint of the
// signing one, which the operator compares on the host.
func (s *Server) installationCA(kind string) (installationCA, error) {
	if s.trust == nil {
		return installationCA{}, errTrustUnavailable
	}
	authorities := s.trust.Authorities()
	if len(authorities) == 0 {
		return installationCA{}, errTrustUnavailable
	}
	active := authorities[0]
	path := agentCAPath
	if kind == enrollment.KindRelay {
		path = relayCAPath
	}
	return installationCA{
		Path: path, PEM: string(s.trust.Bundle()),
		FingerprintSHA256: active.Fingerprint, Subject: active.Subject, NotAfter: active.NotAfter,
	}, nil
}

// installationRepository names the package source of the installation.
func (s *Server) installationRepository(kind string) installationRepository {
	pkg := "flotestro-agent"
	if kind == enrollment.KindRelay {
		pkg = "flotestro-relay"
	}
	base := strings.TrimRight(strings.TrimSpace(s.installation.PackageRepositoryURL), "/")
	repository := installationRepository{Configured: base != "", URL: base, Package: pkg}
	if base == "" {
		repository.URL = repositoryPlaceholder
	}
	repository.KeyURL = repository.URL + "/flotestro-repo.asc"
	return repository
}

// agentConfigText composes the configuration file of an agent or a relay
// for one placement.
//
// Text rather than a marshalled structure, because the file is read by
// people first: the comments say what is not in it and why. The shape is
// the one the packages ship, so a later edit by hand finds what it expects.
func agentConfigText(kind, site, environment string, connection installationConnection) string {
	var b strings.Builder
	gateways := func(indent string) {
		for _, address := range connection.GatewayURLs {
			fmt.Fprintf(&b, "%s- %s\n", indent, yamlString(address))
		}
	}
	if kind == enrollment.KindRelay {
		fmt.Fprintf(&b, "# The Flotestro relay of site %s.\n", yamlString(site))
		b.WriteString("# Composed by the panel. The enrollment token is not here and must not be:\n")
		b.WriteString("# it is a one-time secret, and this file survives package updates.\n")
		b.WriteString("schema_version: 1\n\nrelay:\n")
		b.WriteString("  # The name is the key in the panel's registry: fill in a name unique in\n")
		b.WriteString("  # the fleet. Reinstalling the same name refreshes the entry.\n")
		b.WriteString("  name: \"\"\n")
		fmt.Fprintf(&b, "  site: %s\n", yamlString(site))
		fmt.Fprintf(&b, "  listen: %s\n", yamlString("0.0.0.0:"+relayPort))
		b.WriteString("  # The names or addresses the agents of the site reach this relay under.\n")
		b.WriteString("  # They enter its certificate; fill them in before the registration.\n")
		b.WriteString("  advertised_names: []\n")
		b.WriteString("  state_dir: \"/var/lib/flotestro-relay\"\n")
		b.WriteString("  buffer_max_bytes: 268435456\n\nupstream:\n")
		fmt.Fprintf(&b, "  enrollment_url: %s\n", yamlString(connection.EnrollmentURL))
		b.WriteString("  gateway_urls:\n")
		gateways("    ")
		fmt.Fprintf(&b, "  bootstrap_ca_file: %s\n", yamlString(relayCAPath))
		return b.String()
	}

	fmt.Fprintf(&b, "# The Flotestro agent of a host in site %s, environment %s.\n",
		yamlString(site), yamlString(environment))
	b.WriteString("# Composed by the panel. The enrollment token is not here and must not be:\n")
	b.WriteString("# it is a one-time secret, and this file survives package updates. The\n")
	b.WriteString("# site and the environment come from the order, not from this file.\n")
	b.WriteString("schema_version: 1\n\nconnection:\n")
	fmt.Fprintf(&b, "  enrollment_url: %s\n", yamlString(connection.EnrollmentURL))
	if connection.Relay != nil {
		fmt.Fprintf(&b, "  # Through the relay %s of the site.\n", yamlString(connection.Relay.Name))
	}
	b.WriteString("  gateway_urls:\n")
	gateways("    ")
	fmt.Fprintf(&b, "  bootstrap_ca_file: %s\n", yamlString(agentCAPath))
	b.WriteString("  connect_timeout: \"15s\"\n")
	b.WriteString("  reconnect_min: \"2s\"\n")
	b.WriteString("  reconnect_max: \"2m\"\n\nagent:\n")
	b.WriteString("  state_dir: \"/var/lib/flotestro-agent\"\n")
	b.WriteString("  inventory_interval: \"15m\"\n")
	b.WriteString("  max_concurrent_tasks: 2\n")
	b.WriteString("  # full - a managed host; read_only - a host that is only observed.\n")
	b.WriteString("  mode: \"full\"\n\nhelper:\n")
	b.WriteString("  socket: \"/run/flotestro/helper.sock\"\n")
	return b.String()
}

// yamlString quotes a value for a YAML file. The Go quoting is a subset of
// the YAML double-quoted style, and it keeps an address with a stray
// character from breaking the file.
func yamlString(value string) string {
	return strconv.Quote(value)
}

// installationFamilies composes the commands per distribution family.
//
// The commands put the files on the host with here-documents, so one paste
// carries the content and the operator does not copy a file across a
// terminal by hand. The token appears nowhere: the enrollment step asks
// for it in a hidden prompt.
func installationFamilies(kind string, repository installationRepository, channel string,
	config installationFile, ca installationCA) []installationFamily {
	account, service, enroll := agentAccount, "flotestro-agent.service",
		"sudo -u flotestro-agent flotestro-agentctl enroll"
	if kind == enrollment.KindRelay {
		account, service = relayAccount, "flotestro-relay.service"
		// The relay takes the token from a pipe; the shell reads it without
		// an echo, so that it lands neither in the history nor in the
		// process list.
		enroll = "read -rs -p 'Enrollment token: ' TOKEN; echo; printf '%s' \"$TOKEN\" | " +
			"sudo -u flotestro-relay flotestro-relay enroll; unset TOKEN"
	}
	common := []installationCommand{
		{Key: CommandConfig, Command: fmt.Sprintf(
			"sudo tee %[1]s >/dev/null <<'EOF'\n%[2]sEOF\nsudo chown root:%[3]s %[1]s && sudo chmod 0640 %[1]s",
			config.Path, config.Content, account)},
		{Key: CommandCA, Command: fmt.Sprintf(
			"sudo tee %[1]s >/dev/null <<'EOF'\n%[2]sEOF\n"+
				"sudo chown %[3]s:%[3]s %[1]s && sudo chmod 0644 %[1]s\n"+
				"openssl x509 -in %[1]s -noout -fingerprint -sha256",
			ca.Path, ca.PEM, account)},
		{Key: CommandEnroll, Command: enroll},
		{Key: CommandStart, Command: "sudo systemctl enable --now " + service},
	}
	repo, pkg := repository.URL, repository.Package
	apt := []installationCommand{
		{Key: CommandRepository, Command: "sudo install -d -m 0755 /etc/apt/keyrings\n" +
			"curl -fsS " + repo + "/flotestro-repo.asc | sudo tee /etc/apt/keyrings/flotestro.asc >/dev/null\n" +
			"echo 'deb [signed-by=/etc/apt/keyrings/flotestro.asc] " + repo + "/deb " + channel + " main' | " +
			"sudo tee /etc/apt/sources.list.d/flotestro.list >/dev/null\n" +
			"sudo apt-get update"},
		{Key: CommandPackage, Command: "sudo apt-get install -y " + pkg},
	}
	dnf := []installationCommand{
		{Key: CommandRepository, Command: "sudo rpm --import " + repo + "/flotestro-repo.asc\n" +
			"printf '%s\\n' '[flotestro]' 'name=Flotestro' 'baseurl=" + repo + "/rpm/" + channel + "' " +
			"'enabled=1' 'gpgcheck=1' 'repo_gpgcheck=1' 'gpgkey=" + repo + "/flotestro-repo.asc' | " +
			"sudo tee /etc/yum.repos.d/flotestro.repo >/dev/null"},
		{Key: CommandPackage, Command: "sudo dnf install -y " + pkg},
	}
	pacman := []installationCommand{
		{Key: CommandRepository, Command: "curl -fsS " + repo + "/flotestro-repo.asc | sudo pacman-key --add -\n" +
			"sudo pacman-key --lsign-key \"$(curl -fsS " + repo + "/flotestro-repo.asc | " +
			"gpg --show-keys --with-colons | awk -F: '/^fpr:/ {print $10; exit}')\"\n" +
			"printf '%s\\n' '[flotestro]' 'SigLevel = Required DatabaseRequired' " +
			"'Server = " + repo + "/arch/" + channel + "' | sudo tee -a /etc/pacman.conf >/dev/null\n" +
			"sudo pacman -Sy"},
		{Key: CommandPackage, Command: "sudo pacman -S --noconfirm " + pkg},
	}
	family := func(key, label, manager string, steps []installationCommand) installationFamily {
		return installationFamily{Key: key, Label: label, PackageManager: manager,
			Steps: append(append([]installationCommand{}, steps...), common...)}
	}
	return []installationFamily{
		family("debian", "Debian", "apt", apt),
		family("ubuntu", "Ubuntu", "apt", apt),
		family("rhel", "RHEL / Fedora", "dnf", dnf),
		family("arch", "Arch Linux", "pacman", pacman),
	}
}
