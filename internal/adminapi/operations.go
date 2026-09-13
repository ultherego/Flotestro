package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/secrets"
)

// createOperationRequest describes an operation order for a host.
type createOperationRequest struct {
	Action           string          `json:"action"`
	Payload          json.RawMessage `json:"payload"`
	RequiresApproval *bool           `json:"requires_approval,omitempty"`
	// TargetConfirmation is the hostname typed in by the operator. Required
	// for irreversible operations.
	TargetConfirmation string `json:"target_confirmation,omitempty"`
	// Reason justifies the highest-risk operations and goes to the audit log.
	Reason         string `json:"reason,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	MaxOutputBytes int    `json:"max_output_bytes,omitempty"`
	TTLSeconds     int    `json:"ttl_seconds,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// PinBootID binds the job to the current boot of the host. After a
	// reboot the job is rejected instead of running against a different
	// state.
	PinBootID bool `json:"pin_boot_id,omitempty"`
}

// handleCreateOperation creates an operation plan. A mutation requires
// approval by default; the order itself changes nothing on the host yet.
func (s *Server) handleCreateOperation(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermJobCreate, scope, "host", hostID)
	if !ok {
		return
	}
	actor := principal.Subject

	var request createOperationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}

	action := opspec.ActionType(request.Action)
	if !action.Known() {
		problem(w, http.StatusBadRequest, "unknown_action",
			"unknown operation type; allowed: "+joinActions())
		return
	}

	// Beyond the right to order anything at all, the permission of this
	// particular operation is needed: restarting a service is a different
	// level of trust than reading a log.
	if _, ok := s.authorize(w, r, authz.Permission(action.Permission()), scope, "host", hostID); !ok {
		return
	}

	var payload opspec.Payload
	if len(request.Payload) > 0 {
		if err := json.Unmarshal(request.Payload, &payload); err != nil {
			problem(w, http.StatusBadRequest, "invalid_payload", "the payload is not valid JSON")
			return
		}
	}
	if err := opspec.Validate(action, payload); err != nil {
		problem(w, http.StatusBadRequest, "invalid_payload", err.Error())
		return
	}

	// A host with a broken package database must not receive further
	// package operations until somebody sorts it out.
	if host.PackageDatabaseBroken && blockedByBrokenDatabase(action) {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "job.create", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeDenied,
			Detail:  map[string]any{"reason": "package_database_broken", "action_type": string(action)},
		})
		problem(w, http.StatusConflict, "package_database_broken",
			"the host's package database needs repair; run packages.repair first")
		return
	}

	if host.LifecycleState == "quarantined" {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "job.create", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeDenied, Detail: map[string]any{"reason": "quarantined"},
		})
		problem(w, http.StatusConflict, "host_quarantined", "the host is quarantined")
		return
	}

	// The host capability is checked at planning time already, so as not to
	// queue an operation this host will never perform.
	if capability := action.RequiredCapability(); !hostHasCapability(host, capability) {
		problem(w, http.StatusConflict, "capability_missing",
			"the host lacks capability "+capability)
		return
	}

	// A highest-risk operation requires fresh authentication: one that can
	// cut off access to the host or wipe data must not go from an hour-old
	// session.
	var stepUpProof map[string]any
	if action.RequiresFreshAuth() {
		proof, ok := s.requireStepUp(w, r, principal, request.Reason,
			string(action), "host", hostID)
		if !ok {
			return
		}
		stepUpProof = proof
	}

	// A destructive operation requires typing in the target name. A click is
	// not a sufficient decision for a change that cannot be undone - and the
	// host list tends to be long and alike.
	if action.RequiresTargetConfirmation() && request.TargetConfirmation != host.Hostname {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "job.create", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": "target_confirmation_mismatch", "action": string(action),
			},
		})
		problem(w, http.StatusBadRequest, "target_confirmation_required",
			"this operation is irreversible; repeat the hostname in target_confirmation")
		return
	}

	// A rollback to an earlier file version carries only the digest: the
	// content is attached here, so that the plan and what reaches the host
	// are the same thing. An order with an empty file and a version digest
	// would write emptiness.
	if action == opspec.ActionFileRollback && payload.File != nil {
		content, err := s.files.Content(r.Context(), payload.File.VersionSHA256)
		if err != nil {
			problem(w, http.StatusBadRequest, "version_not_found",
				"no stored version with that checksum")
			return
		}
		payload.File.Content = string(content)
		// The version digest was a way of pointing at the content, not part
		// of the order: once the content is in, the payload describes the
		// same thing as an ordinary write. Left in the payload it would not
		// reach the agent, because the job envelope does not carry it - and
		// the plan hash would stop matching.
		payload.File.VersionSHA256 = ""
	}

	// The secret named in the order must exist and be issuable. Otherwise
	// the job would wait for approval, go to the host and only fail there -
	// and the operator would learn about the typo minutes later.
	for _, reference := range payload.Secrets() {
		if s.secrets == nil {
			problem(w, http.StatusServiceUnavailable, "secrets_disabled",
				"this installation has no secret store")
			return
		}
		secret, err := s.secrets.Secret(r.Context(), reference.Name)
		if errors.Is(err, secrets.ErrNotFound) {
			problem(w, http.StatusBadRequest, "secret_not_found",
				"no secret named "+reference.Name)
			return
		}
		if err != nil {
			s.fail(w, err)
			return
		}
		if !secret.Issuable() {
			problem(w, http.StatusConflict, "secret_unavailable",
				"secret "+reference.Name+" has no version that can be issued")
			return
		}
		if reference.Version > secret.CurrentVersion {
			problem(w, http.StatusBadRequest, "secret_version_not_found",
				"secret "+reference.Name+" has no such version")
			return
		}
	}

	requiresApproval := action.Mutating()
	if request.RequiresApproval != nil {
		requiresApproval = *request.RequiresApproval
	}

	preconditions := jobs.Preconditions{
		OSFamily:             host.OSFamily,
		RequiredCapabilities: []string{action.RequiredCapability()},
	}
	if request.PinBootID {
		preconditions.ExpectedBootID = host.BootID
	}

	tx, err := s.jobs.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	job, err := s.jobs.Create(r.Context(), tx, jobs.Spec{
		HostID:           hostID,
		Action:           action,
		Payload:          payload,
		IdempotencyKey:   idempotencyKeyOf(r, request.IdempotencyKey),
		RequiresApproval: requiresApproval,
		TimeoutSeconds:   request.TimeoutSeconds,
		MaxOutputBytes:   request.MaxOutputBytes,
		TTL:              time.Duration(request.TTLSeconds) * time.Second,
		CreatedBy:        actor,
		RequestID:        requestIDOf(r),
		Preconditions:    preconditions,
	})
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_operation", err.Error())
		return
	}

	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor,
		Action: "job.create", TargetType: "job", TargetID: job.ID,
		RequestID: job.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"host_id": hostID, "action_type": job.ActionType,
			"payload_hash": job.PayloadHash, "requires_approval": job.RequiresApproval,
			"step_up": stepUpProof,
			"state":   string(job.State),
		},
	}); err != nil {
		s.fail(w, err)
		return
	}
	// The content is saved right now, so that the history and the rollback
	// have the bytes the operator approved. The desired state is recorded
	// only by the gateway, after a successful operation: the panel must not
	// claim to manage a file the host rejected.
	// A file from a secret leaves neither the content nor its digest in the
	// panel: the value exists only in the store and briefly on the host.
	if payload.File != nil && payload.File.ContentSecret.Empty() &&
		(action == opspec.ActionFileEnsure || action == opspec.ActionFileRollback) {
		if _, err := s.files.SaveVersion(r.Context(), tx, []byte(payload.File.Content)); err != nil {
			s.fail(w, err)
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, job)
}

func (s *Server) handleApproveJob(w http.ResponseWriter, r *http.Request) {
	s.transitionJob(w, r, "approve")
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	s.transitionJob(w, r, "cancel")
}

type transitionRequest struct {
	Reason string `json:"reason,omitempty"`
	// PayloadHash lets the approver confirm that they approve exactly the
	// plan they saw. A mismatch means a swap between viewing and approving.
	PayloadHash string `json:"payload_hash,omitempty"`
}

func (s *Server) transitionJob(w http.ResponseWriter, r *http.Request, operation string) {
	jobID := r.PathValue("id")

	var request transitionRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
			problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
			return
		}
	}

	current, err := s.jobs.Get(r.Context(), jobID)
	if errors.Is(err, jobs.ErrNotFound) {
		problem(w, http.StatusNotFound, "job_not_found", "no such job")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	scope := s.jobScope(r, current.HostID)
	permission := authz.PermJobApprove
	if operation != "approve" {
		permission = authz.PermJobCancel
	}
	principal, ok := s.authorize(w, r, permission, scope, "job", jobID)
	if !ok {
		return
	}
	actor := principal.Subject

	// The second-person rule: in a production environment the requester
	// cannot approve their own change. Role separation is not enough, because
	// one person may hold both roles.
	if operation == "approve" && s.requiresSecondPerson(scope.Environment) && current.CreatedBy == actor {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "job.approve", TargetType: "job", TargetID: jobID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": "self_approval", "environment": scope.Environment,
				"created_by": current.CreatedBy,
			},
		})
		problem(w, http.StatusForbidden, "self_approval",
			"in environment "+scope.Environment+" changes require approval by a second person")
		return
	}

	if operation == "approve" && request.PayloadHash != "" && request.PayloadHash != current.PayloadHash {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "job.approve", TargetType: "job", TargetID: jobID,
			Outcome: audit.OutcomeDenied,
			Detail:  map[string]any{"reason": "payload_hash_mismatch", "expected": current.PayloadHash},
		})
		problem(w, http.StatusConflict, "payload_hash_mismatch",
			"the plan changed since you reviewed it")
		return
	}

	tx, err := s.jobs.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var (
		job    *jobs.Job
		action string
	)
	switch operation {
	case "approve":
		action = "job.approve"
		job, err = s.jobs.Approve(r.Context(), tx, jobID, actor, request.Reason)
	default:
		action = "job.cancel"
		job, err = s.jobs.Cancel(r.Context(), tx, jobID, actor, request.Reason)
	}
	if errors.Is(err, jobs.ErrConflict) {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: action, TargetType: "job", TargetID: jobID,
			Outcome: audit.OutcomeDenied,
			Detail:  map[string]any{"reason": "invalid_state", "state": string(current.State)},
		})
		problem(w, http.StatusConflict, "invalid_state",
			"operation not allowed in state "+string(current.State))
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor,
		Action: action, TargetType: "job", TargetID: jobID,
		RequestID: job.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"host_id": job.HostID, "action_type": job.ActionType,
			"payload_hash": job.PayloadHash, "state": string(job.State),
			"reason": request.Reason,
			// The audit trail also carries which of the required approvals
			// this is: for a destructive operation the first approval starts
			// nothing yet, and that has to be visible after the fact.
			"approvals": job.CollectedApprovals, "required_approvals": job.RequiredApprovals,
		},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}

	// A cancellation recorded in the database does not stop the work on the
	// host. An operation already delivered keeps going - a log preview would
	// hold the process for its whole timeout even though nobody is watching
	// any more. So the interrupt request also goes to the agent; the agent
	// interrupts what can be interrupted safely and notes the rest.
	if operation == "cancel" {
		s.requestInterrupt(r.Context(), job)
	}

	writeJSON(w, http.StatusOK, job)
}

// requiresSecondPerson says whether the environment requires approval by a
// person other than the requester.
func (s *Server) requiresSecondPerson(environment string) bool {
	return s.productionEnvironments[environment]
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermJobRead, "job")
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	// The database narrows the list: checking the scope after fetching meant
	// a host query for every job separately.
	scopes := principal.ScopesFor(authz.PermJobRead)
	filter := jobs.ListFilter{
		HostID: r.URL.Query().Get("host_id"),
		State:  r.URL.Query().Get("state"),
		Limit:  limit,
	}
	for _, scope := range scopes {
		filter.Scopes = append(filter.Scopes, jobs.Scope{Site: scope.Site, Environment: scope.Environment})
	}
	visible, err := s.jobs.List(r.Context(), filter)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": visible, "count": len(visible)})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	job, err := s.jobs.Get(r.Context(), jobID)
	if errors.Is(err, jobs.ErrNotFound) {
		problem(w, http.StatusNotFound, "job_not_found", "no such job")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if _, ok := s.authorize(w, r, authz.PermJobRead, s.jobScope(r, job.HostID), "job", jobID); !ok {
		return
	}
	// The view of a single job also carries the people who approved it: for
	// an operation requiring two approvals the question "who are we still
	// waiting for" is what the operator comes here for.
	if approvals, err := s.jobs.Approvals(r.Context(), jobID); err == nil {
		job.Approvals = approvals
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleJobAttempts(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	job, err := s.jobs.Get(r.Context(), jobID)
	if errors.Is(err, jobs.ErrNotFound) {
		problem(w, http.StatusNotFound, "job_not_found", "no such job")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if _, ok := s.authorize(w, r, authz.PermJobRead, s.jobScope(r, job.HostID), "job", jobID); !ok {
		return
	}
	attempts, err := s.jobs.Attempts(r.Context(), jobID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if attempts == nil {
		attempts = []jobs.Attempt{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": attempts, "count": len(attempts)})
}

// handleListActions describes the catalogue of operations the control plane
// supports.
func (s *Server) handleListActions(w http.ResponseWriter, r *http.Request) {
	if principal := authz.FromContext(r.Context()); !principal.Authenticated() {
		w.Header().Set("WWW-Authenticate", `Bearer realm="flotestro"`)
		problem(w, http.StatusUnauthorized, "unauthenticated", "no valid token")
		return
	}
	type actionInfo struct {
		Action             string `json:"action"`
		Mutating           bool   `json:"mutating"`
		RequiredCapability string `json:"required_capability"`
		Permission         string `json:"permission"`
		DefaultTimeout     int    `json:"default_timeout_seconds"`
		Risk               string `json:"risk"`
		LockClass          string `json:"lock_class,omitempty"`
		// CampaignMode says what the operation is with respect to the fleet,
		// and CampaignReady - what the panel can really carry out today. These
		// are two different pieces of information: the wizard shows only the
		// latter and explains a refusal with the former.
		CampaignMode  string `json:"campaign_mode"`
		CampaignReady bool   `json:"campaign_ready"`
		// CampaignRefusal carries the reason the operation cannot be ordered
		// in bulk. A refusal without a reason looks in the interface like a
		// missing feature, while it is often a boundary drawn deliberately.
		CampaignRefusal string `json:"campaign_refusal,omitempty"`
		// PayloadTemplate is the example payload the wizard starts from for an
		// operation without a form of its own; NeedsMaterial says the template
		// holds a placeholder for certificate material the operator supplies.
		PayloadTemplate *opspec.Payload `json:"payload_template,omitempty"`
		NeedsMaterial   bool            `json:"needs_material,omitempty"`
	}
	items := make([]actionInfo, 0)
	for _, action := range opspec.AllActions() {
		exclusion := opspec.CampaignExclusionReason(action)
		ready := exclusion == "" && opspec.ExecutableMode(action)
		reason := exclusion
		if reason == "" && !ready {
			reason = campaignModeRefusal(action)
		}
		var template *opspec.Payload
		if example, ok := opspec.PayloadTemplate(action); ok && ready {
			template = &example
		}
		items = append(items, actionInfo{
			PayloadTemplate:    template,
			NeedsMaterial:      opspec.TemplateNeedsMaterial(action),
			Action:             string(action),
			Mutating:           action.Mutating(),
			RequiredCapability: action.RequiredCapability(),
			Permission:         action.Permission(),
			DefaultTimeout:     action.DefaultTimeout(),
			Risk:               string(action.Risk()),
			LockClass:          action.LockClass(),
			CampaignMode:       string(action.CampaignMode()),
			CampaignReady:      ready,
			CampaignRefusal:    reason,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "version": opspec.ActionVersion})
}

// hostHasCapability resolves the operation requirement against the host's
// adapter registry. The decision belongs to the registry, not to this file:
// the operation states a logical requirement, the host says which adapters
// it has.
func hostHasCapability(host *hosts.Host, capability string) bool {
	return host.Capabilities.Satisfies(capability)
}

func joinActions() string {
	result := ""
	for i, action := range opspec.AllActions() {
		if i > 0 {
			result += ", "
		}
		result += string(action)
	}
	return result
}

func requestIDOf(r *http.Request) string {
	return r.Header.Get("X-Request-Id")
}

// idempotencyKeyOf reads the key a caller repeats an order with: the
// Idempotency-Key header the document names, or the body field for
// callers that prefer it. The header wins when both are given.
func idempotencyKeyOf(r *http.Request, fromBody string) string {
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		return key
	}
	return strings.TrimSpace(fromBody)
}

// blockedByBrokenDatabase says which package operations make no sense on a
// host with a broken package database.
//
// Repair and plan are excluded from this, and that is not an exception for
// convenience: repair is the only way out of this state, so blocking it would
// lock the host in a loop with no exit from the panel. Plan changes nothing
// and is needed most on a blocked host, because it shows what blocks.
func blockedByBrokenDatabase(action opspec.ActionType) bool {
	switch action {
	case opspec.ActionPackageRepair, opspec.ActionPackagePlan:
		return false
	}
	return strings.HasPrefix(string(action), "packages.")
}

// requestInterrupt sends the agent a request to interrupt the running attempt.
//
// A missing session is not an error: the host may be offline, and the job is
// already cancelled in the database anyway and will not be delivered again.
func (s *Server) requestInterrupt(ctx context.Context, job *jobs.Job) {
	attemptID, err := s.jobs.LastAttempt(ctx, job.ID)
	if err != nil || attemptID == "" {
		return
	}
	if _, err := s.registry.Dispatch(job.HostID, &agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_CancelTask{
			CancelTask: &agentv1.CancelTask{
				TaskId: attemptID,
				Reason: "operation cancelled from the panel",
			},
		},
	}, 5*time.Second); err != nil {
		s.log.Debug("interrupt request not sent",
			"job_id", job.ID, "host_id", job.HostID, "err", err)
	}
}
