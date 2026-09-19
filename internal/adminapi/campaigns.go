package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/campaigns"
	managedfiles "github.com/ultherego/flotestro/internal/files"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/selector"
)

type createCampaignRequest struct {
	Name    string          `json:"name"`
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload"`
	// Selector is recorded as given; the typed expression, when present, decides
	// alone.
	Selector campaigns.Selector `json:"selector"`

	CanarySize               *int       `json:"canary_size,omitempty"`
	WaveSize                 *int       `json:"wave_size,omitempty"`
	MaxConcurrent            *int       `json:"max_concurrent,omitempty"`
	FailureThresholdPercent  *int       `json:"failure_threshold_percent,omitempty"`
	FailureThresholdAbsolute *int       `json:"failure_threshold_absolute,omitempty"`
	MaintenanceStart         *time.Time `json:"maintenance_start,omitempty"`
	MaintenanceEnd           *time.Time `json:"maintenance_end,omitempty"`
	RebootPolicy             string     `json:"reboot_policy,omitempty"`
	HealthCheckUnits         []string   `json:"health_check_units,omitempty"`
	JobTimeoutSeconds        *int       `json:"job_timeout_seconds,omitempty"`
	// RebootTimeoutSeconds bounds the wait for a host to come back after the
	// reboot the campaign ordered; absent or zero means the default of fifteen
	// minutes.
	RebootTimeoutSeconds *int  `json:"reboot_timeout_seconds,omitempty"`
	RequiresApproval     *bool `json:"requires_approval,omitempty"`
	// OfflinePolicy overrides what the operation declares for a host that is not
	// connected when its turn comes.
	OfflinePolicy string `json:"offline_policy,omitempty"`
	// DeadlineMinutes bounds the wait for offline hosts, counted from the
	// creation; the default is a day.
	DeadlineMinutes *int `json:"deadline_minutes,omitempty"`
	// ManualGate stops the campaign after the canary until somebody
	// advances it into the waves.
	ManualGate *bool `json:"manual_gate,omitempty"`
	// ConnectivityLostAbsolute pauses the campaign once that many hosts
	// lost their session while their task ran; zero disables the check.
	ConnectivityLostAbsolute *int `json:"connectivity_lost_absolute,omitempty"`
	// Reason justifies the highest-risk campaigns and goes to the audit log.
	Reason string `json:"reason,omitempty"`
	// IdempotencyKey lets a caller that lost the answer ask again without a
	// second campaign; the Idempotency-Key header does the same.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// PreviewID names the preview this order was placed from, and PreviewDigest
	// is the fingerprint the preview answered with.
	PreviewID     string `json:"preview_id,omitempty"`
	PreviewDigest string `json:"preview_digest,omitempty"`
	// CompensatesCampaignID names a finished campaign this one undoes.
	CompensatesCampaignID string `json:"compensates_campaign_id,omitempty"`
}

// campaignModeRefusal translates a refusal into a sentence the operator knows
// what to do next from.
func campaignModeRefusal(action opspec.ActionType) string {
	switch action.CampaignMode() {
	case opspec.CampaignPerHostPlan:
		return "this operation computes a different plan on every host, " +
			"and a campaign cannot yet approve a set of per-host plans; run it host by host"
	case opspec.CampaignSpecialized:
		return "this operation needs its own multi-step sequence, " +
			"which the campaign engine does not run yet; run it host by host"
	default:
		return "this operation is not available for campaigns; run it host by host"
	}
}

// The ceilings of a campaign's parallelism. A wave larger than this is
// several waves; more hosts at once than this is not a rollout.
const (
	maxWaveSize            = 500
	maxCampaignConcurrency = 200
)

// handleCreateCampaign plans a campaign. The selector is immediately turned
// into an immutable host snapshot; the creation itself changes nothing.
func (s *Server) handleCreateCampaign(w http.ResponseWriter, r *http.Request) {
	// Whoever asks must at least be somebody who may create campaigns somewhere,
	// before the selector is read: the answers about the snapshot - how many
	// hosts, in what state, which groups exist - are facts about the fleet, not.
	if _, ok := s.authorizeCollection(w, r, authz.PermCampaignCreate, "campaign"); !ok {
		return
	}
	var request createCampaignRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	s.orderCampaign(w, r, request, "", false)
}

// orderCampaign carries an order through every check to the record: the
// operation and its bulk mode, the payload, the selector, the per-host
// permissions, the fresh authentication and the audit event.
func (s *Server) orderCampaign(w http.ResponseWriter, r *http.Request, request createCampaignRequest,
	retriesID string, unattended bool) {
	action := opspec.ActionType(request.Action)
	if !action.Known() || !action.Mutating() {
		problem(w, http.StatusBadRequest, "unknown_action",
			"a campaign requires an operation that changes host state")
		return
	}
	// An operation that requires typing the target name does not run in bulk.
	if action.RequiresTargetConfirmation() && !opspec.PanelPlanned(action) {
		problem(w, http.StatusBadRequest, "not_a_campaign_action",
			"this operation is irreversible and needs its target named; run it host by host")
		return
	}
	// There are operations that must not be done in bulk at all - not because the
	// panel cannot, but because their effect requires the operator's presence at
	// every host separately.
	if reason := opspec.CampaignExclusionReason(action); reason != "" {
		problem(w, http.StatusBadRequest, "not_a_campaign_action", reason)
		return
	}
	// The bulk mode is a declaration of the operation, not a conclusion from its
	// risk.
	if !opspec.ExecutableMode(action) {
		problem(w, http.StatusBadRequest, "campaign_mode_unsupported",
			campaignModeRefusal(action))
		return
	}
	// The offline policy is a property of the operation the campaign may tighten
	// and never loosen.
	offlinePolicy, err := opspec.ResolveOfflinePolicy(action, opspec.OfflinePolicy(request.OfflinePolicy))
	if errors.Is(err, opspec.ErrOfflinePolicyLoosened) {
		problem(w, http.StatusBadRequest, "offline_policy_loosened", err.Error())
		return
	}
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_offline_policy", err.Error())
		return
	}

	var payload opspec.Payload
	if len(request.Payload) > 0 {
		if err := json.Unmarshal(request.Payload, &payload); err != nil {
			problem(w, http.StatusBadRequest, "invalid_payload", "the payload is not valid JSON")
			return
		}
	}
	// A campaign order is validated differently than an operation on one host:
	// there is no plan fingerprint yet, because the plan is made on the hosts.
	if err := opspec.ValidateCampaignRequest(action, payload); err != nil {
		problem(w, http.StatusBadRequest, opspec.RefusalCode(err), err.Error())
		return
	}
	// The per-host part of an order the panel splits itself: a rename names every
	// host's new name in the mapping, and the typed payload does not carry it.
	if err := opspec.ValidateCampaignMapping(action, request.Payload); err != nil {
		problem(w, http.StatusBadRequest, "invalid_mapping", err.Error())
		return
	}
	// A rollback names a version by its digest, as on one host: the content is
	// attached here when the panel holds a copy, so the plans, the consent and
	// what reaches the hosts are the same thing.
	if action == opspec.ActionFileRollback && payload.File != nil && payload.File.VersionSHA256 != "" {
		content, err := s.files.Content(r.Context(), payload.File.VersionSHA256)
		switch {
		case err == nil:
			payload.File.Content = string(content)
		case errors.Is(err, managedfiles.ErrNotFound):
		default:
			s.fail(w, err)
			return
		}
		resolved, err := json.Marshal(payload)
		if err != nil {
			s.fail(w, err)
			return
		}
		request.Payload = resolved
	}

	principal := authz.FromContext(r.Context())
	// The operation's permission has to be held somewhere before the fleet is
	// resolved by it: a caller without it anywhere resolves nobody, and "no
	// targets" would be the wrong answer to give them.
	if _, ok := s.authorizeCollection(w, r, orderPermission(action), "campaign"); !ok {
		return
	}
	chosen, ok := s.checkSelector(w, request.Selector)
	if !ok {
		return
	}
	// A compensation is checked before the selector is resolved: the original
	// decides which hosts may be named at all, and an order that names none takes
	// the hosts the original changed.
	compensation, ok := s.checkCompensation(w, r, request.CompensatesCampaignID, action, &chosen)
	if !ok {
		return
	}
	// The resolver cuts the fleet to the scopes of the operation's permission:
	// the preview ran the same query, so what the operator saw counted is what
	// the order carries.
	candidates, ok := s.materialize(w, r, principal, orderPermission(action), chosen)
	if !ok {
		return
	}
	if len(candidates) == 0 {
		problem(w, http.StatusBadRequest, "no_targets", "the selector matched no hosts")
		return
	}
	if compensation != nil {
		if !compensation.covers(w, candidates, action) {
			return
		}
	}

	// The qualification decides which hosts really move.
	kept, excluded := excludeHosts(candidates, chosen, principal.Subject)
	assessment := assessCandidates(kept, action, s.activeConflicts(r.Context()), time.Now().UTC())
	assessment.Closed = append(assessment.Closed, excluded...)
	if len(assessment.Ready) == 0 {
		problem(w, http.StatusBadRequest, "no_eligible_targets",
			"no matched host can run this operation: "+describeExclusions(assessment.Exclusions()))
		return
	}

	// There are changes that are correct only together: withdrawing an authority
	// on part of the fleet leaves hosts the rest stops recognising.
	if reason := opspec.FullCoverageReason(action); reason != "" {
		if uncertain := assessment.Uncertain(); len(uncertain) > 0 {
			problem(w, http.StatusBadRequest, "incomplete_coverage",
				reason+"; "+describeExclusions(uncertain))
			return
		}
	}

	// The permission is checked for every host of the snapshot.
	for _, host := range candidates {
		scope := hosts.ScopeOf(&host)
		if _, ok := s.authorize(w, r, authz.PermCampaignCreate, scope, "host", host.ID); !ok {
			return
		}
		if _, ok := s.authorize(w, r, authz.Permission(action.Permission()), scope, "host", host.ID); !ok {
			return
		}
		// What the payload asks for beyond the operation - root, an
		// unchecked write - is checked per host too.
		if _, ok := s.authorizePayload(w, r, action, payload, scope, "host", host.ID); !ok {
			return
		}
	}

	// The order is held to the preview it was placed from: the hosts just
	// resolved have to be the hosts the operator was shown, under the rights they
	// had then.
	if !s.checkPreviewToken(w, r, request, principal, orderPermission(action), action,
		chosen, assessment.Ready, unattended) {
		return
	}

	// A campaign must not be a way around the single-host gate.
	var stepUpEvidence map[string]any
	if opspec.PayloadRequiresFreshAuth(action, payload) {
		evidence, ok := s.requireStepUp(w, r, principal, request.Reason,
			"campaign.create", "campaign", "")
		if !ok {
			return
		}
		stepUpEvidence = evidence
	}

	// The pace an operation is carried at when the order names none: the
	// registry knows which operations the document paces differently.
	paceWave, paceConcurrent := opspec.CampaignPace(action)

	spec := campaigns.Spec{
		Name:       request.Name,
		ActionType: string(action),
		Payload:    request.Payload,
		Selector:   chosen,
		CanarySize: valueOrDefault(request.CanarySize, 1),
		// The concurrency is bounded whatever the request says: budgets are the
		// safety net of the fleet, and an installation without them must not be one
		// request away from restarting everything at once.
		WaveSize:                 min(valueOr(request.WaveSize, paceWave), maxWaveSize),
		MaxConcurrent:            min(valueOr(request.MaxConcurrent, paceConcurrent), maxCampaignConcurrency),
		FailureThresholdPercent:  valueOrDefault(request.FailureThresholdPercent, 20),
		FailureThresholdAbsolute: valueOr(request.FailureThresholdAbsolute, 0),
		MaintenanceStart:         request.MaintenanceStart,
		MaintenanceEnd:           request.MaintenanceEnd,
		RebootPolicy:             campaigns.RebootPolicy(orDefault(request.RebootPolicy, "never")),
		HealthCheckUnits:         request.HealthCheckUnits,
		JobTimeoutSeconds:        valueOr(request.JobTimeoutSeconds, action.DefaultTimeout()),
		RebootTimeoutSeconds:     valueAsGiven(request.RebootTimeoutSeconds),
		// A campaign is always approved: the consent binds the fingerprint
		// of what runs on many hosts, and a request cannot waive it.
		RequiresApproval:         true,
		OfflinePolicy:            offlinePolicy,
		DeadlineMinutes:          valueOr(request.DeadlineMinutes, int(campaigns.DefaultDeadline/time.Minute)),
		ManualGate:               request.ManualGate != nil && *request.ManualGate,
		ConnectivityLostAbsolute: valueOr(request.ConnectivityLostAbsolute, 0),
		CreatedBy:                principal.Subject,
		RequestID:                requestIDOf(r),
		IdempotencyKey:           idempotencyKeyOf(r, request.IdempotencyKey),
		CompensatesCampaignID:    request.CompensatesCampaignID,
		RetriesCampaignID:        retriesID,
	}

	targets := assessment.Targets()

	tx, err := s.campaigns.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	campaign, err := s.campaigns.Create(r.Context(), tx, spec, targets)
	if errors.Is(err, campaigns.ErrRepeated) {
		// A repeat of an order already carried out: the existing campaign
		// comes back, and nothing is recorded a second time.
		_ = tx.Rollback(r.Context())
		writeJSON(w, http.StatusOK, campaign)
		return
	}
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_campaign", err.Error())
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign.create", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"name": campaign.Name, "action_type": campaign.ActionType,
			"campaign_mode": string(action.CampaignMode()),
			"targets":       len(targets), "eligible": len(assessment.Ready),
			"excluded": assessment.Exclusions(), "notes": assessment.Notes,
			"selector": chosen.Expression.Describe(), "exclude_reason": chosen.ExcludeReason,
			"canary_size": campaign.CanarySize,
			"wave_size":   campaign.WaveSize, "reboot_policy": string(campaign.RebootPolicy),
			"offline_policy": string(campaign.OfflinePolicy), "deadline_at": campaign.DeadlineAt,
			"manual_gate":                campaign.ManualGate,
			"connectivity_lost_absolute": campaign.ConnectivityLostAbsolute,
			"reboot_timeout_seconds":     campaign.RebootTimeoutSeconds,
			"approval_fingerprint":       campaign.ApprovalFingerprint,
			"compensates_campaign_id":    campaign.CompensatesCampaignID,
			"retries_campaign_id":        campaign.RetriesCampaignID,
		}, stepUpEvidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	// The spent preview names the campaign it created.
	if request.PreviewID != "" && s.campaigns != nil {
		if err := s.campaigns.AttachPreview(r.Context(), request.PreviewID, campaign.ID); err != nil {
			s.log.Warn("the preview of a campaign was not linked to it",
				"preview_id", request.PreviewID, "campaign_id", campaign.ID, "error", err)
		}
	}
	writeJSON(w, http.StatusCreated, campaign)
}

// retryCampaignRequest is the order to run a finished campaign again on
// the hosts that did not reach the desired state.
type retryCampaignRequest struct {
	// Reason justifies the retry and goes to the audit log; a second go
	// at a change that failed is a decision, and the record says why.
	Reason string `json:"reason"`
	// IncludeUnknown takes the hosts that ended without a result as well.
	IncludeUnknown bool `json:"include_unknown"`
}

// handleRetryCampaign orders a new campaign with the same order as a finished
// one, on exactly the hosts that failed - and the unknown ones when asked.
func (s *Server) handleRetryCampaign(w http.ResponseWriter, r *http.Request) {
	original, ok := s.campaignFor(w, r, authz.PermCampaignCreate)
	if !ok {
		return
	}
	var request retryCampaignRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
			problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
			return
		}
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if len([]rune(request.Reason)) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"a retry must state its reason (field reason, min. 8 characters)")
		return
	}
	targets, err := s.campaigns.Targets(r.Context(), original.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	picked, err := campaigns.RetryTargets(*original, targets, request.IncludeUnknown)
	if code := campaigns.RetryCode(err); code != "" {
		problem(w, http.StatusConflict, code, err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	hostIDs := make([]string, 0, len(picked))
	for _, target := range picked {
		hostIDs = append(hostIDs, target.HostID)
	}
	// A retry is not placed from a preview: the hosts are the ones the original
	// campaign settled, read from its own record, and nobody is looking at a
	// fresh count of the fleet.
	s.orderCampaign(w, r, retryOrder(*original, hostIDs, request.Reason), original.ID, true)
}

// retryOrder is the original's order written out again for the hosts given:
// the same operation, payload and rollout policy, named as the retry of the
// original.
func retryOrder(original campaigns.Campaign, hostIDs []string, reason string) createCampaignRequest {
	order := createCampaignRequest{
		Name:                     campaigns.RetryName(original.Name),
		Action:                   original.ActionType,
		Payload:                  original.Payload,
		Selector:                 campaigns.Selector{HostIDs: hostIDs},
		CanarySize:               intPointer(original.CanarySize),
		WaveSize:                 intPointer(original.WaveSize),
		MaxConcurrent:            intPointer(original.MaxConcurrent),
		FailureThresholdPercent:  intPointer(original.FailureThresholdPercent),
		FailureThresholdAbsolute: intPointer(original.FailureThresholdAbsolute),
		RebootPolicy:             string(original.RebootPolicy),
		HealthCheckUnits:         original.HealthCheckUnits,
		JobTimeoutSeconds:        intPointer(original.JobTimeoutSeconds),
		RebootTimeoutSeconds:     intPointer(original.RebootTimeoutSeconds),
		OfflinePolicy:            string(original.OfflinePolicy),
		ManualGate:               &original.ManualGate,
		ConnectivityLostAbsolute: intPointer(original.ConnectivityLostAbsolute),
		Reason:                   reason,
		// A retry of a compensation is still a compensation: the reverse on hosts
		// the compensated campaign changed, linked so the compensate step lands on
		// the original's targets.
		CompensatesCampaignID: original.CompensatesCampaignID,
	}
	if original.MaintenanceEnd == nil || original.MaintenanceEnd.After(time.Now().UTC()) {
		order.MaintenanceStart = original.MaintenanceStart
		order.MaintenanceEnd = original.MaintenanceEnd
	}
	if original.DeadlineAt != nil {
		if minutes := int(original.DeadlineAt.Sub(original.CreatedAt) / time.Minute); minutes > 0 {
			order.DeadlineMinutes = intPointer(minutes)
		}
	}
	return order
}

func intPointer(value int) *int {
	return &value
}

// describeExclusions joins the refusal reasons into one sentence.
func describeExclusions(groups []hostGroup) string {
	description := ""
	for i, group := range groups {
		if i > 0 {
			description += ", "
		}
		description += fmt.Sprintf("%s: %d", group.Reason, group.Count)
	}
	if description == "" {
		return "no reasons to give"
	}
	return description
}

// compensationOrder is a compensation order once checked: the original
// campaign and the hosts it changed, by host identifier.
type compensationOrder struct {
	original *campaigns.Campaign
	changed  []campaigns.Target
}

// checkCompensation reads and checks the campaign an order says it undoes. An
// empty identifier means an ordinary campaign and passes with nil.
func (s *Server) checkCompensation(w http.ResponseWriter, r *http.Request, compensatesID string,
	action opspec.ActionType, chosen *campaigns.Selector) (*compensationOrder, bool) {
	if compensatesID == "" {
		return nil, true
	}
	if _, err := uuid.Parse(compensatesID); err != nil {
		problem(w, http.StatusBadRequest, "invalid_compensates_campaign_id",
			"compensates_campaign_id must be a campaign identifier")
		return nil, false
	}
	original, err := s.campaigns.Get(r.Context(), compensatesID)
	if errors.Is(err, campaigns.ErrNotFound) {
		problem(w, http.StatusBadRequest, "compensated_campaign_not_found",
			"the campaign to compensate, "+compensatesID+", does not exist")
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	scope, err := s.campaignScope(r, original.ID)
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	if _, ok := s.authorize(w, r, authz.PermCampaignRead, scope, "campaign", original.ID); !ok {
		return nil, false
	}
	changed, err := s.campaigns.ChangedTargets(r.Context(), original.ID)
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	// A preview without an operation asks about the compensation itself; it is
	// checked as the declared reverse would be.
	if action == "" {
		action, _ = opspec.ReverseAction(opspec.ActionType(original.ActionType))
	}
	// The rules are checked once here without hosts, so an order refused for its
	// original or its operation is refused before the fleet is read; the hosts
	// are checked once the selector resolved.
	if err := campaigns.CheckCompensation(*original, action, changed, nil); err != nil {
		problem(w, http.StatusBadRequest, campaigns.CompensationCode(err), err.Error())
		return nil, false
	}
	if chosen.Empty() {
		for _, target := range changed {
			chosen.HostIDs = append(chosen.HostIDs, target.HostID)
		}
	}
	return &compensationOrder{original: original, changed: changed}, true
}

// covers checks that every host the selector resolved to is one the original
// changed, and answers the order that names another.
func (c *compensationOrder) covers(w http.ResponseWriter, candidates []hosts.Host, action opspec.ActionType) bool {
	names := make([]string, 0, len(candidates))
	for _, host := range candidates {
		names = append(names, host.ID)
	}
	err := campaigns.CheckCompensation(*c.original, action, c.changed, names)
	if err == nil {
		return true
	}
	reason := err.Error()
	for _, host := range candidates {
		if host.Hostname != "" {
			reason = strings.ReplaceAll(reason, host.ID, host.Hostname+" ("+host.ID+")")
		}
	}
	problem(w, http.StatusBadRequest, campaigns.CompensationCode(err), reason)
	return false
}

// checkSelector validates the selector of an order and answers a request that
// does not hold together.
func (s *Server) checkSelector(w http.ResponseWriter, chosen campaigns.Selector) (campaigns.Selector, bool) {
	if chosen.Expression != nil {
		if err := chosen.Expression.Validate(); err != nil {
			s.selectorProblem(w, err)
			return chosen, false
		}
	}
	chosen.ExcludeReason = strings.TrimSpace(chosen.ExcludeReason)
	exclude := make([]string, 0, len(chosen.Exclude))
	for _, hostID := range chosen.Exclude {
		if hostID = strings.TrimSpace(hostID); hostID != "" {
			exclude = append(exclude, hostID)
		}
	}
	chosen.Exclude = exclude
	// An exclusion without a reason is a hole in the snapshot: the approver
	// sees a host left out and nothing to say why.
	if len(chosen.Exclude) > 0 && chosen.ExcludeReason == "" {
		problem(w, http.StatusBadRequest, "exclude_reason_required",
			"excluding hosts needs a reason; it is what the approver will read next to them")
		return chosen, false
	}
	if len(chosen.Exclude) > maxCampaignSnapshot {
		problem(w, http.StatusBadRequest, "selector_too_broad",
			fmt.Sprintf("the exclusion list names more than %d hosts", maxCampaignSnapshot))
		return chosen, false
	}
	return chosen, true
}

// materialize turns the selector into the host list and answers a selector
// that does not resolve or resolves to too much.
func (s *Server) materialize(w http.ResponseWriter, r *http.Request, principal authz.Principal,
	permission authz.Permission, chosen campaigns.Selector) ([]hosts.Host, bool) {
	candidates, err := s.resolveTargets(r, principal, permission, chosen)
	var invalid *targetsInvalidError
	switch {
	case errors.As(err, &invalid):
		problemWithTargets(w, invalid)
		return nil, false
	case errors.Is(err, ErrSelectorTooBroad):
		problem(w, http.StatusBadRequest, "selector_too_broad", err.Error())
		return nil, false
	case errors.Is(err, selector.ErrCycle), errors.Is(err, selector.ErrUnknownGroup),
		errors.Is(err, selector.ErrInvalid):
		s.selectorProblem(w, err)
		return nil, false
	case err != nil:
		s.fail(w, err)
		return nil, false
	}
	return candidates, true
}

// The reasons an explicitly named host cannot be a target.
const (
	// TargetUnknownHost names an identifier that is no host of the fleet.
	TargetUnknownHost = "unknown_host"
	// TargetOutOfScope names a host the caller has no right over for this
	// operation.
	TargetOutOfScope = "out_of_scope"
	// TargetExcludedAndListed names a host on both the list and the
	// exclusion list: the order does not say what it wants with it.
	TargetExcludedAndListed = "excluded_and_listed"
	// TargetInvalidHostID names an identifier that is not one.
	TargetInvalidHostID = "invalid_host_id"
)

// targetRefusal is one host of an explicit list the order cannot carry.
type targetRefusal struct {
	HostID string `json:"host_id"`
	Reason string `json:"reason"`
}

// targetsInvalidError carries the refusals of an explicit host list.
type targetsInvalidError struct {
	Refusals []targetRefusal
}

func (e *targetsInvalidError) Error() string {
	parts := make([]string, 0, len(e.Refusals))
	for _, refusal := range e.Refusals {
		parts = append(parts, refusal.HostID+": "+refusal.Reason)
	}
	return "the host list names hosts the order cannot carry: " + strings.Join(parts, ", ")
}

// problemWithTargets answers an explicit list the order cannot carry: the
// problem document as always, with the refusals per host next to it.
func problemWithTargets(w http.ResponseWriter, invalid *targetsInvalidError) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":    "about:blank",
		"title":   http.StatusText(http.StatusUnprocessableEntity),
		"status":  http.StatusUnprocessableEntity,
		"code":    "targets_invalid",
		"detail":  invalid.Error(),
		"targets": invalid.Refusals,
	})
}

// resolveTargets turns the selector into a host list, already cut to the
// scopes in which the caller holds the permission the order needs.
func (s *Server) resolveTargets(r *http.Request, principal authz.Principal,
	permission authz.Permission, chosen campaigns.Selector) ([]hosts.Host, error) {
	if len(chosen.HostIDs) > 0 {
		return s.resolveListedHosts(r, orderScopes(principal, permission), chosen)
	}
	filter, err := s.selectorFilter(r, principal, permission, chosen)
	if err != nil {
		return nil, err
	}
	// The selector is read page by page, without a hidden limit: a campaign
	// covering a thousand hosts is meant to mean a thousand hosts, not the first
	// five hundred sorted alphabetically.
	return s.pageHosts(r.Context(), filter)
}

// orderScopes are the scopes the fleet is cut to for an order: those in which
// the caller holds the permission.
func orderScopes(principal authz.Principal, permission authz.Permission) []authz.Scope {
	scopes := principal.ScopesFor(permission)
	if scopes == nil {
		return []authz.Scope{}
	}
	return scopes
}

// selectorFilter is the host query of a selector that is not an explicit list,
// cut to the caller's scopes: the typed expression expanded of its groups when
// there is one, the flat filters otherwise.
func (s *Server) selectorFilter(r *http.Request, principal authz.Principal,
	permission authz.Permission, chosen campaigns.Selector) (hosts.ListFilter, error) {
	scopes := orderScopes(principal, permission)
	if chosen.Expression != nil {
		expanded, err := selector.Expand(r.Context(), chosen.Expression, s.groups)
		if err != nil {
			return hosts.ListFilter{}, err
		}
		return hosts.ListFilter{Expression: expanded, Scopes: scopes}, nil
	}
	return hosts.ListFilter{
		Site:        chosen.Site,
		Environment: chosen.Environment,
		OSFamily:    chosen.OSFamily,
		Scopes:      scopes,
	}, nil
}

// resolveListedHosts reads an explicit host list in strict mode. The hosts
// come back in the order they were named, each once.
func (s *Server) resolveListedHosts(r *http.Request, scopes []authz.Scope,
	chosen campaigns.Selector) ([]hosts.Host, error) {
	var refusals []targetRefusal
	seen := map[string]bool{}
	ids := make([]string, 0, len(chosen.HostIDs))
	for _, hostID := range chosen.HostIDs {
		hostID = strings.TrimSpace(hostID)
		if hostID == "" || seen[hostID] {
			continue
		}
		seen[hostID] = true
		if _, err := uuid.Parse(hostID); err != nil {
			refusals = append(refusals, targetRefusal{HostID: hostID, Reason: TargetInvalidHostID})
			continue
		}
		ids = append(ids, hostID)
	}
	if len(ids) > maxCampaignSnapshot {
		return nil, fmt.Errorf("%w: the host list names more than %d hosts", ErrSelectorTooBroad, maxCampaignSnapshot)
	}
	found, err := s.pageHosts(r.Context(), hosts.ListFilter{IDs: ids, Scopes: scopes})
	if err != nil {
		return nil, err
	}
	byID := make(map[string]hosts.Host, len(found))
	for _, host := range found {
		byID[host.ID] = host
	}
	result := make([]hosts.Host, 0, len(ids))
	for _, hostID := range ids {
		host, inScope := byID[hostID]
		switch {
		case !inScope:
			// The host was not in the narrowed query: either it is not a host at all or
			// it lies outside the caller's scope.
			_, err := s.hosts.Get(r.Context(), hostID)
			if errors.Is(err, hosts.ErrNotFound) {
				refusals = append(refusals, targetRefusal{HostID: hostID, Reason: TargetUnknownHost})
				continue
			}
			if err != nil {
				return nil, err
			}
			refusals = append(refusals, targetRefusal{HostID: hostID, Reason: TargetOutOfScope})
		case chosen.Excluded(hostID):
			refusals = append(refusals, targetRefusal{HostID: hostID, Reason: TargetExcludedAndListed})
		default:
			result = append(result, host)
		}
	}
	if len(refusals) > 0 {
		return nil, &targetsInvalidError{Refusals: refusals}
	}
	return result, nil
}

// orderPermission is the permission the resolver cuts the fleet by: the
// operation's own where there is one, and the right to order a campaign where
// the preview asks only how many hosts a selector covers.
func orderPermission(action opspec.ActionType) authz.Permission {
	if action == "" {
		return authz.PermCampaignCreate
	}
	return authz.Permission(action.Permission())
}

// excludeHosts takes the hosts on the exclusion list out of the candidate
// list.
func excludeHosts(candidates []hosts.Host, chosen campaigns.Selector, actor string) (kept []hosts.Host, closed []closedHost) {
	if len(chosen.Exclude) == 0 {
		return candidates, nil
	}
	kept = make([]hosts.Host, 0, len(candidates))
	for _, host := range candidates {
		if !chosen.Excluded(host.ID) {
			kept = append(kept, host)
			continue
		}
		closed = append(closed, closedHost{
			Host: host, State: campaigns.TargetExcluded, Reason: ReasonExcluded,
			Message: fmt.Sprintf("excluded by %s: %s", actor, chosen.ExcludeReason),
		})
	}
	return kept, closed
}

// maxCampaignSnapshot is the bound of one campaign.
const maxCampaignSnapshot = 10000

// ErrSelectorTooBroad means a selector covering more hosts than one
// campaign is meant to run.
var ErrSelectorTooBroad = errors.New("the selector covers too many hosts")

// handleCampaignPreview answers the question "how many hosts does this
// concern".
func (s *Server) handleCampaignPreview(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermCampaignRead, "campaign")
	if !ok {
		return
	}
	query := r.URL.Query()
	// The host list is read the way the order reads it, so the preview of
	// a list and the order of the same list resolve the same hosts.
	chosen := campaigns.Selector{
		Site:          query.Get("site"),
		Environment:   query.Get("environment"),
		OSFamily:      query.Get("os_family"),
		HostIDs:       query["host_id"],
		Exclude:       query["exclude"],
		ExcludeReason: query.Get("exclude_reason"),
	}
	// The typed selector travels in the query as JSON: the preview is a
	// read, and a read with a body is a read nobody can link to.
	if text := query.Get("expression"); text != "" {
		chosen.Expression = &selector.Expression{}
		if err := json.Unmarshal([]byte(text), chosen.Expression); err != nil {
			problem(w, http.StatusBadRequest, "invalid_selector", "the expression is not valid JSON")
			return
		}
	}
	// The preview shows what the order would do, exclusions included; the
	// reason is not required here, because nothing is recorded yet.
	if chosen.ExcludeReason == "" && len(chosen.Exclude) > 0 {
		chosen.ExcludeReason = "(no reason given yet)"
	}
	if chosen, ok = s.checkSelector(w, chosen); !ok {
		return
	}
	// Without an operation the preview answers only the question "how many hosts
	// does this concern".
	action := opspec.ActionType(query.Get("action"))
	if action != "" && !action.Known() {
		problem(w, http.StatusBadRequest, "unknown_action", "unknown action "+string(action))
		return
	}
	// A preview of an operation is a step of ordering it: the caller has to hold
	// the operation's permission somewhere, the way the order will ask.
	permission := orderPermission(action)
	if _, ok := s.authorizeCollection(w, r, permission, "campaign"); !ok {
		return
	}
	// A compensation previews what the order would do: the same check, the same
	// default host list, so the wizard shows the refusal before the form is
	// filled in rather than after.
	compensation, ok := s.checkCompensation(w, r, query.Get("compensates"), action, &chosen)
	if !ok {
		return
	}

	response := map[string]any{
		"limit":    maxCampaignSnapshot,
		"selector": chosen.Expression.Describe(),
	}
	if compensation != nil {
		response["compensates"] = map[string]any{
			"id": compensation.original.ID, "name": compensation.original.Name,
			"state": compensation.original.State, "changed": len(compensation.changed),
		}
	}

	// Without an operation the answer is a count and a sample, from the same
	// filter the order would page through - in the caller's scopes - but counted
	// in the database, so a selector wider than one campaign may carry is.
	if action == "" && len(chosen.HostIDs) == 0 {
		filter, err := s.selectorFilter(r, principal, permission, chosen)
		if err != nil {
			s.selectorProblem(w, err)
			return
		}
		count, err := s.hosts.Count(r.Context(), filter)
		if err != nil {
			s.fail(w, err)
			return
		}
		sample, err := s.hosts.Page(r.Context(), filter, "", "", previewSampleSize)
		if err != nil {
			s.fail(w, err)
			return
		}
		response["count"] = count
		response["sample"] = hostNames(sample[:min(len(sample), previewSampleSize)])
		writeJSON(w, http.StatusOK, response)
		return
	}

	// The count comes from the same resolver the order runs, in the same scopes:
	// a preview counted differently than the creation would be worse than none.
	candidates, ok := s.materialize(w, r, principal, permission, chosen)
	if !ok {
		return
	}
	response["count"] = len(candidates)
	if action == "" {
		response["sample"] = hostNames(candidates[:min(len(candidates), previewSampleSize)])
		writeJSON(w, http.StatusOK, response)
		return
	}

	// The qualification is computed on the same snapshot that would enter the
	// campaign.
	if compensation != nil && !compensation.covers(w, candidates, action) {
		return
	}
	kept, excluded := excludeHosts(candidates, chosen, principal.Subject)
	assessment := assessCandidates(kept, action, s.activeConflicts(r.Context()), time.Now().UTC())
	assessment.Closed = append(assessment.Closed, excluded...)

	response["sample"] = hostNames(assessment.Ready[:min(len(assessment.Ready), previewSampleSize)])
	response["eligible"] = len(assessment.Ready)
	response["excluded"] = assessment.Exclusions()
	response["notes"] = assessment.Notes
	response["campaign_mode"] = string(action.CampaignMode())
	response["requires_plan"] = opspec.CampaignPlans(action)
	response["distribution"] = distribution(assessment.Ready, action)
	// An order the panel splits host by host needs every ready host in view
	// before the order, not a sample: the mapping names them by identifier, and
	// the wizard shows a host it does not name as ineligible before anything is.
	if opspec.PanelPlanned(action) {
		response["hosts"] = hostEntries(assessment.Ready)
	}
	// What was shown is recorded, so the order placed from this answer can be
	// held to it.
	token, ok := s.issuePreviewToken(w, r, principal, permission, action, chosen, assessment.Ready)
	if !ok {
		return
	}
	for key, value := range token {
		response[key] = value
	}
	writeJSON(w, http.StatusOK, response)
}

// distribution describes what the frozen target snapshot consists of.
func distribution(ready []hosts.Host, action opspec.ActionType) map[string][]hostGroup {
	requirement := action.RequiredCapability()
	by := map[string]map[string]*hostGroup{
		"site": {}, "environment": {}, "os_family": {}, "capability": {},
	}
	order := map[string][]string{}
	addTo := func(dimension, key string, host hosts.Host) {
		if key == "" {
			key = "unknown"
		}
		group, present := by[dimension][key]
		if !present {
			group = &hostGroup{Reason: key}
			by[dimension][key] = group
			order[dimension] = append(order[dimension], key)
		}
		add(group, host)
	}

	for _, host := range ready {
		addTo("site", host.Site, host)
		addTo("environment", host.Environment, host)
		addTo("os_family", host.OSFamily, host)
		// The capability tells the hosts that accept the operation from those that
		// have not reported their adapter registry yet - and the latter go into the
		// campaign and are decided only on the host.
		switch {
		case requirement == "":
			addTo("capability", "no requirements", host)
		case len(host.Capabilities) == 0:
			addTo("capability", "unknown", host)
		default:
			addTo("capability", requirement, host)
		}
	}

	result := map[string][]hostGroup{}
	for dimension, names := range order {
		groups := make([]hostGroup, 0, len(names))
		for _, name := range names {
			groups = append(groups, *by[dimension][name])
		}
		result[dimension] = groups
	}
	return result
}

func hostNames(list []hosts.Host) []string {
	names := make([]string, 0, len(list))
	for _, host := range list {
		names = append(names, host.Hostname)
	}
	return names
}

// hostEntry is a host of the preview named by identifier, for an order
// that has to name every host by itself.
type hostEntry struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

func hostEntries(list []hosts.Host) []hostEntry {
	entries := make([]hostEntry, 0, len(list))
	for _, host := range list {
		entries = append(entries, hostEntry{ID: host.ID, Hostname: host.Hostname})
	}
	return entries
}

// previewSampleSize bounds the sample shown in the preview.
const previewSampleSize = 12

func (s *Server) handleListCampaigns(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermCampaignRead, "campaign")
	if !ok {
		return
	}
	// The list is filtered on the server and read page by page: "the campaigns
	// this operator ordered since Monday" is a question for an index, not for a
	// screen holding the newest fifty rows.
	query := r.URL.Query()
	filter := campaigns.ListFilter{
		State:     strings.TrimSpace(query.Get("state")),
		Action:    strings.TrimSpace(query.Get("action")),
		CreatedBy: strings.TrimSpace(query.Get("requester")),
	}
	if text := strings.TrimSpace(query.Get("since")); text != "" {
		since, err := time.Parse(time.RFC3339, text)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_since", "since must be an RFC 3339 timestamp")
			return
		}
		filter.Since = &since
	}
	filter.Limit, _ = strconv.Atoi(query.Get("limit"))
	if filter.Limit <= 0 || filter.Limit > 200 {
		filter.Limit = 50
	}
	if offset, err := strconv.Atoi(query.Get("offset")); err == nil && offset > 0 {
		filter.Offset = offset
	}
	page, err := s.campaigns.List(r.Context(), filter, campaignScopes(principal))
	if err != nil {
		s.fail(w, err)
		return
	}
	items := page.Items
	if items == nil {
		items = []campaigns.Campaign{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "count": len(items),
		"total": page.Total, "limit": filter.Limit, "offset": filter.Offset,
	})
}

func (s *Server) handleGetCampaign(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, campaign)
}

func (s *Server) handleCampaignTargets(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	// The targets go page by page in the order of the rollout, filtered on the
	// server: a campaign on ten thousand hosts must not become ten thousand rows
	// in the browser, and "the failed ones" is a question the database answers.
	query := r.URL.Query()
	filter := campaigns.TargetFilter{State: query.Get("state"), Search: query.Get("q")}
	if wave, err := strconv.Atoi(query.Get("wave")); err == nil && wave >= 0 {
		filter.Wave, filter.WaveSet = wave, true
	}
	cursor, err := campaigns.ParseTargetCursor(query.Get("cursor"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_cursor", err.Error())
		return
	}
	limit, err := strconv.Atoi(query.Get("limit"))
	if err != nil || limit <= 0 {
		limit = defaultTargetPage
	}
	page, err := s.campaigns.TargetsPage(r.Context(), campaign.ID, filter, cursor, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": page.Items, "count": len(page.Items),
		"total": page.Total, "next_cursor": page.NextCursor,
	})
}

// defaultTargetPage is the page of targets a screen gets without asking.
const defaultTargetPage = 200

// handleCampaignTimeline returns the durable course of a campaign. The report
// says how it ended.
func (s *Server) handleCampaignTimeline(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		limit = 0
	}
	// "after" is the cursor of the trail: the last event identifier the
	// caller already has.
	after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if err != nil || after < 0 {
		after = 0
	}
	course, err := s.campaigns.CourseAfter(r.Context(), campaign.ID, after, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": course, "count": len(course)})
}

// handleCampaignSteps returns the executable steps of the campaign's targets:
// plan, change, reboot, verification and compensation, each with its task, its
// attempts and the reason it did not run.
func (s *Server) handleCampaignSteps(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	query := r.URL.Query()
	cursor, err := campaigns.ParseTargetCursor(query.Get("cursor"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_cursor", err.Error())
		return
	}
	limit, err := strconv.Atoi(query.Get("limit"))
	if err != nil || limit <= 0 {
		limit = defaultTargetPage
	}
	hostID := query.Get("host_id")
	if hostID != "" {
		if _, err := uuid.Parse(hostID); err != nil {
			problem(w, http.StatusBadRequest, "invalid_host_id", "host_id must be a host identifier")
			return
		}
	}
	page, err := s.campaigns.StepsOfCampaign(r.Context(), campaign.ID, hostID, cursor, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": page.Items, "count": len(page.Items), "next_cursor": page.NextCursor,
		// The order the steps of one host run in, so a screen draws the
		// strip from the contract rather than from a list of its own.
		"step_order": campaigns.StepOrder,
	})
}

// handleCampaignPlans groups the host plans by their fingerprint.
func (s *Server) handleCampaignPlans(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	entries, err := s.campaigns.PlansWithContent(r.Context(), campaign.ID)
	if err != nil {
		s.fail(w, err)
		return
	}

	type planGroup struct {
		PlanHash string          `json:"plan_hash"`
		Count    int             `json:"count"`
		Hosts    []string        `json:"hosts"`
		Plan     json.RawMessage `json:"plan,omitempty"`
		// The group expires with its oldest plan: past that moment the
		// hosts are not started on it, digest or no digest.
		ExpiresAt time.Time `json:"expires_at"`
		// The header of the plan envelope: the planner that made the plan and
		// whether the plan is an envelope at all.
		PlannerVersion string `json:"planner_version,omitempty"`
		SchemaVersion  uint32 `json:"schema_version,omitempty"`
		Envelope       bool   `json:"envelope"`
	}
	order := []string{}
	by := map[string]*planGroup{}
	for _, entry := range entries {
		group, present := by[entry.PlanHash]
		if !present {
			header := campaigns.EnvelopeHeader(entry.Plan)
			group = &planGroup{PlanHash: entry.PlanHash, Plan: entry.Plan, ExpiresAt: entry.ExpiresAt,
				PlannerVersion: header.PlannerVersion, SchemaVersion: header.SchemaVersion, Envelope: header.Envelope}
			if expiry, err := time.Parse(time.RFC3339, header.ExpiresAt); err == nil && expiry.Before(group.ExpiresAt) {
				group.ExpiresAt = expiry
			}
			by[entry.PlanHash] = group
			order = append(order, entry.PlanHash)
		}
		if entry.ExpiresAt.Before(group.ExpiresAt) {
			group.ExpiresAt = entry.ExpiresAt
		}
		group.Count++
		// The host list matters here, but need not be a full wall: the first
		// names are enough to learn whom the group concerns.
		if len(group.Hosts) < 20 {
			group.Hosts = append(group.Hosts, orDefault(entry.Hostname, entry.HostID))
		}
	}
	groups := make([]planGroup, 0, len(order))
	for _, hash := range order {
		groups = append(groups, *by[hash])
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": groups, "count": len(groups), "hosts": len(entries),
		"plan_set_hash":    campaign.PlanSetHash,
		"plan_ttl_seconds": int(campaigns.PlanTTL.Seconds()),
	})
}

// handleCampaignReport serves the final report: the state totals, the split
// into waves and the list of hosts that need attention.
func (s *Server) handleCampaignReport(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	switch format := r.URL.Query().Get("format"); format {
	case "", "json":
	case "csv":
		s.writeCampaignCSV(w, r, campaign)
		return
	default:
		problem(w, http.StatusBadRequest, "invalid_format", "format must be json or csv")
		return
	}
	if campaign.State.Terminal() {
		report, err := s.campaigns.StoredReport(r.Context(), campaign.ID)
		if err == nil {
			writeJSON(w, http.StatusOK, report)
			return
		}
		// A campaign that ended before the panel kept reports has none; the live
		// computation is the best knowledge there is, and the answer says it is not
		// the record.
		if !errors.Is(err, campaigns.ErrNoReport) {
			s.fail(w, err)
			return
		}
	}
	report, err := s.campaigns.LiveReport(r.Context(), *campaign)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// campaignCSVColumns is the header of the export. The order is fixed: a
// spreadsheet or a script built against one export must read the next one.
var campaignCSVColumns = []string{"hostname", "host_id", "wave", "position", "state",
	"error_code", "message", "started_at", "finished_at", "job_id"}

// campaignCSVPage bounds one read of the export.
const campaignCSVPage = 1000

// writeCampaignCSV streams the targets of a campaign as a CSV file.
func (s *Server) writeCampaignCSV(w http.ResponseWriter, r *http.Request, campaign *campaigns.Campaign) {
	s.writeCSV(w, r, "campaign-"+campaign.ID+".csv", campaignCSVColumns, func(yield func([]string) bool) error {
		cursor := campaigns.TargetCursor{}
		for {
			page, err := s.campaigns.TargetsPage(r.Context(), campaign.ID, campaigns.TargetFilter{}, cursor, campaignCSVPage)
			if err != nil {
				return err
			}
			for _, target := range page.Items {
				if !yield(campaignCSVRow(target)) {
					return nil
				}
			}
			if page.NextCursor == "" {
				return nil
			}
			if cursor, err = campaigns.ParseTargetCursor(page.NextCursor); err != nil {
				return err
			}
		}
	})
}

// campaignCSVRow renders one target in the order of campaignCSVColumns.
// Times are RFC 3339 and empty when the target never reached that point.
func campaignCSVRow(target campaigns.Target) []string {
	jobID := ""
	if target.JobID != nil {
		jobID = *target.JobID
	}
	return []string{
		target.Hostname, target.HostID, strconv.Itoa(target.Wave), strconv.Itoa(target.Position),
		string(target.State), target.ErrorCode, target.Message,
		formatTime(target.StartedAt), formatTime(target.FinishedAt), jobID,
	}
}

func (s *Server) handleApproveCampaign(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignApprove)
	if !ok {
		return
	}
	principal := authz.FromContext(r.Context())

	// The approval covers what the approver saw: this operation, this payload,
	// this host list and this rollout policy.
	var request struct {
		ApprovalFingerprint string `json:"approval_fingerprint"`
		// The reason is part of the evidence. A critical campaign requires it, like
		// the same operation on one host; elsewhere it is recorded when given.
		Reason       string `json:"reason"`
		ChangeTicket string `json:"change_ticket"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request)
	}
	if request.ApprovalFingerprint != campaign.ApprovalFingerprint {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "campaign.approve", TargetType: "campaign", TargetID: campaign.ID,
			Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": "fingerprint_mismatch", "expected": campaign.ApprovalFingerprint,
				"provided": request.ApprovalFingerprint,
			},
		})
		problem(w, http.StatusConflict, "fingerprint_mismatch",
			"the campaign changed since it was reviewed; re-read it and approve the current plan")
		return
	}

	// The second-person rule binds campaigns too, and all the more: one
	// approval starts a change on many hosts.
	if s.campaignNeedsSecondPerson(r, campaign) && campaign.CreatedBy == principal.Subject {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "campaign.approve", TargetType: "campaign", TargetID: campaign.ID,
			Outcome: audit.OutcomeDenied, Detail: map[string]any{"reason": "self_approval"},
		})
		problem(w, http.StatusForbidden, "self_approval",
			"a production campaign must be approved by a second person")
		return
	}

	// The consent is what starts the change, so the fresh authentication belongs
	// here, immediately before it - a session that was fresh at creation may be
	// hours old by the time the plans are reviewed.
	approval := campaigns.Approval{
		ApprovedBy:     principal.Subject,
		Authentication: "api_token",
		Reason:         strings.TrimSpace(request.Reason),
		ChangeTicket:   strings.TrimSpace(request.ChangeTicket),
	}
	if session, ok := authz.SessionFromContext(r.Context()); ok && session != nil {
		approval.Authentication = "session"
		approval.ACR = session.Auth.ACR
		approval.AMR = session.Auth.AMR
		if !session.Auth.At.IsZero() {
			at := session.Auth.At.UTC()
			approval.AuthenticatedAt = &at
		}
	}
	var stepUpEvidence map[string]any
	if campaignRequiresFreshAuth(campaign) {
		evidence, ok := s.requireStepUp(w, r, principal, request.Reason,
			"campaign.approve", "campaign", campaign.ID)
		if !ok {
			return
		}
		stepUpEvidence = evidence
	}

	// A consent covers plans the hosts still compute.
	if code, detail := campaignPlansConflict(r.Context(), s.campaigns, campaign.ID); code != "" {
		problem(w, http.StatusConflict, code, detail)
		return
	}

	tx, err := s.campaigns.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// The plans are recorded with the approval: what the consent covered,
	// host by host, as it stood when it was given.
	approved, err := s.campaigns.ApproveWithPlans(r.Context(), tx, *campaign, approval)
	if errors.Is(err, campaigns.ErrConflict) {
		problem(w, http.StatusConflict, "invalid_state",
			"the campaign is not awaiting approval (state "+string(campaign.State)+")")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	// The event names everybody behind the change: who ordered the campaign and
	// who has consented so far, this approval included - the list is read inside
	// the transaction, so it holds the record just written.
	approvals, err := s.campaigns.ApprovalsTx(r.Context(), tx, campaign.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	chain := &audit.ApprovalChain{CreatedBy: campaign.CreatedBy, Approvers: make([]string, 0, len(approvals))}
	for _, record := range approvals {
		chain.Approvers = append(chain.Approvers, record.ApprovedBy)
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign.approve", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		ApprovalChain: chain,
		Detail: withStepUp(map[string]any{
			"name": campaign.Name, "created_by": campaign.CreatedBy,
			"approval_fingerprint": campaign.ApprovalFingerprint,
			"reason":               approval.Reason, "change_ticket": approval.ChangeTicket,
		}, stepUpEvidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, approved)
}

// campaignPlansConflict says whether the campaign's plans can still be
// consented to: plan_expired when a plan envelope is past its expiry.
func campaignPlansConflict(ctx context.Context, store *campaigns.Store, campaignID string) (string, string) {
	entries, err := store.PlansWithContent(ctx, campaignID)
	if err != nil {
		return "", ""
	}
	now := time.Now()
	for _, entry := range entries {
		header := campaigns.EnvelopeHeader(entry.Plan)
		if !header.Envelope || header.ExpiresAt == "" {
			continue
		}
		expiry, err := time.Parse(time.RFC3339, header.ExpiresAt)
		if err != nil {
			continue
		}
		if now.After(expiry) {
			return "plan_expired", "the plan of " + orDefault(entry.Hostname, entry.HostID) +
				" expired at " + expiry.UTC().Format(time.RFC3339) + "; plan the campaign again"
		}
	}
	return "", ""
}

// handleCampaignApprovals returns the approval records: the evidence of
// who consented to what, on what authentication and why.
func (s *Server) handleCampaignApprovals(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	approvals, err := s.campaigns.Approvals(r.Context(), campaign.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": approvals, "count": len(approvals)})
}

func (s *Server) handlePauseCampaign(w http.ResponseWriter, r *http.Request) {
	s.controlCampaign(w, r, "pause")
}

func (s *Server) handleResumeCampaign(w http.ResponseWriter, r *http.Request) {
	s.controlCampaign(w, r, "resume")
}

func (s *Server) handleCancelCampaign(w http.ResponseWriter, r *http.Request) {
	s.controlCampaign(w, r, "cancel")
}

// handleAdvanceCampaign lets a campaign standing at the manual gate into the
// waves.
func (s *Server) handleAdvanceCampaign(w http.ResponseWriter, r *http.Request) {
	s.controlCampaign(w, r, "advance")
}

func (s *Server) controlCampaign(w http.ResponseWriter, r *http.Request, operation string) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignControl)
	if !ok {
		return
	}
	principal := authz.FromContext(r.Context())

	var request struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.ContentLength > 0 {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request)
	}

	var (
		updated *campaigns.Campaign
		err     error
	)
	switch operation {
	case "pause":
		updated, err = s.campaigns.Pause(r.Context(), campaign.ID, principal.Subject, request.Reason)
	case "resume":
		updated, err = s.campaigns.Resume(r.Context(), campaign.ID, principal.Subject)
	case "advance":
		updated, err = s.campaigns.Advance(r.Context(), campaign.ID, principal.Subject)
	default:
		updated, err = s.campaigns.Cancel(r.Context(), campaign.ID, principal.Subject, request.Reason)
	}
	if errors.Is(err, campaigns.ErrConflict) {
		problem(w, http.StatusConflict, "invalid_state",
			"operation not allowed in state "+string(campaign.State))
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	// A campaign stopped with one write does not close the hosts one by one, so
	// it has nowhere to return the tokens.
	if operation == "cancel" && s.budgets != nil && updated.State == campaigns.StateCanceled {
		if err := s.budgets.ReleaseClaimant(r.Context(), "campaign:"+campaign.ID); err != nil {
			s.log.Error("the capacity of the cancelled campaign was not released",
				"campaign_id", campaign.ID, "err", err)
		}
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign." + operation, TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"reason": request.Reason, "state": string(updated.State)},
	})
	writeJSON(w, http.StatusOK, updated)
}

// handleSkipCampaignTarget lets an operator leave a host waiting for its
// connection out of the campaign, by name and with a reason: the offline
// canary the document lets the operator skip so that the wave barrier opens.
func (s *Server) handleSkipCampaignTarget(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignApprove)
	if !ok {
		return
	}
	principal := authz.FromContext(r.Context())
	var request struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
			problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
			return
		}
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if len([]rune(request.Reason)) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"a skip must state its reason (field reason, min. 8 characters)")
		return
	}
	hostID := r.PathValue("host")
	if _, err := uuid.Parse(hostID); err != nil {
		problem(w, http.StatusNotFound, "target_not_found", "no such host in the campaign")
		return
	}
	target, err := s.campaigns.SkipTarget(r.Context(), campaign.ID, hostID, principal.Subject, request.Reason)
	switch {
	case errors.Is(err, campaigns.ErrNotFound):
		problem(w, http.StatusNotFound, "target_not_found", "no such host in the campaign")
		return
	case errors.Is(err, campaigns.ErrSkipNotAllowed):
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "campaign.target.skip", TargetType: "host", TargetID: hostID,
			RequestID: campaign.RequestID, Outcome: audit.OutcomeDenied,
			Detail: map[string]any{"campaign_id": campaign.ID, "reason": "skip_not_allowed"},
		})
		problem(w, http.StatusConflict, "skip_not_allowed",
			"only a host waiting for its connection can be skipped; a host under way settles on its own")
		return
	case errors.Is(err, campaigns.ErrConflict), errors.Is(err, campaigns.ErrConcurrentTransition):
		problem(w, http.StatusConflict, "invalid_state",
			"the host or the campaign moved; read it again")
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign.target.skip", TargetType: "host", TargetID: hostID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"campaign_id": campaign.ID, "wave": target.Wave,
			"error_code": target.ErrorCode, "reason": request.Reason,
		},
	})
	writeJSON(w, http.StatusOK, target)
}

// campaignFor loads the campaign and checks the permission in the scope of
// its targets.
func (s *Server) campaignFor(w http.ResponseWriter, r *http.Request,
	permission authz.Permission) (*campaigns.Campaign, bool) {
	campaignID := r.PathValue("id")
	campaign, err := s.campaigns.Get(r.Context(), campaignID)
	if errors.Is(err, campaigns.ErrNotFound) {
		problem(w, http.StatusNotFound, "campaign_not_found", "no such campaign")
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}

	scope, err := s.campaignScope(r, campaign.ID)
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	if _, ok := s.authorize(w, r, permission, scope, "campaign", campaignID); !ok {
		return nil, false
	}
	return campaign, true
}

// campaignScope returns the scope covering all the campaign targets.
func (s *Server) campaignScope(r *http.Request, campaignID string) (authz.Scope, error) {
	targets, err := s.campaigns.Targets(r.Context(), campaignID)
	if err != nil {
		return authz.Scope{}, err
	}
	scope := authz.Scope{}
	for index, target := range targets {
		host, err := s.hosts.Get(r.Context(), target.HostID)
		if err != nil {
			continue
		}
		if index == 0 {
			scope = hosts.ScopeOf(host)
			continue
		}
		if scope.Site != host.Site {
			scope.Site = authz.Wildcard
		}
		if scope.Environment != host.Environment {
			scope.Environment = authz.Wildcard
		}
		// A campaign is over one team only while every host of it is in that team.
		if scope.Team != host.TeamID {
			scope.Team = ""
		}
	}
	return scope, nil
}

// campaignNeedsSecondPerson says whether the campaign touches a production
// environment.
func (s *Server) campaignNeedsSecondPerson(r *http.Request, campaign *campaigns.Campaign) bool {
	targets, err := s.campaigns.Targets(r.Context(), campaign.ID)
	if err != nil {
		// Missing knowledge about the targets must not weaken the control.
		return true
	}
	for _, target := range targets {
		host, err := s.hosts.Get(r.Context(), target.HostID)
		if err != nil {
			continue
		}
		if s.requiresSecondPerson(host.Environment) {
			return true
		}
	}
	return false
}

// valueOrDefault differs from valueOr in one thing: zero is a decision here,
// not a missing value.
func valueOrDefault(value *int, fallback int) int {
	if value == nil || *value < 0 {
		return fallback
	}
	return *value
}

func valueOr(value *int, fallback int) int {
	if value == nil || *value <= 0 {
		return fallback
	}
	return *value
}

// valueAsGiven passes a number through as the request gave it, zero when it
// was left out.
func valueAsGiven(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// campaignScopes carries the principal scopes to the store layer. The
// global scope lifts the narrowing, so it is enough to pass it as it is.
func campaignScopes(principal authz.Principal) []campaigns.Scope {
	scopes := principal.ScopesFor(authz.PermCampaignRead)
	result := make([]campaigns.Scope, 0, len(scopes))
	for _, scope := range scopes {
		result = append(result,
			campaigns.Scope{Site: scope.Site, Environment: scope.Environment, Team: scope.Team})
	}
	return result
}

// campaignRequiresFreshAuth says whether approving the campaign needs the
// operator to confirm their identity first: the registry's answer for the
// operation, raised where the content of the order calls for it.
func campaignRequiresFreshAuth(campaign *campaigns.Campaign) bool {
	action := opspec.ActionType(campaign.ActionType)
	var payload opspec.Payload
	if len(campaign.Payload) > 0 {
		if err := json.Unmarshal(campaign.Payload, &payload); err != nil {
			return action.RequiresFreshAuth()
		}
	}
	return opspec.PayloadRequiresFreshAuth(action, payload)
}
