package adminapi

import (
	"encoding/csv"
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
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/selector"
)

type createCampaignRequest struct {
	Name    string          `json:"name"`
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload"`
	// Selector is recorded as given; the typed expression, when present,
	// decides alone. The exclusions name hosts the selector matches that
	// are to stay out, and need a reason the approver will read.
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
	RequiresApproval         *bool      `json:"requires_approval,omitempty"`
	// OfflinePolicy overrides what the operation declares for a host that
	// is not connected when its turn comes. It may only tighten the
	// declaration: wait_until_deadline may become skip_if_offline or
	// require_online, and require_online may become nothing else - the
	// operation's policy is the boundary its module drew. Empty means the
	// operation's own policy.
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
	// CompensatesCampaignID names a finished campaign this one undoes. The
	// operation has to be the declared reverse of that campaign's, and the
	// targets have to be hosts it changed; an empty selector takes exactly
	// those hosts. The original's record is linked, never rewritten.
	CompensatesCampaignID string `json:"compensates_campaign_id,omitempty"`
}

// campaignModeRefusal translates a refusal into a sentence the operator
// knows what to do next from. A refusal without a reason looks like a
// missing product feature.
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
	// Whoever asks must at least be somebody who may create campaigns
	// somewhere, before the selector is read: the answers about the
	// snapshot - how many hosts, in what state, which groups exist - are
	// facts about the fleet, not for a stranger. Every host of the
	// snapshot is checked again below, in its own scope.
	if _, ok := s.authorizeCollection(w, r, authz.PermCampaignCreate, "campaign"); !ok {
		return
	}
	var request createCampaignRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}

	action := opspec.ActionType(request.Action)
	if !action.Known() || !action.Mutating() {
		problem(w, http.StatusBadRequest, "unknown_action",
			"a campaign requires an operation that changes host state")
		return
	}
	// An operation that requires typing the target name does not run in
	// bulk. The target name is there the only gate between a click and an
	// irreversible change, and a campaign by definition has no single target
	// to type: wiping a disk or powering off a whole wave has no way back.
	if action.RequiresTargetConfirmation() {
		problem(w, http.StatusBadRequest, "not_a_campaign_action",
			"this operation is irreversible and needs its target named; run it host by host")
		return
	}
	// There are operations that must not be done in bulk at all - not
	// because the panel cannot, but because their effect requires the
	// operator's presence at every host separately.
	if reason := opspec.CampaignExclusionReason(action); reason != "" {
		problem(w, http.StatusBadRequest, "not_a_campaign_action", reason)
		return
	}
	// The bulk mode is a declaration of the operation, not a conclusion from
	// its risk. No declaration means a refusal: adding a new operation to the
	// registry must not by itself open it to the whole fleet.
	if !opspec.ExecutableMode(action) {
		problem(w, http.StatusBadRequest, "campaign_mode_unsupported",
			campaignModeRefusal(action))
		return
	}
	// The offline policy is a property of the operation the campaign may
	// tighten and never loosen. It is settled before the payload, because
	// it does not depend on it.
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
	// A campaign order is validated differently than an operation on one
	// host: there is no plan fingerprint yet, because the plan is made on the
	// hosts.
	// A refusal with a code of its own (a protocol this panel does not
	// speak) keeps that code; a malformed payload stays invalid_payload.
	if err := opspec.ValidateCampaignRequest(action, payload); err != nil {
		problem(w, http.StatusBadRequest, opspec.RefusalCode(err), err.Error())
		return
	}
	// A rollback to an earlier file version carries only the digest, as on
	// one host: the content is attached here, so the plans, the consent and
	// what reaches the hosts are the same thing. Left as a digest it would
	// plan and write emptiness on every host. The digest itself leaves the
	// payload once the content is in, exactly as the single-host order does,
	// so the job envelope and the plan hash see an ordinary write.
	if action == opspec.ActionFileRollback && payload.File != nil && payload.File.VersionSHA256 != "" {
		content, err := s.files.Content(r.Context(), payload.File.VersionSHA256)
		if err != nil {
			problem(w, http.StatusBadRequest, "version_not_found",
				"no stored version with the checksum "+payload.File.VersionSHA256)
			return
		}
		payload.File.Content = string(content)
		payload.File.VersionSHA256 = ""
		resolved, err := json.Marshal(payload)
		if err != nil {
			s.fail(w, err)
			return
		}
		request.Payload = resolved
	}

	principal := authz.FromContext(r.Context())
	chosen, ok := s.checkSelector(w, request.Selector)
	if !ok {
		return
	}
	// A compensation is checked before the selector is resolved: the
	// original decides which hosts may be named at all, and an order that
	// names none takes the hosts the original changed.
	compensation, ok := s.checkCompensation(w, r, request.CompensatesCampaignID, action, &chosen)
	if !ok {
		return
	}
	candidates, ok := s.materialize(w, r, chosen)
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

	// The qualification decides which hosts really move. A host in a
	// maintenance window and a host without the required adapter stay in the
	// snapshot, but closed at once and with a reason: vanishing quietly would
	// hide the decision, and listing them as ready would call a missing
	// capability a failure. A host the operator excluded by name is closed
	// the same way, with the reason and the author.
	kept, excluded := excludeHosts(candidates, chosen, principal.Subject)
	assessment := assessCandidates(kept, action, s.activeConflicts(r.Context()), time.Now().UTC())
	assessment.Closed = append(assessment.Closed, excluded...)
	if len(assessment.Ready) == 0 {
		problem(w, http.StatusBadRequest, "no_eligible_targets",
			"no matched host can run this operation: "+describeExclusions(assessment.Exclusions()))
		return
	}

	// There are changes that are correct only together: withdrawing an
	// authority on part of the fleet leaves hosts the rest stops recognising.
	// Such a campaign does not start at all while any target is uncertain -
	// and says which.
	if reason := opspec.FullCoverageReason(action); reason != "" {
		if uncertain := assessment.Uncertain(); len(uncertain) > 0 {
			problem(w, http.StatusBadRequest, "incomplete_coverage",
				reason+"; "+describeExclusions(uncertain))
			return
		}
	}

	// The permission is checked for every host of the snapshot. A campaign
	// covering one host outside the scope must not pass because the rest is
	// inside it.
	for _, host := range candidates {
		scope := authz.Scope{Site: host.Site, Environment: host.Environment}
		if _, ok := s.authorize(w, r, authz.PermCampaignCreate, scope, "host", host.ID); !ok {
			return
		}
		if _, ok := s.authorize(w, r, authz.Permission(action.Permission()), scope, "host", host.ID); !ok {
			return
		}
	}

	// A campaign must not be a way around the single-host gate. The same
	// operation ordered by hand requires fresh authentication, so ordered on
	// the whole fleet it requires it all the more.
	var stepUpEvidence map[string]any
	if opspec.PayloadRequiresFreshAuth(action, payload) {
		evidence, ok := s.requireStepUp(w, r, principal, request.Reason,
			"campaign.create", "campaign", "")
		if !ok {
			return
		}
		stepUpEvidence = evidence
	}

	spec := campaigns.Spec{
		Name:       request.Name,
		ActionType: string(action),
		Payload:    request.Payload,
		Selector:   chosen,
		CanarySize: valueOrDefault(request.CanarySize, 1),
		// The concurrency is bounded whatever the request says: budgets are
		// the safety net of the fleet, and an installation without them
		// must not be one request away from restarting everything at once.
		WaveSize:                 min(valueOr(request.WaveSize, 10), maxWaveSize),
		MaxConcurrent:            min(valueOr(request.MaxConcurrent, 5), maxCampaignConcurrency),
		FailureThresholdPercent:  valueOrDefault(request.FailureThresholdPercent, 20),
		FailureThresholdAbsolute: valueOr(request.FailureThresholdAbsolute, 0),
		MaintenanceStart:         request.MaintenanceStart,
		MaintenanceEnd:           request.MaintenanceEnd,
		RebootPolicy:             campaigns.RebootPolicy(orDefault(request.RebootPolicy, "never")),
		HealthCheckUnits:         request.HealthCheckUnits,
		JobTimeoutSeconds:        valueOr(request.JobTimeoutSeconds, action.DefaultTimeout()),
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
			"approval_fingerprint":       campaign.ApprovalFingerprint,
			"compensates_campaign_id":    campaign.CompensatesCampaignID,
		}, stepUpEvidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, campaign)
}

// describeExclusions joins the refusal reasons into one sentence.
//
// The refusal "no host can run this" without reasons is silence: the
// operator sees a selector that matched something, and a refusal unrelated
// to what they see.
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

// checkCompensation reads and checks the campaign an order says it undoes.
// An empty identifier means an ordinary campaign and passes with nil. The
// answer has already been written when the second result is false.
//
// The original has to exist and be readable by the caller in its scope -
// the same door as reading it directly, so an identifier cannot be used
// to learn about a campaign elsewhere. Then the rules of the package
// apply: the original is settled, the operation is its declared reverse,
// and there is something to compensate. An order with an empty selector
// gets the changed hosts of the original as its host list: those are the
// only hosts it may name, and the operator should not have to copy them.
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
	// A preview without an operation asks about the compensation itself;
	// it is checked as the declared reverse would be. An original with no
	// reverse is refused below, as it would be with any operation.
	if action == "" {
		action, _ = opspec.ReverseAction(opspec.ActionType(original.ActionType))
	}
	// The rules are checked once here without hosts, so an order refused
	// for its original or its operation is refused before the fleet is
	// read; the hosts are checked once the selector resolved.
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

// covers checks that every host the selector resolved to is one the
// original changed, and answers the order that names another. The
// hostname goes into the reason where there is one: an identifier alone
// tells the operator nothing about which row of the list to take out.
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

// checkSelector validates the selector of an order and answers a request
// that does not hold together. The expression is validated and resolved
// here, so an order naming a group that does not exist is refused with the
// name rather than materialised as nothing.
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

// materialize turns the selector into the host list and answers a
// selector that does not resolve or resolves to too much. An empty list is
// an answer, not an error: the preview says "nobody", and the order
// refuses it in its own words. The answer has already been written when
// the second result is false.
func (s *Server) materialize(w http.ResponseWriter, r *http.Request, chosen campaigns.Selector) ([]hosts.Host, bool) {
	candidates, err := s.resolveTargets(r, chosen)
	switch {
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

// resolveTargets turns the selector into a host list.
//
// The typed expression, when present, decides alone: it is expanded of
// its group references and compiled into the host query, the same query
// the host list and the group page run. The older fields take the older
// way - an explicit list is read host by host, the flat filters page
// through the list.
func (s *Server) resolveTargets(r *http.Request, chosen campaigns.Selector) ([]hosts.Host, error) {
	if chosen.Expression != nil {
		expanded, err := selector.Expand(r.Context(), chosen.Expression, s.groups)
		if err != nil {
			return nil, err
		}
		return s.pageHosts(r.Context(), hosts.ListFilter{Expression: expanded})
	}
	if len(chosen.HostIDs) > 0 {
		result := make([]hosts.Host, 0, len(chosen.HostIDs))
		for _, hostID := range chosen.HostIDs {
			host, err := s.hosts.Get(r.Context(), hostID)
			if errors.Is(err, hosts.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			result = append(result, *host)
		}
		return result, nil
	}
	// The selector is read page by page, without a hidden limit: a campaign
	// covering a thousand hosts is meant to mean a thousand hosts, not the
	// first five hundred sorted alphabetically. The upper bound is explicit
	// and ends in an error, not a quiet trimming of the list.
	return s.pageHosts(r.Context(), hosts.ListFilter{
		Site:        chosen.Site,
		Environment: chosen.Environment,
		OSFamily:    chosen.OSFamily,
	})
}

// excludeHosts takes the hosts on the exclusion list out of the candidate
// list. The rest goes to the qualification; the excluded ones come back
// settled - closed at once with the reason and the author - so that they
// enter the snapshot rather than vanish. A host on the list that the
// selector did not match is not a target and leaves no trace.
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

// maxCampaignSnapshot is the bound of one campaign. It does not protect the
// database, only the human: a snapshot bigger than this is usually a wrong
// selector, not an intent.
const maxCampaignSnapshot = 10000

// ErrSelectorTooBroad means a selector covering more hosts than one
// campaign is meant to run.
var ErrSelectorTooBroad = errors.New("the selector covers too many hosts")

// handleCampaignPreview answers the question "how many hosts does this
// concern".
//
// The count comes from the database, not from the length of the first page
// of the host list: the operator approves a change on as many machines as
// shown, so the preview must not stop at a hidden limit. The sample is only
// a sample and is named so.
func (s *Server) handleCampaignPreview(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermCampaignRead, "campaign")
	if !ok {
		return
	}
	query := r.URL.Query()
	chosen := campaigns.Selector{
		Site:          query.Get("site"),
		Environment:   query.Get("environment"),
		OSFamily:      query.Get("os_family"),
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
	// Without an operation the preview answers only the question "how many
	// hosts does this concern". The qualification depends on the operation:
	// hosts without a package adapter are ready for a service restart and
	// unable to update.
	action := opspec.ActionType(query.Get("action"))
	if action != "" && !action.Known() {
		problem(w, http.StatusBadRequest, "unknown_action", "unknown action "+string(action))
		return
	}
	// A compensation previews what the order would do: the same check,
	// the same default host list, so the wizard shows the refusal before
	// the form is filled in rather than after.
	compensation, ok := s.checkCompensation(w, r, query.Get("compensates"), action, &chosen)
	if !ok {
		return
	}

	// The count comes from the same query the snapshot will run: a preview
	// counted differently than the creation would be worse than none.
	filter := hosts.ListFilter{Site: chosen.Site, Environment: chosen.Environment, OSFamily: chosen.OSFamily}
	if chosen.Expression != nil {
		expanded, err := selector.Expand(r.Context(), chosen.Expression, s.groups)
		if err != nil {
			s.selectorProblem(w, err)
			return
		}
		filter = hosts.ListFilter{Expression: expanded}
	}
	var count int
	var listed []hosts.Host
	if len(chosen.HostIDs) > 0 {
		// A list of hosts is not a filter the host table counts; it is
		// resolved the way the order resolves it, and counted.
		listed, ok = s.materialize(w, r, chosen)
		if !ok {
			return
		}
		count = len(listed)
	} else {
		var err error
		count, err = s.hosts.Count(r.Context(), filter)
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	response := map[string]any{
		"count":    count,
		"limit":    maxCampaignSnapshot,
		"selector": chosen.Expression.Describe(),
	}
	if compensation != nil {
		response["compensates"] = map[string]any{
			"id": compensation.original.ID, "name": compensation.original.Name,
			"state": compensation.original.State, "changed": len(compensation.changed),
		}
	}

	if action == "" {
		sample := listed
		if len(chosen.HostIDs) == 0 {
			var err error
			sample, err = s.hosts.Page(r.Context(), filter, "", "", previewSampleSize)
			if err != nil {
				s.fail(w, err)
				return
			}
		}
		response["sample"] = hostNames(sample[:min(len(sample), previewSampleSize)])
		writeJSON(w, http.StatusOK, response)
		return
	}

	// The qualification is computed on the same snapshot that would enter
	// the campaign. A preview computed differently than the creation would be
	// worse than none: the operator would approve one campaign and get
	// another.
	candidates, ok := s.materialize(w, r, chosen)
	if !ok {
		return
	}
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
	response["requires_plan"] = opspec.PlanningAction(action) != ""
	response["distribution"] = distribution(assessment.Ready, action)
	writeJSON(w, http.StatusOK, response)
}

// distribution describes what the frozen target snapshot consists of.
//
// The count of ready hosts does not say what is about to happen: thirty
// hosts from one site is a different change than thirty scattered across
// three, and the OS family decides what the host does at all. The operator
// is meant to see that before approving, not infer it from the names in
// the sample.
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
		// The capability tells the hosts that accept the operation from those
		// that have not reported their adapter registry yet - and the latter
		// go into the campaign and are decided only on the host.
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

// previewSampleSize bounds the sample shown in the preview.
const previewSampleSize = 12

func (s *Server) handleListCampaigns(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermCampaignRead, "campaign")
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.campaigns.List(r.Context(), r.URL.Query().Get("state"), limit,
		campaignScopes(principal))
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []campaigns.Campaign{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
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
	// The targets go page by page in the order of the rollout, filtered on
	// the server: a campaign on ten thousand hosts must not become ten
	// thousand rows in the browser, and "the failed ones" is a question the
	// database answers better than a screen.
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

// handleCampaignTimeline returns the durable course of a campaign.
//
// The report says how it ended. The course says how it went - and that is
// what is needed during: when the canary started, which host failed first
// and at what time the campaign stopped. Notifications will not hold this,
// because an event sent at the moment of a panel restart exists nowhere any
// more.
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

// handleCampaignSteps returns the executable steps of the campaign's
// targets: plan, change, reboot, verification and compensation, each with
// its task, its attempts and the reason it did not run.
//
// The target row says where a host stands; the steps say how it got there,
// and that is what a diagnosis needs - which step failed, on which attempt,
// under which plan. The list goes page by page in the order of the rollout
// and is cut between hosts, never inside one, so a host's strip is always
// read whole. A host filter answers the question the screen asks most:
// "what happened on this one".
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
//
// The approval covers a set of plans, not one payload, so the operator must
// see it before deciding. A list of a hundred hosts with an identical diff
// is not knowledge though - it is a wall of text. Grouping goes by plan
// fingerprint: one item is one real shape of the change together with the
// list of hosts that get it.
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
	}
	order := []string{}
	by := map[string]*planGroup{}
	for _, entry := range entries {
		group, present := by[entry.PlanHash]
		if !present {
			group = &planGroup{PlanHash: entry.PlanHash, Plan: entry.Plan, ExpiresAt: entry.ExpiresAt}
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

// handleCampaignReport serves the final report: the state totals, the
// split into waves and the list of hosts that need attention.
//
// A finished campaign has its report on record, written with the terminal
// transition; the answer is that record, marked as stored, and it does not
// change when a host later leaves the fleet. A campaign under way has no
// record yet and gets the report computed from its targets now.
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
		// A campaign that ended before the panel kept reports has none;
		// the live computation is the best knowledge there is, and the
		// answer says it is not the record.
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

// campaignCSVPage bounds one read of the export. It is the page the store
// serves at most, so the export costs the database the same as a screen
// paged to the end, whatever the size of the campaign.
const campaignCSVPage = 1000

// writeCampaignCSV streams the targets of a campaign as a CSV file. The
// report is meant for a campaign on ten thousand hosts: the rows go page by
// page from the database straight to the socket, and each page leaves the
// panel's memory before the next one is read. The headers are the only
// thing decided before the first row; an error in the middle of the export
// cannot become a problem document any more and ends up as a short file.
func (s *Server) writeCampaignCSV(w http.ResponseWriter, r *http.Request, campaign *campaigns.Campaign) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "campaign-"+campaign.ID+".csv"))
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	writer := csv.NewWriter(w)
	if err := writer.Write(campaignCSVColumns); err != nil {
		return
	}
	cursor := campaigns.TargetCursor{}
	for {
		page, err := s.campaigns.TargetsPage(r.Context(), campaign.ID, campaigns.TargetFilter{}, cursor, campaignCSVPage)
		if err != nil {
			s.log.Warn("the CSV export of the campaign broke off", "campaign_id", campaign.ID, "err", err)
			return
		}
		for _, target := range page.Items {
			if err := writer.Write(campaignCSVRow(target)); err != nil {
				return
			}
		}
		writer.Flush()
		if writer.Error() != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		if page.NextCursor == "" {
			return
		}
		if cursor, err = campaigns.ParseTargetCursor(page.NextCursor); err != nil {
			return
		}
	}
}

// campaignCSVRow renders one target in the order of campaignCSVColumns.
// Times are RFC 3339 and empty when the target never reached that point.
func campaignCSVRow(target campaigns.Target) []string {
	stamp := func(at *time.Time) string {
		if at == nil {
			return ""
		}
		return at.UTC().Format(time.RFC3339)
	}
	jobID := ""
	if target.JobID != nil {
		jobID = *target.JobID
	}
	return []string{
		csvText(target.Hostname), target.HostID, strconv.Itoa(target.Wave), strconv.Itoa(target.Position),
		string(target.State), target.ErrorCode, csvText(target.Message),
		stamp(target.StartedAt), stamp(target.FinishedAt), jobID,
	}
}

// csvText keeps a cell from becoming a formula. A host name or a message
// comes from the host, and a spreadsheet runs a cell that starts with =,
// +, - or @; a leading apostrophe makes it text again.
func csvText(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	}
	return value
}

func (s *Server) handleApproveCampaign(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignApprove)
	if !ok {
		return
	}
	principal := authz.FromContext(r.Context())

	// The approval covers what the approver saw: this operation, this
	// payload, this host list and this rollout policy. The fingerprint is the
	// only proof they looked at the same thing - without it the approval
	// would refer to the campaign identifier alone.
	var request struct {
		ApprovalFingerprint string `json:"approval_fingerprint"`
		// The reason is part of the evidence. A critical campaign requires
		// it, like the same operation on one host; elsewhere it is recorded
		// when given.
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

	// The consent is what starts the change, so the fresh authentication
	// belongs here, immediately before it - a session that was fresh at
	// creation may be hours old by the time the plans are reviewed.
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

	tx, err := s.campaigns.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	approved, err := s.campaigns.Approve(r.Context(), tx, campaign.ID, approval)
	if errors.Is(err, campaigns.ErrConflict) {
		problem(w, http.StatusConflict, "invalid_state",
			"the campaign is not awaiting approval (state "+string(campaign.State)+")")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	// The event names everybody behind the change: who ordered the campaign
	// and who has consented so far, this approval included - the list is
	// read inside the transaction, so it holds the record just written.
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

// handleAdvanceCampaign lets a campaign standing at the manual gate into
// the waves. The canary ran; the decision to go on is a person's, and it is
// recorded with a reason like every other control.
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

	// A campaign stopped with one write does not close the hosts one by one,
	// so it has nowhere to return the tokens. They are returned here: the
	// capacity held by a campaign that does nothing any more stops the next
	// one.
	if operation == "cancel" && s.budgets != nil {
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

// campaignScope returns the scope covering all the campaign targets. When
// the targets lie in different scopes, the global permission is required: a
// campaign is an operation on the whole named part of the fleet.
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
			scope = authz.Scope{Site: host.Site, Environment: host.Environment}
			continue
		}
		if scope.Site != host.Site {
			scope.Site = authz.Wildcard
		}
		if scope.Environment != host.Environment {
			scope.Environment = authz.Wildcard
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

// valueOrDefault differs from valueOr in one thing: zero is a decision
// here, not a missing value. A campaign without a canary makes sense, just
// like a campaign without a percentage threshold - and that is exactly how
// the default profiles from the document look. Quietly substituting a value
// would change the policy the operator asked for, and the approval
// fingerprint would already cover something else.
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
		result = append(result, campaigns.Scope{Site: scope.Site, Environment: scope.Environment})
	}
	return result
}

// campaignRequiresFreshAuth says whether approving the campaign needs the
// operator to confirm their identity first: the registry's answer for the
// operation, raised where the content of the order calls for it. A payload
// that does not decode is treated as the operation's base level - the
// campaign was validated when it was created.
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
