package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

type createCampaignRequest struct {
	Name     string          `json:"name"`
	Action   string          `json:"action"`
	Payload  json.RawMessage `json:"payload"`
	Selector struct {
		Site        string   `json:"site,omitempty"`
		Environment string   `json:"environment,omitempty"`
		OSFamily    string   `json:"os_family,omitempty"`
		HostIDs     []string `json:"host_ids,omitempty"`
	} `json:"selector"`
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
	// Reason justifies the highest-risk campaigns and goes to the audit log.
	Reason string `json:"reason,omitempty"`
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

// handleCreateCampaign plans a campaign. The selector is immediately turned
// into an immutable host snapshot; the creation itself changes nothing.
func (s *Server) handleCreateCampaign(w http.ResponseWriter, r *http.Request) {
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
	if err := opspec.ValidateCampaignRequest(action, payload); err != nil {
		problem(w, http.StatusBadRequest, "invalid_payload", err.Error())
		return
	}

	selector := campaigns.Selector{
		Site:        request.Selector.Site,
		Environment: request.Selector.Environment,
		OSFamily:    request.Selector.OSFamily,
		HostIDs:     request.Selector.HostIDs,
	}
	candidates, err := s.resolveTargets(r, selector)
	if errors.Is(err, ErrSelectorTooBroad) {
		problem(w, http.StatusBadRequest, "selector_too_broad", err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(candidates) == 0 {
		problem(w, http.StatusBadRequest, "no_targets", "the selector matched no hosts")
		return
	}

	// The qualification decides which hosts really move. A host in a
	// maintenance window and a host without the required adapter stay in the
	// snapshot, but closed at once and with a reason: vanishing quietly would
	// hide the decision, and listing them as ready would call a missing
	// capability a failure.
	assessment := assessCandidates(candidates, action, s.activeConflicts(r.Context()),
		time.Now().UTC())
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
	principal := authz.FromContext(r.Context())
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
	if action.RequiresFreshAuth() {
		evidence, ok := s.requireStepUp(w, r, principal, request.Reason,
			"campaign.create", "campaign", "")
		if !ok {
			return
		}
		stepUpEvidence = evidence
	}

	spec := campaigns.Spec{
		Name:                     request.Name,
		ActionType:               string(action),
		Payload:                  request.Payload,
		Selector:                 selector,
		CanarySize:               valueOrDefault(request.CanarySize, 1),
		WaveSize:                 valueOr(request.WaveSize, 10),
		MaxConcurrent:            valueOr(request.MaxConcurrent, 5),
		FailureThresholdPercent:  valueOrDefault(request.FailureThresholdPercent, 20),
		FailureThresholdAbsolute: valueOr(request.FailureThresholdAbsolute, 0),
		MaintenanceStart:         request.MaintenanceStart,
		MaintenanceEnd:           request.MaintenanceEnd,
		RebootPolicy:             campaigns.RebootPolicy(orDefault(request.RebootPolicy, "never")),
		HealthCheckUnits:         request.HealthCheckUnits,
		JobTimeoutSeconds:        valueOr(request.JobTimeoutSeconds, action.DefaultTimeout()),
		RequiresApproval:         request.RequiresApproval == nil || *request.RequiresApproval,
		CreatedBy:                principal.Subject,
		RequestID:                requestIDOf(r),
	}

	targets := assessment.Targets()

	tx, err := s.campaigns.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	campaign, err := s.campaigns.Create(r.Context(), tx, spec, targets)
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
			"canary_size": campaign.CanarySize,
			"wave_size":   campaign.WaveSize, "reboot_policy": string(campaign.RebootPolicy),
			"approval_fingerprint": campaign.ApprovalFingerprint,
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

// resolveTargets turns the selector into a host list.
func (s *Server) resolveTargets(r *http.Request, selector campaigns.Selector) ([]hosts.Host, error) {
	if len(selector.HostIDs) > 0 {
		result := make([]hosts.Host, 0, len(selector.HostIDs))
		for _, hostID := range selector.HostIDs {
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
	filter := hosts.ListFilter{
		Site:        selector.Site,
		Environment: selector.Environment,
		OSFamily:    selector.OSFamily,
	}
	result := make([]hosts.Host, 0, hosts.PageSize)
	afterName, afterID := "", ""
	for {
		page, err := s.hosts.Page(r.Context(), filter, afterName, afterID, hosts.PageSize)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if len(page) < hosts.PageSize {
			return result, nil
		}
		if len(result) > maxCampaignSnapshot {
			return nil, fmt.Errorf("%w: the selector covers more than %d hosts",
				ErrSelectorTooBroad, maxCampaignSnapshot)
		}
		last := page[len(page)-1]
		afterName, afterID = last.Hostname, last.ID
	}
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
	if _, ok := s.authorizeCollection(w, r, authz.PermCampaignRead, "campaign"); !ok {
		return
	}
	filter := hosts.ListFilter{
		Site:        r.URL.Query().Get("site"),
		Environment: r.URL.Query().Get("environment"),
		OSFamily:    r.URL.Query().Get("os_family"),
	}
	count, err := s.hosts.Count(r.Context(), filter)
	if err != nil {
		s.fail(w, err)
		return
	}
	response := map[string]any{
		"count": count,
		"limit": maxCampaignSnapshot,
	}

	// Without an operation the preview answers only the question "how many
	// hosts does this concern". The qualification depends on the operation:
	// hosts without a package adapter are ready for a service restart and
	// unable to update.
	action := opspec.ActionType(r.URL.Query().Get("action"))
	if action == "" {
		sample, err := s.hosts.Page(r.Context(), filter, "", "", previewSampleSize)
		if err != nil {
			s.fail(w, err)
			return
		}
		response["sample"] = hostNames(sample)
		writeJSON(w, http.StatusOK, response)
		return
	}
	if !action.Known() {
		problem(w, http.StatusBadRequest, "unknown_action", "unknown action "+string(action))
		return
	}

	// The qualification is computed on the same snapshot that would enter
	// the campaign. A preview computed differently than the creation would be
	// worse than none: the operator would approve one campaign and get
	// another.
	candidates, err := s.resolveTargets(r, campaigns.Selector{
		Site: filter.Site, Environment: filter.Environment, OSFamily: filter.OSFamily,
	})
	if errors.Is(err, ErrSelectorTooBroad) {
		problem(w, http.StatusBadRequest, "selector_too_broad", err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	assessment := assessCandidates(candidates, action, s.activeConflicts(r.Context()),
		time.Now().UTC())

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
	}
	order := []string{}
	by := map[string]*planGroup{}
	for _, entry := range entries {
		group, present := by[entry.PlanHash]
		if !present {
			group = &planGroup{PlanHash: entry.PlanHash, Plan: entry.Plan}
			by[entry.PlanHash] = group
			order = append(order, entry.PlanHash)
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
		"plan_set_hash": campaign.PlanSetHash,
	})
}

// handleCampaignReport builds the final report: the state totals, the
// split into waves and the list of hosts that need attention.
func (s *Server) handleCampaignReport(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	targets, err := s.campaigns.Targets(r.Context(), campaign.ID)
	if err != nil {
		s.fail(w, err)
		return
	}

	report := campaigns.Report{
		CampaignID: campaign.ID,
		State:      campaign.State,
		Totals:     map[string]int{},
		Failures:   []campaigns.Target{},
	}
	waveTotals := map[int]map[string]int{}
	waveOpen := map[int]bool{}
	for _, target := range targets {
		report.Totals[string(target.State)]++
		if waveTotals[target.Wave] == nil {
			waveTotals[target.Wave] = map[string]int{}
		}
		waveTotals[target.Wave][string(target.State)]++
		if !target.State.Finished() {
			waveOpen[target.Wave] = true
		}
		if target.State == campaigns.TargetFailed {
			report.Failures = append(report.Failures, target)
		}
		if target.State == campaigns.TargetRebooting || target.State == campaigns.TargetVerifying {
			report.RebootPending = append(report.RebootPending, target.HostID)
		}
	}
	for wave := 0; wave < len(waveTotals); wave++ {
		totals, exists := waveTotals[wave]
		if !exists {
			continue
		}
		report.Waves = append(report.Waves, campaigns.WaveSummary{
			Wave:      wave,
			IsCanary:  wave == 0,
			Totals:    totals,
			Completed: !waveOpen[wave],
		})
	}
	writeJSON(w, http.StatusOK, report)
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

	tx, err := s.campaigns.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	approved, err := s.campaigns.Approve(r.Context(), tx, campaign.ID, principal.Subject)
	if errors.Is(err, campaigns.ErrConflict) {
		problem(w, http.StatusConflict, "invalid_state",
			"the campaign is not awaiting approval (state "+string(campaign.State)+")")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign.approve", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"name": campaign.Name, "created_by": campaign.CreatedBy},
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

func (s *Server) handlePauseCampaign(w http.ResponseWriter, r *http.Request) {
	s.controlCampaign(w, r, "pause")
}

func (s *Server) handleResumeCampaign(w http.ResponseWriter, r *http.Request) {
	s.controlCampaign(w, r, "resume")
}

func (s *Server) handleCancelCampaign(w http.ResponseWriter, r *http.Request) {
	s.controlCampaign(w, r, "cancel")
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
