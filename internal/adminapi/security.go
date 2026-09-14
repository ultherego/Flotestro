package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/compliance"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/remediation"
)

// handleHostSecurity returns the compliance findings of a host together
// with the remediation plan.
//
// The assessment is made in the panel from the facts the host reports in
// the inventory anyway: there is no fleet sweep and no script executed on
// the host. Thanks to that the result is repeatable, and two hosts are
// assessed by the same check in the same version.
func (s *Server) handleHostSecurity(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermSecurityRead, scope, "host", hostID); !ok {
		return
	}

	report, err := s.assessCompliance(r, host)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// HostsPerCheckLimit bounds the host list at one check. The count is exact;
// the list is a sample, so the fleet screen does not become a printout of
// the whole inventory.
const HostsPerCheckLimit = 50

// checkView gathers one check at fleet scale.
type checkView struct {
	CheckID  string `json:"check_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Expected string `json:"expected"`
	Failed   int    `json:"failed"`
	Passed   int    `json:"passed"`
	Unknown  int    `json:"unknown"`
	// NotApplicable counts the hosts the check does not concern. Without
	// this column a host without SELinux would look non-compliant or
	// compliant.
	NotApplicable int `json:"not_applicable"`
	// Hosts lists the hosts that did not pass the check.
	Hosts []hostWithFinding `json:"hosts,omitempty"`
	// Fixable says how many of them have a remediation operation behind
	// them.
	Fixable int `json:"fixable"`
}

type hostWithFinding struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Observed string `json:"observed"`
	Action   string `json:"action,omitempty"`
}

// handleFleetSecurity returns the compliance of the whole visible fleet.
//
// The fleet view is the basic mode of this module: one bad setting on a
// hundred hosts is one problem, not a hundred - and that is visible only
// when the findings stand side by side.
func (s *Server) handleFleetSecurity(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSecurityRead, "fleet")
	if !ok {
		return
	}
	list, err := s.hosts.List(r.Context(), hosts.ListFilter{Limit: 500})
	if err != nil {
		s.fail(w, err)
		return
	}
	visible := make([]hosts.Host, 0, len(list))
	ids := make([]string, 0, len(list))
	for _, host := range list {
		if principal.Can(authz.PermSecurityRead, authz.Scope{Site: host.Site, Environment: host.Environment}) {
			visible = append(visible, host)
			ids = append(ids, host.ID)
		}
	}

	fragments, err := s.inventory.HostFragments(r.Context(), ids)
	if err != nil {
		s.fail(w, err)
		return
	}

	now := time.Now().UTC()
	checks := map[string]*checkView{}
	order := make([]string, 0, len(compliance.Checks))
	for _, check := range compliance.Checks {
		checks[check.ID] = &checkView{
			CheckID: check.ID, Title: check.Title,
			Severity: check.Severity, Expected: check.Expected,
		}
		order = append(order, check.ID)
	}

	for _, host := range visible {
		report := compliance.Evaluate(host.ID, hostInput(host, fragments[host.ID]), now)
		for _, finding := range report.Findings {
			view, ok := checks[finding.CheckID]
			if !ok {
				continue
			}
			switch {
			case !finding.Applicable:
				view.NotApplicable++
			case finding.Unknown:
				view.Unknown++
			case finding.Passed:
				view.Passed++
			default:
				view.Failed++
				if finding.Remediation != nil && finding.Remediation.Action != "" {
					view.Fixable++
				}
				if len(view.Hosts) < HostsPerCheckLimit {
					view.Hosts = append(view.Hosts, hostWithFinding{
						HostID: host.ID, Hostname: host.Hostname, Observed: finding.Observed,
						Action: remediationAction(finding),
					})
				}
			}
		}
	}

	results := make([]checkView, 0, len(order))
	for _, id := range order {
		results = append(results, *checks[id])
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Failed != results[j].Failed {
			return results[i].Failed > results[j].Failed
		}
		return results[i].CheckID < results[j].CheckID
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"hosts": len(visible), "checks": results, "generated_at": now,
	})
}

func remediationAction(finding compliance.Finding) string {
	if finding.Remediation == nil {
		return ""
	}
	return finding.Remediation.Action
}

// remediationRequest describes a remediation order.
type remediationRequest struct {
	// PlanHash binds the order to the state the operator viewed.
	PlanHash string `json:"plan_hash"`
	// CheckIDs lists the findings to fix. An empty list does not mean
	// "everything": the panel has no fix-all button.
	CheckIDs []string `json:"check_ids"`
	Reason   string   `json:"reason"`
	// StopOnFailure is enabled by default: the next steps assume the
	// previous ones succeeded.
	StopOnFailure *bool `json:"stop_on_failure,omitempty"`
}

// handleHostRemediation creates a remediation plan for the named findings.
//
// Remediation is not a separate operation on the host. Every step is an
// ordinary task of the module responsible for the given thing - with its
// permission, its risk and its approval. The remediation permission does
// not replace the permissions of those modules, it only adds to them.
//
// The steps go one after another, because each assumes the state left by
// the previous one; the plan stops after an error, and what managed to run
// stays visible.
func (s *Server) handleHostRemediation(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermSecurityRemediate, scope, "host", hostID)
	if !ok {
		return
	}
	if s.remediation == nil {
		problem(w, http.StatusServiceUnavailable, "remediation_disabled",
			"remediation plans are not enabled in this installation")
		return
	}

	var request remediationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	if len(request.CheckIDs) == 0 {
		problem(w, http.StatusBadRequest, "no_checks",
			"list the findings to fix; there is no fix-all")
		return
	}

	report, err := s.assessCompliance(r, host)
	if err != nil {
		s.fail(w, err)
		return
	}
	// The plan computed now must be the same plan the operator approved.
	// The host state changes on its own - between viewing the plan and
	// clicking the host may have been fixed by hand or broken further.
	if request.PlanHash == "" || request.PlanHash != report.PlanHash {
		problem(w, http.StatusConflict, "plan_stale",
			"the host state changed since this plan was computed; review the findings again")
		return
	}

	selected := map[string]bool{}
	for _, id := range request.CheckIDs {
		selected[id] = true
	}
	steps := make([]compliance.Finding, 0, len(request.CheckIDs))
	for _, finding := range report.Findings {
		if selected[finding.CheckID] {
			steps = append(steps, finding)
		}
	}
	if len(steps) != len(selected) {
		problem(w, http.StatusBadRequest, "unknown_check",
			"one of the listed findings does not exist in this plan")
		return
	}

	arranged, err := remediation.Arrange(steps)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_plan", err.Error())
		return
	}

	// The permissions are checked for the whole plan before creating
	// anything: half a remediation is worse than none, because it leaves the
	// host in a state nobody planned.
	requiresFreshAuth := false
	for _, step := range arranged.Steps {
		action := opspec.ActionType(step.ActionType)
		if _, ok := s.authorize(w, r, authz.Permission(action.Permission()), scope, "host", hostID); !ok {
			return
		}
		if action.RequiresTargetConfirmation() {
			problem(w, http.StatusBadRequest, "not_a_remediation",
				"finding "+step.CheckID+" maps to an irreversible operation; run it host by host")
			return
		}
		if capability := action.RequiredCapability(); !hostHasCapability(host, capability) {
			problem(w, http.StatusConflict, "capability_missing",
				"finding "+step.CheckID+" needs capability "+capability)
			return
		}
		if action.RequiresFreshAuth() {
			requiresFreshAuth = true
		}
	}

	// A plan reaching for a highest-risk operation requires fresh
	// authentication just like that operation ordered directly.
	var stepUpEvidence map[string]any
	if requiresFreshAuth {
		evidence, ok := s.requireStepUp(w, r, principal, request.Reason,
			"security.remediation.apply", "host", hostID)
		if !ok {
			return
		}
		stepUpEvidence = evidence
	}

	stopOnFailure := true
	if request.StopOnFailure != nil {
		stopOnFailure = *request.StopOnFailure
	}

	tx, err := s.remediation.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	plan, err := s.remediation.Create(r.Context(), tx, remediation.Spec{
		HostID:          hostID,
		PlanHash:        report.PlanHash,
		PlanHashVersion: report.PlanHashVersion,
		Reason:          request.Reason,
		CreatedBy:       principal.Subject,
		StopOnFailure:   stopOnFailure,
		BootIDBefore:    host.BootID,
	}, arranged.Steps)
	if errors.Is(err, remediation.ErrPlanRunning) {
		problem(w, http.StatusConflict, "plan_in_progress",
			"a remediation plan is already running on this host")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "security.remediate", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"plan_id": plan.ID, "plan_hash": report.PlanHash,
			"plan_hash_version": report.PlanHashVersion,
			"steps":             stepNames(arranged.Steps), "skipped": arranged.Skipped,
			"stop_on_failure": stopOnFailure, "reason": request.Reason,
			"step_up": stepUpEvidence,
		},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"plan": plan, "skipped": arranged.Skipped,
	})
}

// handleListRemediation returns the last remediation plans of a host.
func (s *Server) handleListRemediation(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermSecurityRead, scope, "host", hostID); !ok {
		return
	}
	if s.remediation == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}, "count": 0})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	plans, err := s.remediation.ForHost(r.Context(), hostID, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	if plans == nil {
		plans = []remediation.Plan{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": plans, "count": len(plans)})
}

// handleStopRemediation stops a plan in progress.
//
// A step already delivered to the host ends its own way - the panel does
// not pretend to have revoked what the host is just executing - but its
// task is cancelled, and the steps not started yet do not move.
func (s *Server) handleStopRemediation(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermSecurityRemediate, scope, "host", hostID)
	if !ok {
		return
	}
	if s.remediation == nil {
		problem(w, http.StatusServiceUnavailable, "remediation_disabled",
			"remediation plans are not enabled in this installation")
		return
	}

	plan, err := s.remediation.Plan(r.Context(), r.PathValue("plan"))
	if errors.Is(err, remediation.ErrNotFound) || (plan != nil && plan.HostID != hostID) {
		problem(w, http.StatusNotFound, "plan_not_found", "no such remediation plan on this host")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if plan.State != remediation.StateRunning {
		problem(w, http.StatusConflict, "plan_finished", "this plan is already finished")
		return
	}

	if current := plan.Current(); current != nil && current.JobID != "" {
		tx, err := s.jobs.Pool().Begin(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()
		if _, err := s.jobs.Cancel(r.Context(), tx, current.JobID, principal.Subject,
			"remediation plan stopped"); err == nil {
			_ = tx.Commit(r.Context())
		}
	}
	if err := s.remediation.SkipRemaining(r.Context(), plan.ID, "plan stopped by the operator"); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.remediation.FinishPlan(r.Context(), plan.ID, remediation.StateStopped); err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "security.remediate.stop", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"plan_id": plan.ID},
	})

	updated, err := s.remediation.Plan(r.Context(), plan.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// fleetRemediationRequest describes a fleet remediation: the checks to fix
// and the hosts to fix them on. Both are chosen; neither is implied.
type fleetRemediationRequest struct {
	CheckIDs []string           `json:"check_ids"`
	Selector campaigns.Selector `json:"selector"`
	// The rest concerns the order only, not the preview.
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason,omitempty"`
	// The rollout. The defaults follow the module's policy: a canary of
	// one, waves of five, two hosts at once.
	CanarySize              *int  `json:"canary_size,omitempty"`
	WaveSize                *int  `json:"wave_size,omitempty"`
	MaxConcurrent           *int  `json:"max_concurrent,omitempty"`
	FailureThresholdPercent *int  `json:"failure_threshold_percent,omitempty"`
	ManualGate              *bool `json:"manual_gate,omitempty"`
	// OfflinePolicy may only tighten what the operation declares.
	OfflinePolicy   string `json:"offline_policy,omitempty"`
	DeadlineMinutes *int   `json:"deadline_minutes,omitempty"`
	IdempotencyKey  string `json:"idempotency_key,omitempty"`
}

// The ceilings of a remediation rollout. Wider waves than this are several
// waves: every step is a change of the module that owns it, and a wave of
// a hundred sshd rewrites is not a trial on a small group.
const (
	maxRemediationWave = 20
	// ReasonNoPlan means a host the chosen checks give no step on: they
	// passed, do not apply, are unknown or have no remediating operation.
	ReasonNoPlan = "no_plan"
)

// remediationCandidate is a host with its computed plan.
type remediationCandidate struct {
	host        hosts.Host
	arrangement remediation.Arrangement
}

// excludedHost is a host of the snapshot that will not move, as the
// preview shows it.
type excludedHost struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Reason   string `json:"reason"`
	Message  string `json:"message"`
}

// fleetRemediation is the computed shape of a fleet remediation: the
// snapshot, every ready host's plan and the plans grouped.
//
// One function computes it for the preview and for the order. A drift
// between them would be the worst kind of bug: the operator would approve a
// different set of plans than the one they read.
type fleetRemediation struct {
	CheckIDs    []string
	Selector    campaigns.Selector
	Candidates  []hosts.Host
	Ready       []remediationCandidate
	Closed      []closedHost
	Notes       []hostGroup
	Groups      []remediation.Group
	GeneratedAt time.Time
}

func (f fleetRemediation) excluded() []excludedHost {
	list := make([]excludedHost, 0, len(f.Closed))
	for _, entry := range f.Closed {
		list = append(list, excludedHost{
			HostID: entry.Host.ID, Hostname: entry.Host.Hostname,
			Reason: entry.Reason, Message: entry.Message,
		})
	}
	return list
}

func (f fleetRemediation) exclusions() []hostGroup {
	return qualification{Closed: f.Closed}.Exclusions()
}

// targets assembles the campaign snapshot: the hosts with a plan, and the
// closed ones with their reasons.
func (f fleetRemediation) targets() []campaigns.TargetHost {
	targets := make([]campaigns.TargetHost, 0, len(f.Ready)+len(f.Closed))
	for _, candidate := range f.Ready {
		targets = append(targets, campaigns.TargetHost{ID: candidate.host.ID, BootID: candidate.host.BootID})
	}
	for _, entry := range f.Closed {
		targets = append(targets, campaigns.TargetHost{
			ID: entry.Host.ID, BootID: entry.Host.BootID,
			State: entry.State, Reason: entry.Reason, Message: entry.Message,
		})
	}
	return targets
}

// plans returns the per-host plans as the campaign records them.
func (f fleetRemediation) plans() ([]campaigns.HostPlanSpec, error) {
	plans := make([]campaigns.HostPlanSpec, 0, len(f.Ready))
	for _, candidate := range f.Ready {
		content, err := json.Marshal(candidate.arrangement.Plan)
		if err != nil {
			return nil, err
		}
		plans = append(plans, campaigns.HostPlanSpec{
			HostID: candidate.host.ID, PlanHash: candidate.arrangement.Hash, Plan: content,
		})
	}
	return plans, nil
}

// planFleetRemediation computes the fleet remediation for a request. The
// answer has already been written when the second result is false.
//
// The operator picks checks and hosts: an empty check list or an empty
// selector is a refusal, not "everything". Every host that the selector
// matched stays in the snapshot - ready with its plan, or closed with a
// reason the approver reads - and the ready plans are grouped by their
// steps, because a hundred hosts with the same change are one change.
func (s *Server) planFleetRemediation(w http.ResponseWriter, r *http.Request,
	request fleetRemediationRequest, principal authz.Principal) (*fleetRemediation, bool) {
	checkIDs, ok := checkChoice(w, request.CheckIDs)
	if !ok {
		return nil, false
	}
	if request.Selector.Empty() {
		problem(w, http.StatusBadRequest, "selector_required",
			"name the hosts to fix: a site, an environment, an expression or a host list; there is no fix-all")
		return nil, false
	}
	chosen, ok := s.checkSelector(w, request.Selector)
	if !ok {
		return nil, false
	}
	candidates, ok := s.materialize(w, r, chosen)
	if !ok {
		return nil, false
	}
	if len(candidates) == 0 {
		problem(w, http.StatusBadRequest, "no_targets", "the selector matched no hosts")
		return nil, false
	}

	now := time.Now().UTC()
	result := &fleetRemediation{CheckIDs: checkIDs, Selector: chosen, Candidates: candidates, GeneratedAt: now}

	// A host outside the reading scope is in the snapshot as closed: the
	// preview must not describe findings the principal may not read, and
	// the order refuses such a host outright below.
	visible := make([]hosts.Host, 0, len(candidates))
	for _, host := range candidates {
		if !principal.Can(authz.PermSecurityRead, authz.Scope{Site: host.Site, Environment: host.Environment}) {
			result.Closed = append(result.Closed, closedHost{
				Host: host, State: campaigns.TargetIneligible, Reason: ReasonOutOfScope,
				Message: "the host is outside the scope of your security permissions",
			})
			continue
		}
		visible = append(visible, host)
	}
	kept, excluded := excludeHosts(visible, chosen, principal.Subject)
	assessment := assessCandidates(kept, opspec.ActionSecurityRemediate, s.activeConflicts(r.Context()), now)
	result.Closed = append(result.Closed, excluded...)
	result.Closed = append(result.Closed, assessment.Closed...)
	result.Notes = assessment.Notes

	fragments, err := s.inventory.HostFragments(r.Context(), hostIDs(assessment.Ready))
	if err != nil {
		s.fail(w, err)
		return nil, false
	}

	byHost := map[remediation.Host]remediation.Arrangement{}
	for _, host := range assessment.Ready {
		report := compliance.Evaluate(host.ID, hostInput(host, fragments[host.ID]), now)
		arrangement, err := remediation.ArrangeForChecks(report, checkIDs)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_plan", host.Hostname+": "+err.Error())
			return nil, false
		}
		if arrangement.Empty() {
			result.Closed = append(result.Closed, closedHost{
				Host: host, State: campaigns.TargetIneligible, Reason: ReasonNoPlan,
				Message: describeSkipped(checkIDs, arrangement.Skipped),
			})
			continue
		}
		if reason := stepRefusal(host, arrangement.Plan.Plan.Steps); reason != "" {
			if strings.HasPrefix(reason, "capability ") {
				result.Closed = append(result.Closed, closedHost{
					Host: host, State: campaigns.TargetIneligible,
					Reason: ReasonCapabilityMissing, Message: reason,
				})
				continue
			}
			problem(w, http.StatusBadRequest, "not_a_remediation", reason)
			return nil, false
		}
		result.Ready = append(result.Ready, remediationCandidate{host: host, arrangement: arrangement})
		byHost[remediation.Host{HostID: host.ID, Hostname: host.Hostname}] = arrangement
	}
	result.Groups = remediation.GroupPlans(byHost)
	return result, true
}

// checkChoice validates the chosen checks: named, known and not repeated.
func checkChoice(w http.ResponseWriter, ids []string) ([]string, bool) {
	if len(ids) == 0 {
		problem(w, http.StatusBadRequest, "no_checks", "list the checks to fix; there is no fix-all")
		return nil, false
	}
	known := map[string]bool{}
	for _, check := range compliance.Checks {
		known[check.ID] = true
	}
	seen := map[string]bool{}
	chosen := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if !known[id] {
			problem(w, http.StatusBadRequest, "unknown_check", "the check "+id+" does not exist")
			return nil, false
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		chosen = append(chosen, id)
	}
	sort.Strings(chosen)
	return chosen, true
}

// describeSkipped says, check by check, why a host got no step.
func describeSkipped(checkIDs []string, skipped map[string]string) string {
	parts := make([]string, 0, len(checkIDs))
	for _, id := range checkIDs {
		if reason, ok := skipped[id]; ok {
			parts = append(parts, id+": "+reason)
		}
	}
	return strings.Join(parts, "; ")
}

// stepRefusal names the step a host cannot run: an irreversible operation
// that needs its target typed, or an adapter the host lacks. An empty
// result means every step may go.
func stepRefusal(host hosts.Host, steps []remediation.Step) string {
	for _, step := range steps {
		action := opspec.ActionType(step.ActionType)
		if action.RequiresTargetConfirmation() {
			return "finding " + step.CheckID + " maps to an irreversible operation; run it host by host"
		}
		if capability := action.RequiredCapability(); !hostHasCapability(&host, capability) {
			return "capability " + capability + " is missing for finding " + step.CheckID
		}
	}
	return ""
}

// handleFleetRemediationPreview answers what a fleet remediation would do:
// the per-host plans grouped by their steps, and the hosts that get none.
//
// A preview is a read of the findings: it needs the reading permission
// and changes nothing. The order goes through the composite permission
// check, which the preview does not, so the preview may show more than
// the order will accept.
func (s *Server) handleFleetRemediationPreview(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSecurityRead, "fleet")
	if !ok {
		return
	}
	var request fleetRemediationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	plan, ok := s.planFleetRemediation(w, r, request, principal)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"check_ids": plan.CheckIDs, "hosts": len(plan.Candidates), "eligible": len(plan.Ready),
		"groups": plan.Groups, "excluded": plan.excluded(), "notes": plan.Notes,
		"generated_at": plan.GeneratedAt,
	})
}

// handleFleetRemediation orders a fleet remediation as a campaign.
//
// The plans are the same the preview showed, computed again now: the
// campaign records every host's steps, and the approval fingerprint covers
// the whole set, so the consent concerns those steps on those hosts. The
// composite permission is checked before anything is created - the
// remediation permission and the permission of every step's operation, in
// the scope of every host - and refused as a whole: half a fleet
// remediation is a fleet in a state nobody planned.
func (s *Server) handleFleetRemediation(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSecurityRemediate, "fleet")
	if !ok {
		return
	}
	var request fleetRemediationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	action := opspec.ActionSecurityRemediate
	offlinePolicy, err := opspec.ResolveOfflinePolicy(action, opspec.OfflinePolicy(request.OfflinePolicy))
	if errors.Is(err, opspec.ErrOfflinePolicyLoosened) {
		problem(w, http.StatusBadRequest, "offline_policy_loosened", err.Error())
		return
	}
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_offline_policy", err.Error())
		return
	}

	plan, ok := s.planFleetRemediation(w, r, request, principal)
	if !ok {
		return
	}
	if len(plan.Ready) == 0 {
		problem(w, http.StatusBadRequest, "no_eligible_targets",
			"no matched host gets a plan from these checks: "+describeExclusions(plan.exclusions()))
		return
	}

	// The composite permission, host by host, step by step. The first
	// missing one ends the order and is named; nothing has been created.
	for _, host := range plan.Candidates {
		scope := authz.Scope{Site: host.Site, Environment: host.Environment}
		if _, ok := s.authorize(w, r, authz.PermCampaignCreate, scope, "host", host.ID); !ok {
			return
		}
		if _, ok := s.authorize(w, r, authz.PermSecurityRemediate, scope, "host", host.ID); !ok {
			return
		}
	}
	for _, candidate := range plan.Ready {
		scope := authz.Scope{Site: candidate.host.Site, Environment: candidate.host.Environment}
		for _, step := range candidate.arrangement.Plan.Actions() {
			permission := authz.Permission(opspec.ActionType(step).Permission())
			if _, ok := s.authorize(w, r, permission, scope, "host", candidate.host.ID); !ok {
				return
			}
		}
	}

	// A fleet remediation is the highest-risk order of the module: one
	// consent changes many hosts through operations that may each cut off
	// access. It requires fresh authentication like any critical campaign.
	stepUpEvidence, ok := s.requireStepUp(w, r, principal, request.Reason,
		"security.remediation.apply", "campaign", "")
	if !ok {
		return
	}

	payload := opspec.Payload{Security: &opspec.SecurityPayload{CheckIDs: plan.CheckIDs}}
	if err := opspec.ValidateRemediationOrder(payload); err != nil {
		problem(w, http.StatusBadRequest, "invalid_payload", err.Error())
		return
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		s.fail(w, err)
		return
	}
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = "Security remediation: " + strings.Join(plan.CheckIDs, ", ")
	}
	spec := campaigns.Spec{
		Name:       name,
		ActionType: string(action),
		Payload:    encodedPayload,
		Selector:   plan.Selector,
		CanarySize: valueOrDefault(request.CanarySize, 1),
		// The waves and the concurrency follow the module's policy and are
		// bounded whatever the request says: every step is a change of the
		// module that owns it.
		WaveSize:                min(valueOr(request.WaveSize, 5), maxRemediationWave),
		MaxConcurrent:           min(valueOr(request.MaxConcurrent, 2), maxCampaignConcurrency),
		FailureThresholdPercent: valueOrDefault(request.FailureThresholdPercent, 20),
		RebootPolicy:            campaigns.RebootNever,
		JobTimeoutSeconds:       action.DefaultTimeout(),
		RequiresApproval:        true,
		OfflinePolicy:           offlinePolicy,
		DeadlineMinutes:         valueOr(request.DeadlineMinutes, int(campaigns.DefaultDeadline/time.Minute)),
		ManualGate:              request.ManualGate != nil && *request.ManualGate,
		CreatedBy:               principal.Subject,
		RequestID:               requestIDOf(r),
		IdempotencyKey:          idempotencyKeyOf(r, request.IdempotencyKey),
	}
	plans, err := plan.plans()
	if err != nil {
		s.fail(w, err)
		return
	}

	tx, err := s.campaigns.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	campaign, err := s.campaigns.CreatePlanned(r.Context(), tx, spec, plan.targets(), plans)
	if errors.Is(err, campaigns.ErrRepeated) {
		_ = tx.Rollback(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"campaign": campaign, "groups": plan.Groups, "excluded": plan.excluded()})
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
			"check_ids":     plan.CheckIDs, "targets": len(plan.Candidates),
			"eligible": len(plan.Ready), "excluded": plan.exclusions(), "notes": plan.Notes,
			"plan_groups": len(plan.Groups), "plan_set_hash": campaign.PlanSetHash,
			"selector": plan.Selector.Expression.Describe(), "exclude_reason": plan.Selector.ExcludeReason,
			"canary_size": campaign.CanarySize, "wave_size": campaign.WaveSize,
			"max_concurrent": campaign.MaxConcurrent, "manual_gate": campaign.ManualGate,
			"offline_policy": string(campaign.OfflinePolicy), "deadline_at": campaign.DeadlineAt,
			"approval_fingerprint": campaign.ApprovalFingerprint, "reason": request.Reason,
		}, stepUpEvidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"campaign": campaign, "groups": plan.Groups, "excluded": plan.excluded(),
	})
}

func stepNames(steps []remediation.Step) []string {
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, step.CheckID+":"+step.ActionType)
	}
	return names
}

// assessCompliance computes the findings for a host from the inventory
// fragments.
func (s *Server) assessCompliance(r *http.Request, host *hosts.Host) (compliance.Report, error) {
	fragments, err := s.inventory.Fragments(r.Context(), host.ID)
	if err != nil {
		return compliance.Report{}, err
	}
	return compliance.Evaluate(host.ID, hostInput(*host, fragments), time.Now().UTC()), nil
}

// hostInput assembles everything the checks are computed from.
func hostInput(host hosts.Host, fragments []inventory.Fragment) compliance.Input {
	input := compliance.Input{
		Host: compliance.Host{
			Hostname:               host.Hostname,
			OSFamily:               host.OSFamily,
			PendingSecurityUpdates: host.PendingSecurityUpdates,
			RebootRequired:         host.RebootRequired,
		},
		Fragments: map[string]compliance.Fragment{},
	}
	for _, fragment := range fragments {
		input.Fragments[fragment.Module] = convert(fragment)
	}
	return input
}

func convert(fragment inventory.Fragment) compliance.Fragment {
	return compliance.Fragment{
		Module:            fragment.Module,
		Revision:          fragment.Revision,
		Payload:           fragment.Payload,
		ObservedAt:        fragment.ObservedAt,
		UnavailableReason: strings.TrimSpace(fragment.UnavailableReason),
	}
}
