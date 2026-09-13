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
