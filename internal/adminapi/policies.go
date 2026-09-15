package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	managedfiles "github.com/ultherego/flotestro/internal/files"
	"github.com/ultherego/flotestro/internal/paging"
	"github.com/ultherego/flotestro/internal/policy"
	"github.com/ultherego/flotestro/internal/selector"
)

// Desired-state policies.
//
// A policy is edited as a draft, published as a version and judged by the
// loop from the inventory. The publication is the approval the document
// names: it asks for fresh authentication like the approval of a
// campaign, and a policy that remediates automatically asks for the
// separate permission besides. The handlers write nothing to a host; the
// only change they can set in motion is a campaign, ordered by the
// evaluator through the same path a fleet remediation takes, and that
// campaign waits for its approval like any other.

// policyStore opens the store on the panel's pool. The store is a view
// on the pool, so opening it per request costs nothing and the server
// keeps no field for it.
func (s *Server) policyStore() *policy.Store { return policy.NewStore(s.pool) }

// policyEvaluator builds the evaluator with the stores the panel already
// holds: the same judgement the loop runs, ordered now.
func (s *Server) policyEvaluator() *policy.Evaluator {
	return policy.NewEvaluator(s.policyStore(), s.hosts, s.inventory, s.groups, s.hostPackages,
		s.files, s.campaigns, s.audit, s.authz, s.log)
}

// policyETag names the version of the record an editor holds: the
// document changes with updated_at, the publication with the version.
func policyETag(p *policy.Policy) string {
	return etagOf(paging.FormatTime(p.UpdatedAt), strconv.Itoa(p.Version))
}

// handleListPolicies lists the policies with the counts of their latest
// verdicts.
func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermPolicyRead, "policy"); !ok {
		return
	}
	policies, err := s.policyStore().List(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": policies, "count": len(policies)})
}

// readPolicySpec decodes and checks a draft. The answer has been written
// when the second result is false.
func (s *Server) readPolicySpec(w http.ResponseWriter, r *http.Request) (policy.Spec, bool) {
	var spec policy.Spec
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&spec); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON: "+err.Error())
		return spec, false
	}
	if spec.RemediationMode == "" {
		spec.RemediationMode = policy.ModeReport
	}
	if err := spec.Validate(); err != nil {
		problem(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return spec, false
	}
	// The selector is checked the way a campaign's is: the exclusions
	// need their reason, the expression its grammar.
	chosen, ok := s.checkSelector(w, spec.Selector)
	if !ok {
		return spec, false
	}
	spec.Selector = chosen
	// A draft may be half-written, but a rule of a kind the panel does
	// not know is refused at once: the editor is to learn it now, not at
	// the publication.
	for index, rule := range spec.Rules {
		if rule.Kind != "" && !knownKind(rule.Kind) {
			problem(w, http.StatusBadRequest, "unsupported_rule",
				policy.ErrUnsupportedRule{Index: index, Kind: rule.Kind}.Error())
			return spec, false
		}
	}
	return spec, true
}

func knownKind(kind string) bool {
	for _, known := range policy.Kinds {
		if known == kind {
			return true
		}
	}
	return false
}

// handleCreatePolicy records a draft.
func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermPolicyWrite, "policy")
	if !ok {
		return
	}
	spec, ok := s.readPolicySpec(w, r)
	if !ok {
		return
	}
	created, err := s.policyStore().Create(r.Context(), spec, principal.Subject)
	if errors.Is(err, policy.ErrNameTaken) {
		problem(w, http.StatusConflict, "name_taken", "a policy with this name exists")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "policy.create", TargetType: "policy", TargetID: created.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"name": created.Name, "remediation_mode": created.RemediationMode,
			"rules": len(created.Rules)},
		After: policy.DocumentOf(*created),
	})
	setETag(w, policyETag(created))
	writeJSON(w, http.StatusCreated, created)
}

// policyFor reads the policy of the request and checks the permission.
// The answer has been written when the second result is false.
func (s *Server) policyFor(w http.ResponseWriter, r *http.Request, permission authz.Permission) (*policy.Policy, bool) {
	if _, ok := s.authorizeCollection(w, r, permission, "policy"); !ok {
		return nil, false
	}
	found, err := s.policyStore().Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, policy.ErrNotFound) {
		problem(w, http.StatusNotFound, "policy_not_found", "no such policy")
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return found, true
}

// handleGetPolicy serves one policy with its entity tag.
func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	found, ok := s.policyFor(w, r, authz.PermPolicyRead)
	if !ok {
		return
	}
	setETag(w, policyETag(found))
	writeJSON(w, http.StatusOK, found)
}

// handleUpdatePolicy rewrites the draft on the version the editor read.
func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	found, ok := s.policyFor(w, r, authz.PermPolicyWrite)
	if !ok {
		return
	}
	if !requireMatch(w, r, policyETag(found)) {
		return
	}
	spec, ok := s.readPolicySpec(w, r)
	if !ok {
		return
	}
	principal := authz.FromContext(r.Context())
	updated, err := s.policyStore().Update(r.Context(), found.ID, spec)
	if errors.Is(err, policy.ErrNameTaken) {
		problem(w, http.StatusConflict, "name_taken", "a policy with this name exists")
		return
	}
	if errors.Is(err, policy.ErrNotFound) {
		problem(w, http.StatusNotFound, "policy_not_found", "no such policy")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "policy.update", TargetType: "policy", TargetID: updated.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"name": updated.Name, "remediation_mode": updated.RemediationMode,
			"rules": len(updated.Rules), "draft": updated.Draft},
		Before: policy.DocumentOf(*found), After: policy.DocumentOf(*updated),
	})
	setETag(w, policyETag(updated))
	writeJSON(w, http.StatusOK, updated)
}

// handleDeletePolicy removes a policy. Its campaigns stay, unlinked.
func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	found, ok := s.policyFor(w, r, authz.PermPolicyWrite)
	if !ok {
		return
	}
	if !requireMatch(w, r, policyETag(found)) {
		return
	}
	principal := authz.FromContext(r.Context())
	if err := s.policyStore().Delete(r.Context(), found.ID); err != nil && !errors.Is(err, policy.ErrNotFound) {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "policy.delete", TargetType: "policy", TargetID: found.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"name": found.Name, "version": found.Version},
		Before: policy.DocumentOf(*found),
	})
	w.WriteHeader(http.StatusNoContent)
}

// handlePublishPolicy freezes the draft as the next version.
//
// The publication is where the rules are held to their kinds, where the
// mode is held to the permission it needs and where the publisher
// authenticates afresh: from this moment the loop judges the fleet by
// this text, and in automatic mode changes it on the publisher's
// authority.
func (s *Server) handlePublishPolicy(w http.ResponseWriter, r *http.Request) {
	found, ok := s.policyFor(w, r, authz.PermPolicyPublish)
	if !ok {
		return
	}
	principal := authz.FromContext(r.Context())
	var request struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request)
	}
	if err := policy.ValidateRules(found.Rules, found.RemediationMode); err != nil {
		var unsupported policy.ErrUnsupportedRule
		var invalid policy.ErrInvalidRule
		var bound policy.ErrApprovalBound
		switch {
		case errors.As(err, &unsupported):
			problem(w, http.StatusBadRequest, "unsupported_rule", err.Error())
		case errors.As(err, &invalid):
			problem(w, http.StatusBadRequest, "invalid_rule", err.Error())
		case errors.As(err, &bound):
			problem(w, http.StatusBadRequest, "approval_bound_rule", err.Error())
		case errors.Is(err, policy.ErrNoRules):
			problem(w, http.StatusBadRequest, "no_rules", err.Error())
		default:
			problem(w, http.StatusBadRequest, "invalid_policy", err.Error())
		}
		return
	}
	if policy.DocumentOf(*found).Selector.Empty() {
		problem(w, http.StatusBadRequest, "selector_required",
			"name the hosts the policy concerns: a site, an environment, an expression or a host list; there is no policy over nobody")
		return
	}
	// A file rule names a version the panel holds; a digest nobody
	// uploaded would judge every host as drifted with nothing to fix.
	for index, rule := range found.Rules {
		if rule.Kind != policy.KindFileContent {
			continue
		}
		if _, err := s.files.Content(r.Context(), rule.SHA256); errors.Is(err, managedfiles.ErrNotFound) {
			problem(w, http.StatusBadRequest, "version_unknown",
				policy.ErrInvalidRule{Index: index, Reason: "the panel holds no file version " + rule.SHA256}.Error())
			return
		} else if err != nil {
			s.fail(w, err)
			return
		}
	}
	// The automatic mode needs the separate permission somewhere in the
	// fleet; the evaluator holds every host to the publisher's scope when
	// the drift is found.
	if found.RemediationMode == policy.ModeAutomatic {
		if _, ok := s.authorizeCollection(w, r, authz.PermPolicyRemediateAuto, "policy"); !ok {
			return
		}
	}
	stepUpEvidence, ok := s.requireStepUp(w, r, principal, request.Reason, "policy.publish", "policy", found.ID)
	if !ok {
		return
	}

	publication := policy.Publication{
		PublishedBy: principal.Subject, Reason: strings.TrimSpace(request.Reason), Authentication: "api_token",
	}
	if session, ok := authz.SessionFromContext(r.Context()); ok && session != nil {
		publication.Authentication = "session"
		publication.ACR = session.Auth.ACR
		publication.AMR = session.Auth.AMR
		if !session.Auth.At.IsZero() {
			at := session.Auth.At.UTC()
			publication.AuthenticatedAt = &at
		}
	}
	published, version, err := s.policyStore().Publish(r.Context(), found.ID, publication)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "policy.publish", TargetType: "policy", TargetID: published.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		ApprovalChain: &audit.ApprovalChain{CreatedBy: found.CreatedBy, Approvers: []string{principal.Subject}},
		Detail: withStepUp(map[string]any{
			"name": published.Name, "version": published.Version, "remediation_mode": published.RemediationMode,
			"rules": len(published.Rules), "reason": publication.Reason,
			"selector": policy.DocumentOf(*published).Selector.Expression.Describe(),
		}, stepUpEvidence),
		Before: map[string]any{"version": found.Version},
		After:  map[string]any{"version": published.Version, "document": version.Document},
	})
	setETag(w, policyETag(published))
	writeJSON(w, http.StatusOK, published)
}

// handlePolicyVersions lists the publications, newest first.
func (s *Server) handlePolicyVersions(w http.ResponseWriter, r *http.Request) {
	found, ok := s.policyFor(w, r, authz.PermPolicyRead)
	if !ok {
		return
	}
	versions, err := s.policyStore().Versions(r.Context(), found.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": versions, "count": len(versions)})
}

// handlePolicyCampaigns lists the remediation campaigns the policy
// ordered, newest first.
func (s *Server) handlePolicyCampaigns(w http.ResponseWriter, r *http.Request) {
	found, ok := s.policyFor(w, r, authz.PermPolicyRead)
	if !ok {
		return
	}
	links, err := s.policyStore().Campaigns(r.Context(), found.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": links, "count": len(links)})
}

// handlePolicyResults pages through the verdicts of a policy.
func (s *Server) handlePolicyResults(w http.ResponseWriter, r *http.Request) {
	found, ok := s.policyFor(w, r, authz.PermPolicyRead)
	if !ok {
		return
	}
	query := r.URL.Query()
	filter := policy.ResultFilter{HostID: strings.TrimSpace(query.Get("host_id")), Verdict: strings.TrimSpace(query.Get("verdict"))}
	switch filter.Verdict {
	case "", policy.VerdictCompliant, policy.VerdictDrift, policy.VerdictError, policy.VerdictNotApplicable:
	default:
		problem(w, http.StatusBadRequest, "invalid_filter", "verdict is compliant, drift, error or not_applicable")
		return
	}
	asCSV, ok := exportFormat(w, r)
	if !ok {
		return
	}
	if asCSV {
		s.writePolicyResultsCSV(w, r, found, filter)
		return
	}
	requested, _ := strconv.Atoi(query.Get("limit"))
	limit := paging.Limit(requested, 100, 500)
	results, next, total, err := s.policyStore().Results(r.Context(), found.ID, filter, query.Get("cursor"), limit)
	if errors.Is(err, paging.ErrInvalidCursor) {
		problem(w, http.StatusBadRequest, "invalid_cursor", "the cursor does not belong to this list")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": results, "count": len(results), "total": total, "next_cursor": next,
	})
}

// policyResultsCSVColumns is the header of the verdict export. The order
// is fixed: a sheet built against one export reads the next one.
var policyResultsCSVColumns = []string{
	"policy_id", "policy_name", "hostname", "host_id", "rule_index", "rule_kind", "rule_subject",
	"version", "verdict", "reason", "observed_revision", "evaluated_at",
}

// writePolicyResultsCSV streams the verdicts of a policy as a file: the
// same host and verdict filter as the JSON list, every page of it, in
// the order of the list. The pages come one at a time from the store;
// the file ends with a truncation row past exportRowLimit verdicts. The
// file is named after the policy so two policies' exports do not collide
// in a download folder.
func (s *Server) writePolicyResultsCSV(w http.ResponseWriter, r *http.Request, found *policy.Policy, filter policy.ResultFilter) {
	s.writeCSV(w, r, exportFileName("policy-"+found.ID+"-results", time.Now()), policyResultsCSVColumns,
		func(yield func([]string) bool) error {
			cursor := ""
			for {
				results, next, _, err := s.policyStore().Results(r.Context(), found.ID, filter, cursor, maxListPage)
				if err != nil {
					return err
				}
				for _, result := range results {
					if !yield(policyResultCSVRow(result)) {
						return nil
					}
				}
				if next == "" {
					return nil
				}
				cursor = next
			}
		})
}

// policyResultCSVRow renders one verdict in the order of
// policyResultsCSVColumns. The rule is named by its kind and subject - the
// package, the unit, the path, the key or the account - as the screen
// names it; the whole declaration is read on the policy page.
func policyResultCSVRow(result policy.Result) []string {
	kind, subject := "", ""
	if result.Rule != nil {
		kind, subject = result.Rule.Kind, result.Rule.Subject()
	}
	return []string{
		result.PolicyID, result.PolicyName, result.Hostname, result.HostID, strconv.Itoa(result.RuleIndex), kind, subject,
		strconv.Itoa(result.Version), result.Verdict, result.Reason, result.ObservedRevision, csvInstant(result.EvaluatedAt),
	}
}

// handleHostPolicies lists the verdicts of every policy on one host.
func (s *Server) handleHostPolicies(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermPolicyRead, scope, "host", hostID); !ok {
		return
	}
	results, err := s.policyStore().ForHost(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": results, "count": len(results)})
}

// handleEvaluatePolicy runs one evaluation now: the same judgement the
// loop runs at the interval, with the same consequences in the
// policy's mode. The caller triggers it; the remediation, if any, is
// ordered on the publisher's authority, not the caller's.
func (s *Server) handleEvaluatePolicy(w http.ResponseWriter, r *http.Request) {
	found, ok := s.policyFor(w, r, authz.PermPolicyWrite)
	if !ok {
		return
	}
	if found.Version == 0 {
		problem(w, http.StatusConflict, "not_published", "the policy has not been published; there is nothing to judge by")
		return
	}
	outcome, err := s.policyEvaluator().Evaluate(r.Context(), *found)
	switch {
	case errors.Is(err, selector.ErrCycle), errors.Is(err, selector.ErrUnknownGroup), errors.Is(err, selector.ErrInvalid):
		s.selectorProblem(w, err)
		return
	case err != nil && strings.HasPrefix(err.Error(), policy.ReasonSelectorFailed):
		problem(w, http.StatusBadRequest, "selector_failed", err.Error())
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	principal := authz.FromContext(r.Context())
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "policy.evaluate", TargetType: "policy", TargetID: found.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"name": found.Name, "version": outcome.Version, "hosts": outcome.Hosts,
			"counts": outcome.Counts, "campaign_id": outcome.CampaignID, "remediation": outcome.Remediation},
	})
	writeJSON(w, http.StatusOK, outcome)
}
