package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/compliance"
	managedfiles "github.com/ultherego/flotestro/internal/files"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/remediation"
	"github.com/ultherego/flotestro/internal/selector"
	"github.com/ultherego/flotestro/internal/vuln"
)

// Authorizer resolves the publisher of a policy when its remediation is
// ordered: the campaign is created on their authority, hours or days
// after the publication, so their rights are read then and not assumed.
type Authorizer interface {
	PrincipalBySubject(ctx context.Context, subject string) (*authz.Principal, error)
}

// Evaluator judges the fleet against a policy and orders the remediation
// its mode asks for.
type Evaluator struct {
	store      *Store
	hosts      *hosts.Store
	inventory  *inventory.Store
	groups     selector.Groups
	packages   *vuln.PackageStore
	files      *managedfiles.Store
	campaigns  *campaigns.Store
	audit      *audit.Recorder
	authorizer Authorizer
	log        *slog.Logger
}

// NewEvaluator wires the stores the judgement reads and the campaign
// store the remediation writes.
func NewEvaluator(store *Store, hostStore *hosts.Store, inventoryStore *inventory.Store,
	groups selector.Groups, packageStore *vuln.PackageStore, fileStore *managedfiles.Store,
	campaignStore *campaigns.Store, recorder *audit.Recorder, authorizer Authorizer,
	log *slog.Logger) *Evaluator {
	return &Evaluator{
		store: store, hosts: hostStore, inventory: inventoryStore, groups: groups,
		packages: packageStore, files: fileStore, campaigns: campaignStore,
		audit: recorder, authorizer: authorizer, log: log,
	}
}

// The rollout of a remediation campaign: a canary of one, waves of five,
// two hosts at once, the same policy the fleet remediation follows,
// because the steps are the same operations.
const (
	remediationCanary        = 1
	remediationWave          = 5
	remediationConcurrency   = 2
	remediationFailurePct    = 20
	remediationFingerprintV1 = "flotestro/policy-remediation/1"
)

// The reasons a host of the drift set does not enter the remediation as
// a ready target.
const (
	ReasonNoPlan            = "no_plan"
	ReasonQuarantined       = "quarantined"
	ReasonCapabilityMissing = "capability_missing"
	ReasonOutOfScope        = "out_of_scope"
)

// Outcome summarises one evaluation.
type Outcome struct {
	PolicyID string         `json:"policy_id"`
	Version  int            `json:"version"`
	Hosts    int            `json:"hosts"`
	Counts   map[string]int `json:"counts"`
	// CampaignID names the remediation campaign the evaluation ordered,
	// or the one already open for the same drift; empty in report mode
	// or without a drift to fix.
	CampaignID string `json:"campaign_id,omitempty"`
	// Remediation says in words what happened to the drift.
	Remediation string    `json:"remediation,omitempty"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// hostFindings is one host judged: the results for the table and the
// findings for the remediation builder.
type hostFindings struct {
	host     hosts.Host
	results  []Result
	findings []compliance.Finding
}

// Evaluate judges every host the policy selects against its published
// document, writes the verdicts and, when the mode asks for it, orders
// the remediation of the drift.
func (e *Evaluator) Evaluate(ctx context.Context, policy Policy) (*Outcome, error) {
	if policy.Version == 0 {
		return nil, ErrNotPublished
	}
	version, err := e.store.VersionOf(ctx, policy.ID, policy.Version)
	if err != nil {
		return nil, err
	}
	document, err := version.Decode()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()

	selected, err := e.resolve(ctx, document.Selector)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ReasonSelectorFailed, err)
	}
	judged, err := e.judge(ctx, document, policy.Version, selected, now)
	if err != nil {
		return nil, err
	}

	outcome := &Outcome{PolicyID: policy.ID, Version: policy.Version, Hosts: len(selected),
		Counts: EmptyCounts(), EvaluatedAt: now}
	results := make([]Result, 0, len(selected)*len(document.Rules))
	for _, entry := range judged {
		for _, result := range entry.results {
			outcome.Counts[result.Verdict]++
			results = append(results, result)
		}
	}
	if err := e.store.ReplaceResults(ctx, policy.ID, policy.Version, results, now); err != nil {
		return nil, err
	}

	switch document.RemediationMode {
	case ModeCampaign, ModeAutomatic:
		campaignID, note, err := e.remediate(ctx, policy, *version, document, judged)
		if err != nil {
			return nil, err
		}
		outcome.CampaignID = campaignID
		outcome.Remediation = note
	default:
		if outcome.Counts[VerdictDrift] > 0 {
			outcome.Remediation = "report mode: the drift is recorded and nothing is ordered"
		}
	}
	return outcome, nil
}

// resolve turns the selector into the host list the way the campaigns
// do: the typed expression decides alone, an explicit list is read host
// by host, the flat filters page through the fleet. The exclusion list
// takes hosts out afterwards.
func (e *Evaluator) resolve(ctx context.Context, chosen campaigns.Selector) ([]hosts.Host, error) {
	var list []hosts.Host
	switch {
	case chosen.Expression != nil:
		expanded, err := selector.Expand(ctx, chosen.Expression, e.groups)
		if err != nil {
			return nil, err
		}
		list, err = e.page(ctx, hosts.ListFilter{Expression: expanded})
		if err != nil {
			return nil, err
		}
	case len(chosen.HostIDs) > 0:
		for _, hostID := range chosen.HostIDs {
			host, err := e.hosts.Get(ctx, hostID)
			if errors.Is(err, hosts.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			list = append(list, *host)
		}
	case chosen.Empty():
		// An empty selector names nobody, not everybody: a policy over
		// the whole fleet says so with an expression that matches it.
		return nil, nil
	default:
		var err error
		list, err = e.page(ctx, hosts.ListFilter{
			Site: chosen.Site, Environment: chosen.Environment, OSFamily: chosen.OSFamily,
		})
		if err != nil {
			return nil, err
		}
	}
	kept := make([]hosts.Host, 0, len(list))
	for _, host := range list {
		if !chosen.Excluded(host.ID) {
			kept = append(kept, host)
		}
	}
	return kept, nil
}

// maxPolicyHosts bounds one policy. A selector wider than this is a
// mistake in the selector, not an intent, and the loop stops rather than
// judging half a fleet.
const maxPolicyHosts = 10000

func (e *Evaluator) page(ctx context.Context, filter hosts.ListFilter) ([]hosts.Host, error) {
	result := make([]hosts.Host, 0, hosts.PageSize)
	afterName, afterID := "", ""
	for {
		page, err := e.hosts.Page(ctx, filter, afterName, afterID, hosts.PageSize)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if len(page) < hosts.PageSize {
			return result, nil
		}
		if len(result) > maxPolicyHosts {
			return nil, fmt.Errorf("the selector covers more than %d hosts", maxPolicyHosts)
		}
		last := page[len(page)-1]
		afterName, afterID = last.Hostname, last.ID
	}
}

// judge computes the verdicts of every rule on every selected host.
func (e *Evaluator) judge(ctx context.Context, document Document, version int,
	selected []hosts.Host, now time.Time) ([]hostFindings, error) {
	ids := make([]string, 0, len(selected))
	for _, host := range selected {
		ids = append(ids, host.ID)
	}
	fragments, err := e.inventory.HostFragments(ctx, ids)
	if err != nil {
		return nil, err
	}
	needsPackages, needsFiles := false, false
	for _, rule := range document.Rules {
		switch rule.Kind {
		case KindPackageInstalled, KindPackageAbsent:
			needsPackages = true
		case KindFileContent:
			needsFiles = true
		}
	}
	var packageStates map[string]vuln.PackageListState
	if needsPackages && e.packages != nil {
		packageStates, err = e.packages.States(ctx, ids)
		if err != nil {
			return nil, err
		}
	}
	// The version store is asked once per digest, not once per host: a
	// policy over a thousand hosts names one file.
	contents := map[string][]byte{}
	var fileContent func(string) ([]byte, bool)
	if needsFiles && e.files != nil {
		fileContent = func(digest string) ([]byte, bool) {
			if content, ok := contents[digest]; ok {
				return content, content != nil
			}
			content, err := e.files.Content(ctx, digest)
			if err != nil {
				contents[digest] = nil
				return nil, false
			}
			contents[digest] = content
			return content, true
		}
	}

	judged := make([]hostFindings, 0, len(selected))
	for _, host := range selected {
		facts := Facts{Host: host, Fragments: map[string]inventory.Fragment{}, FileContent: fileContent, Now: now}
		for _, fragment := range fragments[host.ID] {
			facts.Fragments[fragment.Module] = fragment
		}
		if needsPackages && e.packages != nil {
			facts.Packages = e.packageFacts(ctx, host.ID, packageStates[host.ID])
		}
		entry := hostFindings{host: host}
		for index, rule := range document.Rules {
			judgement := Judge(rule, facts)
			entry.results = append(entry.results, Result{
				HostID: host.ID, Hostname: host.Hostname, RuleIndex: index, Version: version,
				Verdict: judgement.Verdict, Reason: judgement.Reason,
				ObservedRevision: judgement.Revision, EvaluatedAt: now,
			})
			entry.findings = append(entry.findings, Finding(index, rule, version, judgement))
		}
		judged = append(judged, entry)
	}
	return judged, nil
}

// packageFacts reads the panel's copy of one host's package list. The
// state row says whether the copy exists; the list itself is read only
// when it does.
func (e *Evaluator) packageFacts(ctx context.Context, hostID string, state vuln.PackageListState) PackageFacts {
	facts := PackageFacts{Loaded: true, Digest: state.Digest, CollectedAt: state.CollectedAt,
		UnavailableReason: state.UnavailableReason, Installed: map[string]bool{}}
	if state.HostID == "" {
		facts.UnavailableReason = vuln.ReasonPackageListMissing
		return facts
	}
	if state.Digest == "" {
		return facts
	}
	list, err := e.packages.Packages(ctx, hostID)
	if err != nil {
		facts.UnavailableReason = "the package list was not read: " + err.Error()
		facts.Digest = ""
		return facts
	}
	for _, pkg := range list {
		facts.Installed[pkg.Name] = true
	}
	return facts
}

// remediate turns the drift of an evaluation into a campaign, unless the
// same drift set already has one or a campaign of the policy is still
// open. It answers with the campaign and a sentence for the outcome.
func (e *Evaluator) remediate(ctx context.Context, policy Policy, version Version, document Document,
	judged []hostFindings) (string, string, error) {
	action := opspec.ActionSecurityRemediate

	// Every host of the drift set enters the snapshot: ready with its
	// plan, or closed with the reason the approver reads.
	var ready []campaigns.TargetHost
	var closed []campaigns.TargetHost
	var plans []campaigns.HostPlanSpec
	byHost := map[remediation.Host]remediation.Arrangement{}
	lines := []string{}
	checkIDs := map[string]bool{}
	for _, entry := range judged {
		drifted := false
		for _, finding := range entry.findings {
			if finding.NeedsAction() {
				drifted = true
			}
		}
		if !drifted {
			continue
		}
		report := compliance.Report{
			HostID: entry.host.ID, Findings: entry.findings,
			PlanHash: compliance.PlanHash(entry.host.ID, entry.findings), PlanHashVersion: compliance.CanonicalVersion,
		}
		arrangement, err := remediation.ArrangeFindings(report)
		if err != nil {
			closed = append(closed, campaigns.TargetHost{ID: entry.host.ID, BootID: entry.host.BootID,
				State: campaigns.TargetIneligible, Reason: ReasonNoPlan, Message: err.Error()})
			continue
		}
		if arrangement.Empty() {
			closed = append(closed, campaigns.TargetHost{ID: entry.host.ID, BootID: entry.host.BootID,
				State: campaigns.TargetIneligible, Reason: ReasonNoPlan, Message: describeSkips(entry.findings, arrangement.Skipped)})
			continue
		}
		if reason, message := e.refusal(entry.host, arrangement.Plan.Plan.Steps); reason != "" {
			closed = append(closed, campaigns.TargetHost{ID: entry.host.ID, BootID: entry.host.BootID,
				State: campaigns.TargetIneligible, Reason: reason, Message: message})
			continue
		}
		content, err := json.Marshal(arrangement.Plan)
		if err != nil {
			return "", "", err
		}
		ready = append(ready, campaigns.TargetHost{ID: entry.host.ID, BootID: entry.host.BootID})
		plans = append(plans, campaigns.HostPlanSpec{HostID: entry.host.ID, PlanHash: arrangement.Hash, Plan: content})
		byHost[remediation.Host{HostID: entry.host.ID, Hostname: entry.host.Hostname}] = arrangement
		lines = append(lines, entry.host.ID+"\x1f"+arrangement.Hash)
		for _, step := range arrangement.Plan.Plan.Steps {
			checkIDs[step.CheckID] = true
		}
	}
	if len(ready) == 0 {
		if len(closed) == 0 {
			return "", "", nil
		}
		return "", fmt.Sprintf("%d hosts drifted and none can be fixed by a campaign; the reasons are in the results", len(closed)), nil
	}

	fingerprint := DriftFingerprint(policy.ID, policy.Version, lines)
	if existing, err := e.store.RemediationCampaign(ctx, policy.ID, fingerprint); err != nil {
		return "", "", err
	} else if existing != "" {
		return existing, "the same drift set already has a campaign", nil
	}
	if open, err := e.store.OpenRemediation(ctx, policy.ID); err != nil {
		return "", "", err
	} else if open != "" {
		return open, "a remediation campaign of this policy is still open; the drift is judged again after it settles", nil
	}

	// The campaign is created on the publisher's authority, and the
	// publisher's rights are read now, not assumed from the publication:
	// a host the publisher may not change is closed in the snapshot the
	// way a fleet remediation closes a host out of scope.
	publisher, err := e.principal(ctx, version.PublishedBy)
	if err != nil {
		e.recordRemediation(ctx, policy, document, audit.OutcomeDenied, map[string]any{
			"reason": "publisher_unknown", "publisher": version.PublishedBy, "error": err.Error()})
		return "", "the publisher " + version.PublishedBy + " cannot be resolved: " + err.Error(), nil
	}
	if document.RemediationMode == ModeAutomatic && !publisher.CanAnywhere(authz.PermPolicyRemediateAuto) {
		e.recordRemediation(ctx, policy, document, audit.OutcomeDenied, map[string]any{
			"reason": "permission_denied", "permission": string(authz.PermPolicyRemediateAuto),
			"publisher": version.PublishedBy})
		return "", "automatic remediation refused: " + version.PublishedBy + " no longer holds " + string(authz.PermPolicyRemediateAuto), nil
	}
	ready, closed = e.scopeTargets(*publisher, ready, closed, byHost, judged, document.RemediationMode)
	if len(ready) == 0 {
		e.recordRemediation(ctx, policy, document, audit.OutcomeDenied, map[string]any{
			"reason": "permission_denied", "publisher": version.PublishedBy, "closed": len(closed)})
		return "", "no drifted host is within the publisher's rights; nothing was ordered", nil
	}
	plans = keepPlans(plans, ready)

	ids := make([]string, 0, len(checkIDs))
	for id := range checkIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	payload, err := json.Marshal(opspec.Payload{Security: &opspec.SecurityPayload{CheckIDs: ids}})
	if err != nil {
		return "", "", err
	}
	spec := campaigns.Spec{
		Name:                    fmt.Sprintf("Policy %s v%d", document.Name, policy.Version),
		ActionType:              string(action),
		Payload:                 payload,
		Selector:                document.Selector,
		CanarySize:              remediationCanary,
		WaveSize:                remediationWave,
		MaxConcurrent:           remediationConcurrency,
		FailureThresholdPercent: remediationFailurePct,
		RebootPolicy:            campaigns.RebootNever,
		JobTimeoutSeconds:       action.DefaultTimeout(),
		RequiresApproval:        true,
		OfflinePolicy:           action.OfflinePolicy(),
		CreatedBy:               version.PublishedBy,
		IdempotencyKey:          "policy:" + policy.ID + ":" + fingerprint,
		PolicyID:                policy.ID,
		PolicyVersion:           policy.Version,
	}

	tx, err := e.campaigns.Pool().Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	campaign, err := e.campaigns.CreatePlanned(ctx, tx, spec, append(ready, closed...), plans)
	if errors.Is(err, campaigns.ErrRepeated) {
		return campaign.ID, "the same drift set already has a campaign", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("ordering the remediation campaign: %w", err)
	}
	if err := e.store.RecordRemediation(ctx, tx, policy.ID, policy.Version, fingerprint, campaign.ID); err != nil {
		return "", "", err
	}
	detail := map[string]any{
		"campaign_id": campaign.ID, "name": campaign.Name, "mode": document.RemediationMode,
		"policy_version": policy.Version, "fingerprint": fingerprint,
		"targets": len(ready) + len(closed), "eligible": len(ready), "closed": len(closed),
		"plan_groups": len(remediation.GroupPlans(byHost)), "plan_set_hash": campaign.PlanSetHash,
		"approval_fingerprint": campaign.ApprovalFingerprint, "check_ids": ids,
		"publisher": version.PublishedBy,
	}
	note := fmt.Sprintf("campaign %s ordered for %d hosts; it waits for approval", campaign.ID, len(ready))

	if document.RemediationMode == ModeAutomatic {
		// The publication is the approval: the record quotes the same
		// authentication the publisher gave then, and names the policy as
		// the reason, so the approval chain reads the way the document
		// describes it - approved at publication, carried out at drift.
		approval := campaigns.Approval{
			ApprovedBy:      version.PublishedBy,
			Authentication:  version.Authentication,
			ACR:             version.ACR,
			AMR:             version.AMR,
			AuthenticatedAt: version.AuthenticatedAt,
			Reason:          fmt.Sprintf("policy %s v%d", document.Name, policy.Version),
		}
		if approval.Authentication == "" {
			approval.Authentication = "api_token"
		}
		if _, err := e.campaigns.Approve(ctx, tx, campaign.ID, approval); err != nil {
			return "", "", fmt.Errorf("approving the remediation campaign with the publication: %w", err)
		}
		detail["approved_by"] = version.PublishedBy
		detail["approval_reason"] = approval.Reason
		note = fmt.Sprintf("campaign %s ordered for %d hosts and approved by the publication", campaign.ID, len(ready))
	}
	if err := e.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "policy:" + policy.ID,
		Action: "policy.remediate", TargetType: "campaign", TargetID: campaign.ID,
		Outcome: audit.OutcomeSuccess, Detail: detail,
		Before: map[string]any{"campaign_id": ""},
		After:  map[string]any{"campaign_id": campaign.ID, "state": string(campaign.State)},
	}); err != nil {
		return "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	e.log.Info("a policy ordered a remediation campaign", "policy_id", policy.ID,
		"version", policy.Version, "campaign_id", campaign.ID, "hosts", len(ready), "mode", document.RemediationMode)
	return campaign.ID, note, nil
}

// refusal names why a host cannot run its plan: the quarantine, or an
// adapter a step needs that the host lacks. An irreversible step is
// refused outright, as the fleet remediation refuses it - none of this
// version's rules maps to one, and the check keeps it that way.
func (e *Evaluator) refusal(host hosts.Host, steps []remediation.Step) (string, string) {
	if host.LifecycleState == "quarantined" {
		return ReasonQuarantined, "the host is quarantined and accepts no operations"
	}
	for _, step := range steps {
		action := opspec.ActionType(step.ActionType)
		if action.RequiresTargetConfirmation() {
			return ReasonNoPlan, "step " + step.CheckID + " is an irreversible operation; run it host by host"
		}
		if requirement := action.RequiredCapability(); requirement != "" && !host.Capabilities.Satisfies(requirement) {
			return ReasonCapabilityMissing, "the host lacks the adapter step " + step.CheckID + " needs: " + requirement
		}
	}
	return "", ""
}

// scopeTargets closes the ready hosts the publisher may not change: the
// campaign right and the remediation right in the host's scope, and the
// permission of every step. The orchestrator checks the same at dispatch;
// checking here keeps a host the publisher cannot touch out of the
// approver's consent in the first place.
func (e *Evaluator) scopeTargets(publisher authz.Principal, ready, closed []campaigns.TargetHost,
	byHost map[remediation.Host]remediation.Arrangement, judged []hostFindings, mode string) ([]campaigns.TargetHost, []campaigns.TargetHost) {
	hostByID := map[string]hosts.Host{}
	for _, entry := range judged {
		hostByID[entry.host.ID] = entry.host
	}
	kept := make([]campaigns.TargetHost, 0, len(ready))
	for _, target := range ready {
		host := hostByID[target.ID]
		scope := hosts.ScopeOf(&host)
		missing := ""
		required := []authz.Permission{authz.PermCampaignCreate, authz.PermSecurityRemediate}
		if mode == ModeAutomatic {
			required = append(required, authz.PermPolicyRemediateAuto)
		}
		for _, permission := range required {
			if !publisher.Can(permission, scope) {
				missing = string(permission)
				break
			}
		}
		if missing == "" {
			arrangement := byHost[remediation.Host{HostID: host.ID, Hostname: host.Hostname}]
			for _, action := range arrangement.Plan.Actions() {
				permission := authz.Permission(opspec.ActionType(action).Permission())
				if !publisher.Can(permission, scope) {
					missing = string(permission) + " (step " + action + ")"
					break
				}
			}
		}
		if missing != "" {
			closed = append(closed, campaigns.TargetHost{ID: target.ID, BootID: target.BootID,
				State: campaigns.TargetIneligible, Reason: ReasonOutOfScope,
				Message: "the publisher " + publisher.Subject + " does not hold " + missing + " on " + scope.String()})
			delete(byHost, remediation.Host{HostID: host.ID, Hostname: host.Hostname})
			continue
		}
		kept = append(kept, target)
	}
	return kept, closed
}

// keepPlans keeps the plans of the hosts still ready.
func keepPlans(plans []campaigns.HostPlanSpec, ready []campaigns.TargetHost) []campaigns.HostPlanSpec {
	wanted := map[string]bool{}
	for _, target := range ready {
		wanted[target.ID] = true
	}
	kept := make([]campaigns.HostPlanSpec, 0, len(ready))
	for _, plan := range plans {
		if wanted[plan.HostID] {
			kept = append(kept, plan)
		}
	}
	return kept
}

func (e *Evaluator) principal(ctx context.Context, subject string) (*authz.Principal, error) {
	if e.authorizer == nil {
		return nil, errors.New("no authorizer is configured")
	}
	principal, err := e.authorizer.PrincipalBySubject(ctx, subject)
	if err != nil {
		return nil, err
	}
	if principal == nil {
		return nil, errors.New("the principal does not exist")
	}
	return principal, nil
}

func (e *Evaluator) recordRemediation(ctx context.Context, policy Policy, document Document, outcome audit.Outcome, detail map[string]any) {
	detail["policy_version"] = policy.Version
	detail["mode"] = document.RemediationMode
	e.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "policy:" + policy.ID,
		Action: "policy.remediate", TargetType: "policy", TargetID: policy.ID,
		Outcome: outcome, Detail: detail,
	})
}

// describeSkips says, rule by rule, why a drifted host got no step.
func describeSkips(findings []compliance.Finding, skipped map[string]string) string {
	parts := []string{}
	for _, finding := range findings {
		if !finding.NeedsAction() {
			continue
		}
		reason, ok := skipped[finding.CheckID]
		if !ok {
			reason = strings.TrimPrefix(finding.Observed, ReasonNoRemediation+": ")
		}
		parts = append(parts, finding.CheckID+": "+reason)
	}
	return strings.Join(parts, "; ")
}

// DriftFingerprint identifies a drift set: the policy, the version and,
// for every host, the digest of the steps it would run. The same hosts
// with the same steps give the same fingerprint, so a cycle that finds
// the drift still there does not order a second campaign; a host fixed
// or a host added changes it.
func DriftFingerprint(policyID string, version int, lines []string) string {
	sorted := append([]string(nil), lines...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(remediationFingerprintV1 + "\n" + policyID + "\n" +
		fmt.Sprintf("%d", version) + "\n" + strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:])
}
