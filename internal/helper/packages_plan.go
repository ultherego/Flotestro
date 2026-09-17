package helper

import (
	"context"
	"fmt"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/plan"
)

// detectPackages returns the package manager of the host, or the one a
// test stands in through packageManager.
func (s *Server) detectPackages() (packages.Manager, error) {
	if s.packageManager != nil {
		return s.packageManager()
	}
	return packages.Detect()
}

// approvedPlan reads the approved plan out of the request: the digest and
// the header the envelope is rebuilt with. False means the request binds
// no plan - a legacy order that runs as before.
func approvedPlan(action *helperv1.PackageActionRequest) (plan.Reference, packages.PlanHeader, bool) {
	if len(action.GetPlanHash()) == 0 {
		return plan.Reference{}, packages.PlanHeader{}, false
	}
	reference := plan.Reference{
		Hash:           action.GetPlanHash(),
		SchemaVersion:  action.GetPlanSchemaVersion(),
		PlannerVersion: action.GetPlannerVersion(),
	}
	header := packages.PlanHeader{
		HostID:            action.GetPlanHostId(),
		InventoryRevision: action.GetPlanInventoryRevision(),
	}
	if unix := action.GetPlanExpiresAtUnix(); unix > 0 {
		reference.ExpiresAt = time.Unix(unix, 0).UTC()
		header.ExpiresAt = reference.ExpiresAt
	}
	return reference, header, true
}

// planMode names the kind of plan an operation is bound to.
func planMode(operation helperv1.PackageActionRequest_Operation) string {
	switch operation {
	case helperv1.PackageActionRequest_OPERATION_INSTALL:
		return packages.ModeInstall
	case helperv1.PackageActionRequest_OPERATION_REMOVE:
		return packages.ModeRemove
	}
	return packages.ModeUpgrade
}

// executeApproved carries an approved plan out, and nothing else.
//
// The helper does not trust that the agent checked the plan: under the
// package lock, right before the transaction, it reads the host again,
// computes the same plan with the header of the approved one and compares
// the digest. A difference is a refusal with its code - stale_plan for a
// moved content, replan_required for another planner, plan_expired for a
// plan past its validity - never a quiet update of the plan. The
// transaction then runs on the exact specs of the plan computed now, which
// are the approved ones since the digests matched; afterwards the state
// is read and every expected effect settled.
func (s *Server) executeApproved(ctx context.Context, request *helperv1.HelperRequest,
	manager packages.Manager, action *helperv1.PackageActionRequest,
	options packages.Options) *helperv1.HelperResponse {
	reference, header, _ := approvedPlan(action)
	options.Mode = planMode(action.GetOperation())
	options.Header = header
	// The exact specs of an install or a removal name the packages of the
	// order; the plan is computed for them, as it was on the agent.
	if len(options.Packages) == 0 && options.Mode != packages.ModeUpgrade {
		for _, spec := range action.GetExactSpecs() {
			if spec.GetAction() != packages.ActionRemove || options.Mode == packages.ModeRemove {
				options.Packages = append(options.Packages, spec.GetName())
			}
		}
	}

	current, err := manager.Plan(ctx, options)
	if err != nil {
		// A plan that cannot be computed against the metadata the approved
		// one was read from is a plan the host no longer computes: the
		// cache is gone or was replaced. Anything else is the failure it is.
		if expected := action.GetPlanResourceRevision(); expected != "" &&
			packages.MetadataRevision(manager) != expected {
			s.log.Warn("the package plan is stale: the repository metadata moved",
				"task_id", request.GetTaskId(), "manager", manager.Name(), "err", err)
			return packageFailure(manager.Name(), fmt.Errorf("%w: the repository metadata the plan "+
				"was read against is no longer there (%v)", plan.ErrStalePlan, err))
		}
		return packageFailure(manager.Name(), err)
	}
	if err := current.Envelope().Verify(reference, time.Now()); err != nil {
		if drift := describeDrift(action.GetExactSpecs(), current); drift != "" {
			err = fmt.Errorf("%w; %s", err, drift)
		}
		s.log.Warn("the package plan was refused before the transaction",
			"task_id", request.GetTaskId(), "manager", manager.Name(), "err", err)
		return packageFailure(manager.Name(), err)
	}
	if err := packages.SpaceShortfall(current.Space); err != nil {
		return packageFailure(manager.Name(), err)
	}
	// A protected package in the plan is a plan that will not be carried
	// out, whatever the digest says: the policy of the host weighs more
	// than the consent.
	if len(current.Protected) > 0 {
		return packageFailure(manager.Name(), fmt.Errorf("%w: %s",
			packages.ErrProtectedPackage, strings.Join(current.Protected, ", ")))
	}
	exact, ok := manager.(packages.Exact)
	if !ok {
		return reject(ErrorUnsupported,
			"the manager "+manager.Name()+" cannot execute an approved plan exactly")
	}

	apply, err := exact.ApplyExact(ctx, current, options)
	response := &helperv1.HelperResponse{PackageResult: packageResultToProto(apply)}
	if err != nil {
		// A partial result goes back on failure as well: the operator has to
		// know which effects the host reached before the breakdown.
		response.Accepted = false
		response.ErrorCode = packageErrorCode(err)
		response.Message = err.Error()
		response.ExitCode = -1
		s.log.Error("the approved package transaction did not reach its effects",
			"task_id", request.GetTaskId(), "manager", manager.Name(), "code", response.ErrorCode,
			"changed", len(apply.Applied), "missed", len(apply.EffectsMissed),
			"database_broken", apply.DatabaseBroken, "err", err)
		return response
	}
	response.Accepted = true
	s.log.Info("the approved package transaction finished",
		"task_id", request.GetTaskId(), "manager", manager.Name(), "plan", shortDigest(reference.Hash),
		"changed", len(apply.Applied), "effects", len(apply.EffectsAchieved), "reboot", apply.RebootRequired)
	return response
}

// describeDrift names the elements that differ between the approved specs
// and the plan computed now, so the refusal says which package moved
// rather than that two digests differ. Empty when the specs were not sent
// or nothing among them differs - the drift is then in the header or in
// an element the panel did not send.
func describeDrift(approved []*helperv1.PackageExactSpec, current packages.Plan) string {
	if len(approved) == 0 {
		return ""
	}
	now := map[string]packages.Change{}
	for _, change := range current.Changes {
		now[change.Name] = change
	}
	var drift []string
	seen := map[string]bool{}
	for _, spec := range approved {
		seen[spec.GetName()] = true
		change, ok := now[spec.GetName()]
		switch {
		case !ok:
			drift = append(drift, spec.GetName()+" is no longer in the plan")
		case change.CandidateVersion != spec.GetCandidateVersion():
			drift = append(drift, fmt.Sprintf("%s: approved %s, now %s",
				spec.GetName(), spec.GetCandidateVersion(), change.CandidateVersion))
		case change.Origin != spec.GetOrigin():
			drift = append(drift, fmt.Sprintf("%s: approved from %s, now from %s",
				spec.GetName(), spec.GetOrigin(), change.Origin))
		case change.Architecture != spec.GetArchitecture():
			drift = append(drift, fmt.Sprintf("%s: approved %s, now %s",
				spec.GetName(), spec.GetArchitecture(), change.Architecture))
		case change.Action != spec.GetAction():
			drift = append(drift, fmt.Sprintf("%s: approved as %s, now %s",
				spec.GetName(), spec.GetAction(), change.Action))
		}
	}
	for _, change := range current.Changes {
		if !seen[change.Name] {
			drift = append(drift, change.Name+" entered the plan")
		}
	}
	if len(drift) > 8 {
		drift = append(drift[:8], fmt.Sprintf("and %d more", len(drift)-8))
	}
	return strings.Join(drift, "; ")
}

func shortDigest(sum []byte) string {
	text := fmt.Sprintf("%x", sum)
	if len(text) > 12 {
		return text[:12]
	}
	return text
}

// effectOutcomesToProto carries the settled effects into the result.
func effectOutcomesToProto(outcomes []plan.Outcome) []*helperv1.PackageEffectOutcome {
	if len(outcomes) == 0 {
		return nil
	}
	out := make([]*helperv1.PackageEffectOutcome, 0, len(outcomes))
	for _, outcome := range outcomes {
		expected := outcome.Effect.Value
		if outcome.Effect.Kind == plan.EffectPackageAbsent {
			expected = "absent"
		}
		out = append(out, &helperv1.PackageEffectOutcome{
			Kind: outcome.Effect.Kind, Subject: outcome.Effect.Subject,
			Expected: expected, Observed: outcome.Observed, Achieved: outcome.Achieved,
		})
	}
	return out
}
