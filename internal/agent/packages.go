package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/plan"
)

// planPackages computes what would be upgraded.
func (e *TaskExecutor) planPackages(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.PackagePlanPayload) *agentv1.TaskResult {
	manager, err := packages.Detect()
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorUnsupported, err.Error())
	}

	timeout := timeoutOf(task, opspec.ActionPackagePlan)
	planCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	refreshed := false
	// On Arch without pacman-contrib the plan reads a copy of the sync database
	// only the helper can refresh, so a missing or old copy is refreshed first.
	if payload.RefreshMetadata || packages.NeedsSyncCopy(manager) {
		response, err := e.helper.Call(planCtx, &helperv1.HelperRequest{
			TaskId:         task.GetTaskId(),
			ExpiresAt:      task.GetExpiresAt(),
			TimeoutSeconds: uint32(timeout.Seconds()),
			Action: &helperv1.HelperRequest_PackageAction{
				PackageAction: &helperv1.PackageActionRequest{
					Operation: helperv1.PackageActionRequest_OPERATION_REFRESH,
				},
			},
		}, timeout)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
		}
		if !response.GetAccepted() {
			return rejected(agentv1.TaskResult_STATUS_REJECTED,
				response.GetErrorCode(), response.GetMessage())
		}
		refreshed = true
	}

	computed, err := manager.Plan(planCtx, packages.Options{
		Mode:         payload.Mode,
		Packages:     payload.OnlyPackages,
		SecurityOnly: payload.SecurityOnly,
		Header:       e.planHeader(),
	})
	if err != nil {
		status := agentv1.TaskResult_STATUS_FAILED
		// A refusal of the host - a lock, a distribution that does not do partial
		// upgrades, a missing planning tool - is a rejection rather than a failed
		// attempt: nothing was tried.
		if packages.Refused(err) {
			status = agentv1.TaskResult_STATUS_REJECTED
		}
		return rejected(status, packageErrorCode(err), err.Error())
	}
	computed.MetadataRefreshed = refreshed

	return &agentv1.TaskResult{
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Detail:   &agentv1.TaskResult_PackagePlan{PackagePlan: planToProto(computed)},
	}
}

// planHeader is the identity the agent gives a plan it computes: this host,
// the picture of it the panel holds now, and an expiry a day away.
func (e *TaskExecutor) planHeader() packages.PlanHeader {
	header := packages.PlanHeader{
		HostID:    e.hostID,
		ExpiresAt: time.Now().Add(plan.DefaultTTL).UTC().Truncate(time.Second),
	}
	if e.facts != nil {
		if revision, _, err := e.facts().Revision(); err == nil {
			header.InventoryRevision = revision
		}
	}
	return header
}

// approvedReference turns the plan reference of an order into the fields the
// helper request carries.
func approvedReference(hash string, reference *opspec.PlanReference,
	request *helperv1.PackageActionRequest) *agentv1.TaskResult {
	if hash == "" {
		return nil
	}
	sum, err := plan.ParseHash(hash)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, err.Error())
	}
	request.PlanHash = sum
	if reference == nil {
		return nil
	}
	if reference.PlannerVersion != "" && reference.PlannerVersion != packages.PlannerVersion {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, plan.ErrorReplanRequired,
			fmt.Sprintf("planner %s made the plan, planner %s would execute it; plan again",
				reference.PlannerVersion, packages.PlannerVersion))
	}
	request.PlanSchemaVersion = reference.SchemaVersion
	request.PlannerVersion = reference.PlannerVersion
	request.PlanInventoryRevision = reference.InventoryRevision
	request.PlanResourceRevision = reference.ResourceRevision
	if reference.ExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, reference.ExpiresAt)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
				"the expiry of the plan is not an RFC 3339 time: "+err.Error())
		}
		if time.Now().After(expiry) {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, plan.ErrorPlanExpired,
				"the plan expired at "+expiry.UTC().Format(time.RFC3339)+"; plan again")
		}
		request.PlanExpiresAtUnix = expiry.Unix()
	}
	for _, change := range reference.Changes {
		request.ExactSpecs = append(request.ExactSpecs, &helperv1.PackageExactSpec{
			Name: change.Name, CurrentVersion: change.CurrentVersion, CandidateVersion: change.CandidateVersion,
			Architecture: change.Architecture, Origin: change.Origin, Action: change.Action,
		})
	}
	return nil
}

// upgradePackages performs the transaction through the helper.
func (e *TaskExecutor) upgradePackages(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.PackageUpgradePayload) *agentv1.TaskResult {
	if _, err := packages.Detect(); err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorUnsupported, err.Error())
	}

	timeout := timeoutOf(task, opspec.ActionPackageUpgrade)
	upgradeCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	request := &helperv1.PackageActionRequest{
		Operation:    helperv1.PackageActionRequest_OPERATION_UPGRADE,
		Packages:     payload.Packages,
		SecurityOnly: payload.SecurityOnly,
		PlanHostId:   e.hostID,
	}
	if refusal := approvedReference(payload.PlanHash, payload.Plan, request); refusal != nil {
		return refusal
	}

	// A package transaction takes minutes. The operator is to see where it
	// stands instead of waiting for the result in front of an empty screen.
	var reportProgress func(*helperv1.TaskProgress)
	if e.progress != nil {
		reportProgress = func(p *helperv1.TaskProgress) {
			e.progress(&agentv1.TaskProgress{
				TaskId:  task.GetTaskId(),
				Step:    p.GetStep(),
				Total:   p.GetTotal(),
				Percent: p.Percent,
				Message: p.GetMessage(),
			})
		}
	}

	response, err := e.helper.CallWithProgress(upgradeCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_PackageAction{PackageAction: request},
	}, timeout, reportProgress)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	// The partial result goes into the result on failure as well: without it the
	// administrator does not know what managed to change before the breakdown.
	detail := applyToProto(response.GetPackageResult())
	if !response.GetAccepted() {
		result := rejected(agentv1.TaskResult_STATUS_FAILED,
			response.GetErrorCode(), response.GetMessage())
		result.Detail = &agentv1.TaskResult_PackageApply{PackageApply: detail}
		return result
	}

	return &agentv1.TaskResult{
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Detail:   &agentv1.TaskResult_PackageApply{PackageApply: detail},
	}
}

func packageErrorCode(err error) string {
	if code, ok := packages.ErrorCodeOf(err); ok {
		return code
	}
	return packages.ErrorTransaction
}

func planToProto(computed packages.Plan) *agentv1.PackagePlanResult {
	changes := make([]*agentv1.PackageChange, 0, len(computed.Changes))
	for _, change := range computed.Changes {
		changes = append(changes, changeToProto(change))
	}
	envelope := computed.Envelope()
	// The canonical bytes are what the digest was computed over; the panel keeps
	// them as the plan body next to the approval.
	canonical, err := envelope.Canonical()
	if err != nil {
		canonical = nil
	}
	return &agentv1.PackagePlanResult{
		Manager:            computed.Manager,
		Changes:            changes,
		DownloadBytes:      computed.DownloadBytes,
		DiskAvailableBytes: computed.DiskAvailableBytes,
		PlanHash:           envelope.Hash(),
		RebootPredicted:    computed.RebootPredicted,
		MetadataRefreshed:  computed.MetadataRefreshed,
		Blocked:            blockedPlanToProto(computed.Blocked),
		Mode:               computed.Mode,
		Removals:           computed.Removals,
		Protected:          computed.Protected,
		Space:              spaceToProto(computed.Space),
		SchemaVersion:      envelope.SchemaVersion,
		PlannerVersion:     envelope.PlannerVersion,
		HostId:             envelope.HostID,
		InventoryRevision:  envelope.InventoryRevision,
		ResourceRevision:   envelope.ResourceRevision,
		ExpiresAtUnix:      envelope.ExpiresAt.Unix(),
		RollbackMechanism:  computed.Rollback.Mechanism,
		RollbackId:         computed.Rollback.ID,
		RollbackAvailable:  computed.Rollback.Available,
		RollbackReason:     computed.Rollback.Reason,
		Envelope:           canonical,
		Description:        envelope.Description,
	}
}

// changeToProto carries one element of a plan with everything the digest
// covers: the version, the origin, the architecture and the direction.
func changeToProto(change packages.Change) *agentv1.PackageChange {
	return &agentv1.PackageChange{
		Name:                change.Name,
		CurrentVersion:      change.CurrentVersion,
		CandidateVersion:    change.CandidateVersion,
		Origin:              change.Origin,
		Security:            change.Security,
		Architecture:        change.Architecture,
		Action:              change.Action,
		Reason:              change.Reason,
		Blocked:             change.Blocked,
		Protected:           change.Protected,
		InstalledDeltaBytes: change.InstalledDeltaBytes,
		InstalledDeltaKnown: change.InstalledDeltaKnown,
		Digest:              change.Digest,
	}
}

func spaceToProto(facts []packages.SpaceFact) []*agentv1.SpaceFact {
	out := make([]*agentv1.SpaceFact, 0, len(facts))
	for _, fact := range facts {
		out = append(out, &agentv1.SpaceFact{
			Path:           fact.Path,
			Filesystem:     fact.Filesystem,
			AvailableBytes: fact.AvailableBytes,
			NeededBytes:    fact.NeededBytes,
			Purpose:        fact.Purpose,
			Basis:          fact.Basis,
		})
	}
	return out
}

// blockedPlanToProto carries the blocks together with the configuration
// questions.
func blockedPlanToProto(blocked []packages.Blocked) []*agentv1.BlockedPackage {
	result := make([]*agentv1.BlockedPackage, 0, len(blocked))
	for _, pkg := range blocked {
		questions := make([]*agentv1.DebconfQuestion, 0, len(pkg.Questions))
		for _, question := range pkg.Questions {
			questions = append(questions, &agentv1.DebconfQuestion{
				Name: question.Name, Value: question.Value, Answered: question.Answered,
			})
		}
		result = append(result, &agentv1.BlockedPackage{
			Name: pkg.Name, Status: pkg.Status, Kind: pkg.Kind, Questions: questions,
		})
	}
	return result
}

func applyToProto(result *helperv1.PackageActionResult) *agentv1.PackageApplyResult {
	if result == nil {
		return nil
	}
	changes := make([]*agentv1.PackageChange, 0, len(result.GetApplied()))
	for _, change := range result.GetApplied() {
		changes = append(changes, &agentv1.PackageChange{
			Name:             change.GetName(),
			CurrentVersion:   change.GetVersionBefore(),
			CandidateVersion: change.GetVersionAfter(),
		})
	}
	// The settled effects of the approved plan ride in the same list, each marked
	// achieved or missed with what was found: the operator reads which effect the
	// host reached and which it did not.
	for _, outcomes := range [][]*helperv1.PackageEffectOutcome{result.GetEffectsAchieved(), result.GetEffectsMissed()} {
		for _, outcome := range outcomes {
			effect := "missed"
			if outcome.GetAchieved() {
				effect = "achieved"
			}
			changes = append(changes, &agentv1.PackageChange{
				Name:             outcome.GetSubject(),
				CandidateVersion: outcome.GetExpected(),
				ObservedVersion:  outcome.GetObserved(),
				Effect:           effect,
			})
		}
	}
	return &agentv1.PackageApplyResult{
		Manager:                  result.GetManager(),
		Applied:                  changes,
		RebootRequired:           result.GetRebootRequired(),
		ServicesNeedingRestart:   result.GetServicesNeedingRestart(),
		PackageDatabaseBroken:    result.GetPackageDatabaseBroken(),
		PackagesNeedingAttention: result.GetPackagesNeedingAttention(),
		SelfRepair:               result.GetSelfRepair(),
		Output:                   result.GetOutput(),
		ScriptletErrors:          result.GetScriptletErrors(),
	}
}

// ProbePrivilegedIdentity reads through the helper the parts of the domain
// state that need root: the host keytab, the SSSD cache database and the SSSD
// offline policy.
func (e *TaskExecutor) ProbePrivilegedIdentity(ctx context.Context, domain string) (PrivilegedIdentity, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TaskId:         "identity-probe",
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_IdentityProbe{
			IdentityProbe: &helperv1.IdentityProbeRequest{Domain: domain},
		},
	}, 60*time.Second)
	if err != nil {
		return PrivilegedIdentity{}, err
	}
	if !response.GetAccepted() {
		return PrivilegedIdentity{}, errors.New(response.GetErrorCode() + ": " + response.GetMessage())
	}
	result := response.GetIdentityResult()
	return PrivilegedIdentity{
		HostPrincipal:     result.GetHostPrincipal(),
		KeytabKVNO:        result.KeytabKvno,
		CacheAgeSeconds:   result.CacheAgeSeconds,
		SSSDOnline:        result.SssdOnline,
		ConfigIssues:      result.GetConfigIssues(),
		UnavailableReason: result.GetUnavailableReason(),
		SSSDOfflinePolicy: sssdOfflinePolicyFromHelper(result.GetSssdOfflinePolicy()),
	}, nil
}

// applyPackageLifecycle asks the helper for an installation, a removal or a
// hold of packages.
func (e *TaskExecutor) applyPackageLifecycle(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.PackageChangePayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the package change payload is missing")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	operation := helperv1.PackageActionRequest_OPERATION_INSTALL
	switch action {
	case opspec.ActionPackageRemove:
		operation = helperv1.PackageActionRequest_OPERATION_REMOVE
	case opspec.ActionPackageHoldSet:
		operation = helperv1.PackageActionRequest_OPERATION_HOLD
	}

	// An installation or a removal approved on the basis of a plan is to do what
	// the operator looked at.
	request := &helperv1.PackageActionRequest{
		Operation:        operation,
		Packages:         payload.Packages,
		ExpectedRemovals: payload.ExpectedRemovals,
		Hold:             payload.Hold,
		PlanHostId:       e.hostID,
	}
	if action != opspec.ActionPackageHoldSet {
		if refusal := approvedReference(payload.PlanHash, payload.Plan, request); refusal != nil {
			refusal.TaskId = task.GetTaskId()
			return refusal
		}
	}

	// The progress concerns installation and removal: both can take minutes.
	var reportProgress func(*helperv1.TaskProgress)
	if e.progress != nil && action != opspec.ActionPackageHoldSet {
		reportProgress = func(p *helperv1.TaskProgress) {
			e.progress(&agentv1.TaskProgress{
				TaskId:  task.GetTaskId(),
				Step:    p.GetStep(),
				Total:   p.GetTotal(),
				Percent: p.Percent,
				Message: p.GetMessage(),
			})
		}
	}

	response, err := e.helper.CallWithProgress(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_PackageAction{PackageAction: request},
	}, timeout, reportProgress)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	detail := applyToProto(response.GetPackageResult())
	if !response.GetAccepted() {
		result := rejected(agentv1.TaskResult_STATUS_FAILED,
			response.GetErrorCode(), response.GetMessage())
		result.TaskId = task.GetTaskId()
		result.Detail = &agentv1.TaskResult_PackageApply{PackageApply: detail}
		return result
	}
	return &agentv1.TaskResult{
		TaskId:   task.GetTaskId(),
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Detail:   &agentv1.TaskResult_PackageApply{PackageApply: detail},
	}
}
