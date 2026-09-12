package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// planPackages computes what would be upgraded. The simulation needs neither
// root nor a lock, so it does not collide with the manual work of the
// administrator. Refreshing the metadata needs root and goes through the
// helper.
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
	if payload.RefreshMetadata {
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

	plan, err := manager.Plan(planCtx, packages.Options{
		Mode:         payload.Mode,
		Packages:     payload.OnlyPackages,
		SecurityOnly: payload.SecurityOnly,
	})
	if err != nil {
		status := agentv1.TaskResult_STATUS_FAILED
		if errors.Is(err, packages.ErrLocked) {
			status = agentv1.TaskResult_STATUS_REJECTED
		}
		return rejected(status, packageErrorCode(err), err.Error())
	}
	plan.MetadataRefreshed = refreshed

	return &agentv1.TaskResult{
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Detail:   &agentv1.TaskResult_PackagePlan{PackagePlan: planToProto(plan)},
	}
}

// upgradePackages performs the transaction through the helper. Before the
// execution the plan is recomputed and compared with the approved one: the
// repository metadata may have changed between the plan and the execution.
func (e *TaskExecutor) upgradePackages(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.PackageUpgradePayload) *agentv1.TaskResult {
	manager, err := packages.Detect()
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorUnsupported, err.Error())
	}

	timeout := timeoutOf(task, opspec.ActionPackageUpgrade)
	upgradeCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	options := packages.Options{Packages: payload.Packages, SecurityOnly: payload.SecurityOnly}

	if payload.PlanHash != "" {
		current, err := manager.Plan(upgradeCtx, options)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, packageErrorCode(err), err.Error())
		}
		if hex.EncodeToString(current.Hash()) != strings.ToLower(payload.PlanHash) {
			// A refusal is the right reaction here: the administrator approved a
			// different set of changes than the one that would be applied now.
			return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorPlanMismatch,
				"the repository metadata changed since the plan was approved")
		}
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
		Action: &helperv1.HelperRequest_PackageAction{
			PackageAction: &helperv1.PackageActionRequest{
				Operation:    helperv1.PackageActionRequest_OPERATION_UPGRADE,
				Packages:     payload.Packages,
				SecurityOnly: payload.SecurityOnly,
			},
		},
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
	if errors.Is(err, packages.ErrLocked) {
		return packages.ErrorLocked
	}
	return packages.ErrorTransaction
}

func planToProto(plan packages.Plan) *agentv1.PackagePlanResult {
	changes := make([]*agentv1.PackageChange, 0, len(plan.Changes))
	for _, change := range plan.Changes {
		changes = append(changes, &agentv1.PackageChange{
			Name:             change.Name,
			CurrentVersion:   change.CurrentVersion,
			CandidateVersion: change.CandidateVersion,
			Origin:           change.Origin,
			Security:         change.Security,
		})
	}
	return &agentv1.PackagePlanResult{
		Manager:            plan.Manager,
		Changes:            changes,
		DownloadBytes:      plan.DownloadBytes,
		DiskAvailableBytes: plan.DiskAvailableBytes,
		PlanHash:           plan.Hash(),
		RebootPredicted:    plan.RebootPredicted,
		MetadataRefreshed:  plan.MetadataRefreshed,
		Blocked:            blockedPlanToProto(plan.Blocked),
		Mode:               plan.Mode,
		Removals:           plan.Removals,
		Protected:          plan.Protected,
	}
}

// blockedPlanToProto carries the blocks together with the configuration
// questions. The operator is to see them already at the plan stage and not
// after a failed transaction.
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
			Name: pkg.Name, Status: pkg.Status, Questions: questions,
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
	return &agentv1.PackageApplyResult{
		Manager:                  result.GetManager(),
		Applied:                  changes,
		RebootRequired:           result.GetRebootRequired(),
		ServicesNeedingRestart:   result.GetServicesNeedingRestart(),
		PackageDatabaseBroken:    result.GetPackageDatabaseBroken(),
		PackagesNeedingAttention: result.GetPackagesNeedingAttention(),
		SelfRepair:               result.GetSelfRepair(),
		Output:                   result.GetOutput(),
	}
}

// ProbePrivilegedIdentity reads through the helper the parts of the domain
// state that need root: the host keytab and the SSSD cache database.
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

	// An installation approved on the basis of a plan is to install what the
	// operator looked at. Repository metadata changed since the planning gives a
	// different plan - and that is a refusal, not a warning.
	if action == opspec.ActionPackageInstall && payload.PlanHash != "" {
		manager, err := packages.Detect()
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorUnsupported, err.Error())
		}
		current, err := manager.Plan(callCtx, packages.Options{Mode: "install", Packages: payload.Packages})
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, packageErrorCode(err), err.Error())
		}
		if hex.EncodeToString(current.Hash()) != strings.ToLower(payload.PlanHash) {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorPlanMismatch,
				"the repository metadata changed since the plan was approved")
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
		Action: &helperv1.HelperRequest_PackageAction{
			PackageAction: &helperv1.PackageActionRequest{
				Operation:        operation,
				Packages:         payload.Packages,
				ExpectedRemovals: payload.ExpectedRemovals,
				Hold:             payload.Hold,
			},
		},
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
