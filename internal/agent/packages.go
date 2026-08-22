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

// planPackages liczy, co zostaloby zaktualizowane. Symulacja nie wymaga roota
// ani blokady, wiec nie koliduje z reczna praca administratora. Odswiezenie
// metadanych wymaga roota i idzie przez helper.
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

// upgradePackages wykonuje transakcje przez helpera. Przed wykonaniem plan
// jest przeliczany i porownywany z zatwierdzonym: metadane repozytorium mogly
// zmienic sie miedzy planem a wykonaniem.
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
			// Odmowa jest tu wlasciwa reakcja: administrator zatwierdzil inny
			// zestaw zmian niz ten, ktory zostalby teraz zastosowany.
			return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorPlanMismatch,
				"metadane repozytorium zmienily sie od zatwierdzenia planu")
		}
	}

	response, err := e.helper.Call(upgradeCtx, &helperv1.HelperRequest{
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
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	// Wynik czesciowy trafia do rezultatu takze przy bledzie: bez tego
	// administrator nie wie, co zdazylo sie zmienic przed awaria.
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
	}
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
		Manager:                result.GetManager(),
		Applied:                changes,
		RebootRequired:         result.GetRebootRequired(),
		ServicesNeedingRestart: result.GetServicesNeedingRestart(),
		PackageDatabaseBroken:  result.GetPackageDatabaseBroken(),
	}
}
