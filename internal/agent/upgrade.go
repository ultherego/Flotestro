package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helper"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// RejectMetadataStale means the repository metadata was not refreshed before
// the replacement.
const RejectMetadataStale = "agent_upgrade_metadata_stale"

// detectManager and readInstalledPackages are the two reads of the host a
// replacement makes before it orders anything.
var (
	detectManager         = packages.Detect
	readInstalledPackages = packages.Installed
)

// upgradeAgent replaces the agent itself with the given version. This is the
// only operation that ends the process performing it.
func (e *TaskExecutor) upgradeAgent(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.AgentUpgradePayload) *agentv1.TaskResult {
	// What the host runs and what its package database holds are two different
	// facts, and only the second one survives a restart.
	manager, detected := detectManager()
	installed, installedReason := "", ""
	if detected == nil {
		installed, installedReason = installedAgentVersion(ctx, manager.Name())
	} else {
		installedReason = detected.Error()
	}
	atTarget := payload.TargetVersion == Version &&
		(installed == "" || versionIs(installed, payload.TargetVersion))

	if atTarget && payload.PackageSHA256 == "" {
		// A repeated order is not an error: the host is already where it was meant
		// to be, and there is no point in restarting the agent a second time.
		return &agentv1.TaskResult{
			Status: agentv1.TaskResult_STATUS_SUCCEEDED, ExitCode: 0,
			Message: "the agent is already at version " + Version + "; " +
				describeInstalled(installed, installedReason),
		}
	}

	if detected != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorUnsupported, detected.Error())
	}
	name, err := agentPackage(manager.Name(), payload.TargetVersion)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorUnsupported, err.Error())
	}

	timeout := timeoutOf(task, opspec.ActionAgentUpgrade)
	upgradeCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	// The result may never come back: installing the package restarts the agent
	// and with it this process.
	if e.progress != nil {
		e.progress(&agentv1.TaskProgress{
			TaskId: task.GetTaskId(), Step: 1, Total: 2,
			Message: "installing the agent at version " + payload.TargetVersion,
		})
	}

	// The repository metadata has to be fresh: a version released a quarter of an
	// hour ago does not exist for a manager that last looked at the repository
	// yesterday.
	refresh, err := e.helper.Call(upgradeCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		TimeoutSeconds: 300,
		Action: &helperv1.HelperRequest_PackageAction{
			PackageAction: &helperv1.PackageActionRequest{
				Operation: helperv1.PackageActionRequest_OPERATION_REFRESH,
			},
		},
	}, 5*time.Minute)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	if !refresh.GetAccepted() {
		// The answer of the refresh decides.
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectMetadataStale,
			"the repository metadata was not refreshed ("+
				firstNonEmptyText(refresh.GetErrorCode(), "refused")+"): "+refresh.GetMessage())
	}

	// A host already at the target version still has the order's artefact
	// checked.
	if atTarget {
		response, err := e.helper.Call(upgradeCtx,
			replacementRequest(task, name, payload, timeout, true), timeout)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
		}
		if !response.GetAccepted() {
			return replacementRefusal(response)
		}
		return &agentv1.TaskResult{
			Status: agentv1.TaskResult_STATUS_SUCCEEDED, ExitCode: 0,
			Message: "the agent is already at version " + Version + "; " +
				describeInstalled(installed, installedReason) + "; " +
				describeArtefacts(response.GetPackageResult()),
			Detail: &agentv1.TaskResult_PackageApply{
				PackageApply: applyToProto(response.GetPackageResult()),
			},
		}
	}

	response, err := e.helper.Call(upgradeCtx,
		replacementRequest(task, name, payload, timeout, false), timeout)
	if err != nil {
		// A broken connection to the helper during this operation usually means the
		// package managed to install and the restart is under way - together with
		// the socket of the helper.
		return &agentv1.TaskResult{
			Status: agentv1.TaskResult_STATUS_UNSPECIFIED, ErrorCode: StatusAfterReplacement,
			Message: "the installation is in flight; the return of the agent decides the result",
		}
	}
	detail := applyToProto(response.GetPackageResult())
	if !response.GetAccepted() {
		result := replacementRefusal(response)
		result.Detail = &agentv1.TaskResult_PackageApply{PackageApply: detail}
		return result
	}

	// Even when the installation went through without a broken connection, the
	// success is not the exit code of the package manager: the agent may fail to
	// come up or come up in a different version.
	return &agentv1.TaskResult{
		Status: agentv1.TaskResult_STATUS_UNSPECIFIED, ErrorCode: StatusAfterReplacement,
		Message: "the package was installed; waiting for the agent to come back at version " +
			payload.TargetVersion + "; " + describeInstalled(installed, installedReason) +
			" before the change; " + describeArtefacts(response.GetPackageResult()),
		Detail: &agentv1.TaskResult_PackageApply{PackageApply: detail},
	}
}

// replacementRequest assembles the order for the helper.
func replacementRequest(task *agentv1.TaskEnvelope, name string,
	payload *opspec.AgentUpgradePayload, timeout time.Duration,
	verifyOnly bool) *helperv1.HelperRequest {
	return &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_PackageAction{
			PackageAction: &helperv1.PackageActionRequest{
				Operation: helperv1.PackageActionRequest_OPERATION_INSTALL,
				Packages:  []string{name},
				// The version is given explicitly, so a downgrade is an operator decision
				// as well - that is how the return after a failed release works.
				AllowDowngrade:  true,
				PackageSha256:   payload.PackageSHA256,
				RollbackVersion: payload.RollbackVersion,
				VerifyOnly:      verifyOnly,
			},
		},
	}
}

// replacementRefusal turns the helper's answer into the result of the task.
func replacementRefusal(response *helperv1.HelperResponse) *agentv1.TaskResult {
	status := agentv1.TaskResult_STATUS_FAILED
	switch response.GetErrorCode() {
	case helper.ErrorArtefactDigest, helper.ErrorArtefactUnavailable, helper.ErrorRollbackUnavailable:
		status = agentv1.TaskResult_STATUS_REJECTED
	}
	return rejected(status, response.GetErrorCode(), response.GetMessage())
}

// installedAgentVersion reads the version of the agent package from the
// package database of the host.
func installedAgentVersion(ctx context.Context, manager string) (string, string) {
	list := readInstalledPackages(ctx, manager)
	if list.UnavailableReason != "" {
		return "", list.UnavailableReason
	}
	for _, pkg := range list.Packages {
		if pkg.Name == packages.AgentPackage {
			return pkg.EVR(), ""
		}
	}
	return "", "the package " + packages.AgentPackage + " is not in the package database"
}

// versionIs says whether the version from the package database is the version
// the order names.
func versionIs(installed, target string) bool {
	if _, rest, found := strings.Cut(installed, ":"); found {
		installed = rest
	}
	return installed == target || strings.HasPrefix(installed, target+"-")
}

// describeInstalled puts the package database's answer into the result.
func describeInstalled(version, reason string) string {
	if version == "" {
		return "the installed version is unknown (" + reason + ")"
	}
	return "the package database holds " + version
}

// describeArtefacts says what the host verified and what it kept, so the
// operator knows where the return of the previous version waits.
func describeArtefacts(result *helperv1.PackageActionResult) string {
	parts := make([]string, 0, 2)
	if artefact := result.GetVerifiedArtefactPath(); artefact != "" {
		parts = append(parts, "the verified artefact is "+artefact)
	}
	if rollback := result.GetRollbackArtefactPath(); rollback != "" {
		parts = append(parts, "the artefact to go back to is kept at "+rollback)
	}
	if len(parts) == 0 {
		return "the order named neither an artefact digest nor a version to go back to"
	}
	return strings.Join(parts, "; ")
}

// firstNonEmptyText returns the first value that carries anything.
func firstNonEmptyText(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// agentPackage assembles the package name with the version in the notation of
// the given manager.
func agentPackage(manager, version string) (string, error) {
	switch manager {
	case "apt", packages.PacmanName:
		return packages.AgentPackage + "=" + version, nil
	case "dnf":
		return packages.AgentPackage + "-" + version, nil
	}
	return "", fmt.Errorf("the manager %s cannot name a package version", manager)
}
