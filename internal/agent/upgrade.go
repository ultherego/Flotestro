package agent

import (
	"context"
	"fmt"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// upgradeAgent replaces the agent itself with the given version.
//
// This is the only operation that ends the process performing it. The agent
// package is protected from an ordinary upgrade exactly for that reason: a host
// must not cut itself off from management in the middle of a transaction whose
// result it still has to send back. Here it is done deliberately and settled
// differently - the success is the return of the host with the expected
// version, not the exit code of the package manager.
func (e *TaskExecutor) upgradeAgent(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.AgentUpgradePayload) *agentv1.TaskResult {
	if payload.TargetVersion == Version {
		// A repeated order is not an error: the host is already where it was
		// meant to be, and there is no point in restarting the agent a second
		// time.
		return &agentv1.TaskResult{
			Status: agentv1.TaskResult_STATUS_SUCCEEDED, ExitCode: 0,
			Message: "the agent is already at version " + Version,
		}
	}

	manager, err := packages.Detect()
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorUnsupported, err.Error())
	}
	name, err := agentPackage(manager.Name(), payload.TargetVersion)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorUnsupported, err.Error())
	}

	timeout := timeoutOf(task, opspec.ActionAgentUpgrade)
	upgradeCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	// The result may never come back: installing the package restarts the agent
	// and with it this process. The panel knows that and decides by the return of
	// the host - which is why the report about the start matters more here than
	// usual.
	if e.progress != nil {
		e.progress(&agentv1.TaskProgress{
			TaskId: task.GetTaskId(), Step: 1, Total: 2,
			Message: "installing the agent at version " + payload.TargetVersion,
		})
	}

	// The repository metadata has to be fresh: a version released a quarter of
	// an hour ago does not exist for a manager that last looked at the repository
	// yesterday. The refresh is a separate, cheap step and changes nothing on the
	// host.
	if _, err := e.helper.Call(upgradeCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		TimeoutSeconds: 300,
		Action: &helperv1.HelperRequest_PackageAction{
			PackageAction: &helperv1.PackageActionRequest{
				Operation: helperv1.PackageActionRequest_OPERATION_REFRESH,
			},
		},
	}, 5*time.Minute); err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	response, err := e.helper.Call(upgradeCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_PackageAction{
			PackageAction: &helperv1.PackageActionRequest{
				Operation: helperv1.PackageActionRequest_OPERATION_INSTALL,
				Packages:  []string{name},
				// The version is given explicitly, so a downgrade is an operator
				// decision as well - that is how the return after a failed
				// release works.
				AllowDowngrade: true,
			},
		},
	}, timeout)
	if err != nil {
		// A broken connection to the helper during this operation usually means
		// the package managed to install and the restart is under way - together
		// with the socket of the helper. Sending back an error would be untrue
		// then: the success is decided by the return of the host with the new
		// version.
		return &agentv1.TaskResult{
			Status: agentv1.TaskResult_STATUS_UNSPECIFIED, ErrorCode: StatusAfterReplacement,
			Message: "the installation is in flight; the return of the agent decides the result",
		}
	}
	detail := applyToProto(response.GetPackageResult())
	if !response.GetAccepted() {
		result := rejected(agentv1.TaskResult_STATUS_FAILED,
			response.GetErrorCode(), response.GetMessage())
		result.Detail = &agentv1.TaskResult_PackageApply{PackageApply: detail}
		return result
	}

	// Even when the installation went through without a broken connection, the
	// success is not the exit code of the package manager: the agent may fail to
	// come up or come up in a different version. The task stays open until the
	// return.
	return &agentv1.TaskResult{
		Status: agentv1.TaskResult_STATUS_UNSPECIFIED, ErrorCode: StatusAfterReplacement,
		Message: "the package was installed; waiting for the agent to come back at version " +
			payload.TargetVersion,
		Detail: &agentv1.TaskResult_PackageApply{PackageApply: detail},
	}
}

// agentPackage assembles the package name with the version in the notation of
// the given manager.
//
// Every manager selects a version differently and that cannot be hidden behind
// a common notation: apt expects "package=version", dnf "package-version".
func agentPackage(manager, version string) (string, error) {
	switch manager {
	case "apt":
		return packages.AgentPackage + "=" + version, nil
	case "dnf":
		return packages.AgentPackage + "-" + version, nil
	}
	return "", fmt.Errorf("the manager %s cannot name a package version", manager)
}
