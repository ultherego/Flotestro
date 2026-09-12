package agent

import (
	"context"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// repairPackages unblocks the package operations through the root helper.
//
// The operation ends in success only when no blocking package is left after the
// repair. A partial repair is a negative result with a list of what remains: a
// host on which the updates still will not go through must not be reported as
// repaired.
func (e *TaskExecutor) repairPackages(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.PackageRepairPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, opspec.ActionPackageRepair)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	answers := make([]*helperv1.DebconfSelection, 0, len(payload.Answers))
	for _, answer := range payload.Answers {
		answers = append(answers, &helperv1.DebconfSelection{
			Package:  answer.Package,
			Question: answer.Question,
			Type:     answer.Type,
			Value:    answer.Value,
		})
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		MaxOutputBytes: task.GetLimits().GetMaxOutputBytes(),
		Action: &helperv1.HelperRequest_PackageRepair{
			PackageRepair: &helperv1.PackageRepairRequest{Answers: answers},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	detail := repairResultToAgent(response.GetRepairResult())
	if !response.GetAccepted() {
		result := rejected(agentv1.TaskResult_STATUS_FAILED,
			response.GetErrorCode(), response.GetMessage())
		result.Stderr = response.GetStderr()
		result.Detail = &agentv1.TaskResult_PackageRepair{PackageRepair: detail}
		return result
	}

	if len(detail.GetStillBlocked()) > 0 {
		return &agentv1.TaskResult{
			Status:    agentv1.TaskResult_STATUS_FAILED,
			ExitCode:  1,
			ErrorCode: "packages_still_blocked",
			Message:   "still blocking after the repair: " + packageNames(detail.GetStillBlocked()),
			Detail:    &agentv1.TaskResult_PackageRepair{PackageRepair: detail},
		}
	}

	message := "the package operations were unblocked"
	if len(detail.GetAnswered()) == 0 {
		// A repair of a host that needed nothing is a success. A campaign
		// covering the whole fleet will meet such hosts and must not report
		// errors because of them.
		message = "nothing needed a repair"
	}
	return &agentv1.TaskResult{
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Message:  message,
		Detail:   &agentv1.TaskResult_PackageRepair{PackageRepair: detail},
	}
}

func repairResultToAgent(response *helperv1.PackageRepairResponse) *agentv1.PackageRepairResult {
	if response == nil {
		return &agentv1.PackageRepairResult{}
	}
	return &agentv1.PackageRepairResult{
		Manager:      response.GetManager(),
		Answered:     response.GetAnswered(),
		Repaired:     response.GetRepaired(),
		StillBlocked: blockedToAgent(response.GetStillBlocked()),
	}
}

func blockedToAgent(blocked []*helperv1.BlockedPackageDetail) []*agentv1.BlockedPackage {
	result := make([]*agentv1.BlockedPackage, 0, len(blocked))
	for _, pkg := range blocked {
		questions := make([]*agentv1.DebconfQuestion, 0, len(pkg.GetQuestions()))
		for _, question := range pkg.GetQuestions() {
			questions = append(questions, &agentv1.DebconfQuestion{
				Name: question.GetName(), Value: question.GetValue(), Answered: question.Answered,
			})
		}
		result = append(result, &agentv1.BlockedPackage{
			Name: pkg.GetName(), Status: pkg.GetStatus(), Questions: questions,
		})
	}
	return result
}

func packageNames(blocked []*agentv1.BlockedPackage) string {
	names := make([]string, 0, len(blocked))
	for _, pkg := range blocked {
		names = append(names, pkg.GetName())
	}
	return joinNames(names)
}
