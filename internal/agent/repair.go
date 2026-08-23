package agent

import (
	"context"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// repairPackages odblokowuje operacje pakietowe przez helpera roota.
//
// Operacja konczy sie sukcesem tylko wtedy, gdy po naprawie nie zostal zaden
// pakiet blokujacy. Czesciowa naprawa jest wynikiem negatywnym z lista tego,
// co zostalo: host, na ktorym aktualizacje nadal nie przejda, nie moze byc
// raportowany jako naprawiony.
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
			Message:   "po naprawie nadal blokuja: " + nazwyPakietow(detail.GetStillBlocked()),
			Detail:    &agentv1.TaskResult_PackageRepair{PackageRepair: detail},
		}
	}

	komunikat := "operacje pakietowe odblokowane"
	if len(detail.GetAnswered()) == 0 {
		// Naprawa hosta, ktory niczego nie potrzebowal, jest powodzeniem.
		// Kampania obejmujaca cala flote trafi na takie hosty i nie moze
		// z tego powodu raportowac bledow.
		komunikat = "nic nie wymagalo naprawy"
	}
	return &agentv1.TaskResult{
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Message:  komunikat,
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
	for _, pakiet := range blocked {
		pytania := make([]*agentv1.DebconfQuestion, 0, len(pakiet.GetQuestions()))
		for _, pytanie := range pakiet.GetQuestions() {
			pytania = append(pytania, &agentv1.DebconfQuestion{
				Name: pytanie.GetName(), Value: pytanie.GetValue(), Answered: pytanie.Answered,
			})
		}
		result = append(result, &agentv1.BlockedPackage{
			Name: pakiet.GetName(), Status: pakiet.GetStatus(), Questions: pytania,
		})
	}
	return result
}

func nazwyPakietow(blocked []*agentv1.BlockedPackage) string {
	nazwy := make([]string, 0, len(blocked))
	for _, pakiet := range blocked {
		nazwy = append(nazwy, pakiet.GetName())
	}
	return joinNames(nazwy)
}
