package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/security"
	"github.com/ultherego/flotestro/internal/opspec"
)

// securityProbe sklada stan ochronny hosta. Wiekszosc faktow czyta sam agent;
// helper dostaje wylacznie te, ktorych bez roota nie widac.
var securityProbe func(context.Context) (security.Snapshot, error)

// SetSecurityProbe wskazuje funkcje skladajaca stan ochronny.
func SetSecurityProbe(probe func(context.Context) (security.Snapshot, error)) {
	securityProbe = probe
}

// faktyHelpera tlumaczy nazwy faktow modulu na wyliczenie protokolu.
var faktyHelpera = map[string]helperv1.SecurityRequest_Fact{
	security.FaktProfileAppArmor:   helperv1.SecurityRequest_FACT_APPARMOR_PROFILES,
	security.FaktRegulyAudytu:      helperv1.SecurityRequest_FACT_AUDIT_RULES,
	security.FaktSecureBoot:        helperv1.SecurityRequest_FACT_SECURE_BOOT,
	security.FaktWlascicieleGniazd: helperv1.SecurityRequest_FACT_SOCKET_OWNERS,
}

// ZbierzOchrone czyta stan ochronny hosta.
//
// Najpierw to, co widac bez roota - tryb SELinuksa, przelacznik AppArmora,
// FIPS, lockdown, stan jednostki audytu i lista gniazd. Dopiero brakujace
// fakty agent zamawia u helpera, po nazwie i po jednym: modul nie idzie przez
// roota w calosci tylko dlatego, ze czesc jego obrazu tego wymaga.
func (e *TaskExecutor) ZbierzOchrone(ctx context.Context) security.Snapshot {
	snapshot := security.Zbierz(ctx, wyjsciePolecenia)
	brakujace := snapshot.Brakujace()
	if len(brakujace) == 0 {
		return snapshot
	}

	zadane := make([]helperv1.SecurityRequest_Fact, 0, len(brakujace))
	for _, nazwa := range brakujace {
		if fakt, znany := faktyHelpera[nazwa]; znany {
			zadane = append(zadane, fakt)
		}
	}
	if len(zadane) == 0 {
		return snapshot
	}

	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Security{
			Security: &helperv1.SecurityRequest{
				Operation: helperv1.SecurityRequest_OPERATION_FACTS,
				Facts:     zadane,
			},
		},
	}, time.Minute)
	if err != nil {
		// Brak helpera nie unieważnia tego, co juz wiadomo: obraz zostaje
		// niepelny, a powody brakow mowia, czego w nim nie ma.
		for _, nazwa := range brakujace {
			snapshot.Missing[nazwa] = "helper: " + err.Error()
		}
		return snapshot
	}
	if !response.GetAccepted() {
		for _, nazwa := range brakujace {
			snapshot.Missing[nazwa] = "helper: " + response.GetMessage()
		}
		return snapshot
	}

	var dodatki security.Uzupelnienie
	dane := response.GetSecurityResult().GetFacts()
	if len(dane) > 0 {
		if err := json.Unmarshal(dane, &dodatki); err != nil {
			for _, nazwa := range brakujace {
				snapshot.Missing[nazwa] = "helper: " + err.Error()
			}
			return snapshot
		}
	}
	return snapshot.Uzupelnij(dodatki)
}

// ProbeSecurity odczytuje stan ochronny hosta na potrzeby inwentarza.
func (e *TaskExecutor) ProbeSecurity(ctx context.Context) (security.Snapshot, error) {
	return e.ZbierzOchrone(ctx), nil
}

// applySecurity wykonuje operacje modulu bezpieczenstwa.
func (e *TaskExecutor) applySecurity(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.SecurityPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+15*time.Second)
	defer cancel()

	komunikat := "stan ochronny odczytany"
	if action == opspec.ActionSELinuxModeSet || action == opspec.ActionAuditRulesReload {
		zadanie := &helperv1.SecurityRequest{
			Operation: helperv1.SecurityRequest_OPERATION_AUDIT_RELOAD,
		}
		if action == opspec.ActionSELinuxModeSet {
			zadanie.Operation = helperv1.SecurityRequest_OPERATION_SELINUX_MODE
			if payload != nil {
				zadanie.Mode = payload.Mode
			}
		}
		response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
			TaskId:         task.GetTaskId(),
			ExpiresAt:      task.GetExpiresAt(),
			TimeoutSeconds: uint32(timeout.Seconds()),
			Action:         &helperv1.HelperRequest_Security{Security: zadanie},
		}, timeout)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
		}
		if !response.GetAccepted() {
			odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
				response.GetErrorCode(), response.GetMessage())
			odrzucone.TaskId = task.GetTaskId()
			return odrzucone
		}
		komunikat = response.GetSecurityResult().GetMessage()
	}

	// Obraz po operacji sklada agent, tak samo jak przy zwyklym odczycie.
	snapshot := e.ZbierzOchrone(callCtx)
	zakodowany, err := json.Marshal(snapshot)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	return &agentv1.TaskResult{
		TaskId:         task.GetTaskId(),
		Status:         agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:        komunikat,
		SecurityResult: &agentv1.SecurityResult{Snapshot: zakodowany, Message: komunikat},
	}
}
