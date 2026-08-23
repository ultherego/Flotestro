package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/firewall"
	"github.com/ultherego/flotestro/internal/opspec"
)

// firewallProbe czyta stan zapory przez helpera: tablice nftables sa
// widoczne wylacznie dla roota.
var firewallProbe func(context.Context) (firewall.Snapshot, error)

// SetFirewallProbe wskazuje funkcje odczytujaca stan zapory.
func SetFirewallProbe(probe func(context.Context) (firewall.Snapshot, error)) {
	firewallProbe = probe
}

// ProbeFirewall odczytuje stan zapory hosta.
func (e *TaskExecutor) ProbeFirewall(ctx context.Context) (firewall.Snapshot, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Firewall{
			Firewall: &helperv1.FirewallRequest{
				Operation: helperv1.FirewallRequest_OPERATION_READ,
			},
		},
	}, time.Minute)
	if err != nil {
		return firewall.Snapshot{}, err
	}
	var snapshot firewall.Snapshot
	dane := response.GetFirewallResult().GetSnapshot()
	if len(dane) == 0 {
		return snapshot, nil
	}
	if err := json.Unmarshal(dane, &snapshot); err != nil {
		return firewall.Snapshot{}, err
	}
	return snapshot, nil
}

// applyFirewall zmienia zapore i potwierdza, ze host nadal rozmawia z panelem.
func (e *TaskExecutor) applyFirewall(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.FirewallPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "brak payloadu zapory")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	operacja := helperv1.FirewallRequest_OPERATION_RULE_ENSURE
	switch action {
	case opspec.ActionFirewallPlan:
		operacja = helperv1.FirewallRequest_OPERATION_READ
	case opspec.ActionFirewallRuleRemove:
		operacja = helperv1.FirewallRequest_OPERATION_RULE_REMOVE
	case opspec.ActionFirewallZonePort:
		operacja = helperv1.FirewallRequest_OPERATION_ZONE_PORT
	case opspec.ActionFirewallZoneService:
		operacja = helperv1.FirewallRequest_OPERATION_ZONE_SERVICE
	case opspec.ActionFirewallRulesetRestore:
		operacja = helperv1.FirewallRequest_OPERATION_RESTORE
	}

	// Adres i port kanalu zarzadzania sa faktem znanym agentowi, a nie
	// panelowi: to agent wie, ktora droga naprawde rozmawia.
	adres, port := kanalZarzadzania()

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Firewall{
			Firewall: &helperv1.FirewallRequest{
				Operation:         operacja,
				RuleId:            payload.RuleID,
				Chain:             payload.Chain,
				Action:            payload.Action,
				Protocol:          payload.Protocol,
				Ports:             payload.Ports,
				Sources:           payload.Sources,
				Interface:         payload.Interface,
				Comment:           payload.Comment,
				Zone:              payload.Zone,
				Service:           payload.Service,
				Enable:            payload.Enable,
				ManagementAddress: adres,
				ManagementPort:    uint32(port),
				BreakGlass:        payload.BreakGlass,
				RollbackSeconds:   payload.RollbackSeconds,
				RollbackId:        payload.RollbackID,
				ExpectedHash:      payload.ExpectedHash,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetFirewallResult()
	szczegoly := &agentv1.FirewallResult{
		Snapshot:         wynik.GetSnapshot(),
		Message:          wynik.GetMessage(),
		RollbackId:       wynik.GetRollbackId(),
		RollbackDeadline: wynik.GetRollbackDeadline(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.FirewallResult = szczegoly
		return odrzucone
	}

	if wynik.GetRollbackId() == "" {
		return &agentv1.TaskResult{
			TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_SUCCEEDED,
			Message: wynik.GetMessage(), FirewallResult: szczegoly,
		}
	}

	termin := terminWycofania(wynik.GetRollbackDeadline())
	if !czekajNaPanel(ctx, adresPanelu, termin.Add(-marginesPotwierdzenia)) {
		return &agentv1.TaskResult{
			TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
			ErrorCode:      RejectNetworkUnreachable,
			Message:        "po zmianie zapory host nie dosiega panelu; wycofanie o " + wynik.GetRollbackDeadline(),
			FirewallResult: szczegoly,
		}
	}

	potwierdzenie, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TaskId: task.GetTaskId(), TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Firewall{
			Firewall: &helperv1.FirewallRequest{
				Operation:  helperv1.FirewallRequest_OPERATION_CONFIRM,
				RollbackId: wynik.GetRollbackId(),
			},
		},
	}, time.Minute)
	if err != nil || !potwierdzenie.GetAccepted() {
		return &agentv1.TaskResult{
			TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
			ErrorCode: RejectHelperFailed, Message: "nie rozbrojono wycofania",
			FirewallResult: szczegoly,
		}
	}
	szczegoly.Snapshot = potwierdzenie.GetFirewallResult().GetSnapshot()
	szczegoly.Confirmed = true
	return &agentv1.TaskResult{
		TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:        wynik.GetMessage() + "; lacznosc potwierdzona, wycofanie rozbrojone",
		FirewallResult: szczegoly,
	}
}

// kanalZarzadzania zwraca adres i port, ktorymi host rozmawia z panelem.
//
// To agent wie, ktora droga naprawde idzie ruch: panel widzi tylko adres,
// z ktorego przyszlo polaczenie, a helper nie widzi go wcale.
func kanalZarzadzania() (string, int) {
	parsed, err := url.Parse(adresPanelu)
	if err != nil || parsed.Hostname() == "" {
		return "", 0
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	numer, err := net.LookupPort("tcp", port)
	if err != nil {
		return parsed.Hostname(), 0
	}
	return parsed.Hostname(), numer
}
