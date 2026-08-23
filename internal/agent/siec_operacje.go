package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// marginesPotwierdzenia to czas, ktory zostawiamy zegarowi wycofania.
// Potwierdzenie wyslane w ostatniej sekundzie moglo by minac sie z zegarem
// i host wrocilby do starej konfiguracji mimo udanej zmiany.
const marginesPotwierdzenia = 20 * time.Second

// odstepProbyLacznosci mowi, jak czesto agent sprawdza droge do panelu.
const odstepProbyLacznosci = 3 * time.Second

// applyNetwork zmienia konfiguracje sieci i potwierdza, ze host nadal
// rozmawia z panelem.
//
// Kolejnosc jest tu cala trescia operacji: helper uzbraja wycofanie, zmienia
// konfiguracje, a agent dopiero potem sprawdza, czy droga do panelu nadal
// istnieje. Potwierdzenie wysylane bez tego sprawdzenia rozbrajaloby zegar
// ratunkowy dokladnie wtedy, gdy jest potrzebny.
func (e *TaskExecutor) applyNetwork(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.NetworkPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"brak payloadu sieci")
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	operacja := helperv1.NetworkRequest_OPERATION_APPLY_PROFILE
	switch action {
	case opspec.ActionNetworkPlan:
		operacja = helperv1.NetworkRequest_OPERATION_READ
	case opspec.ActionNetworkMTUSet:
		operacja = helperv1.NetworkRequest_OPERATION_SET_MTU
	case opspec.ActionNetworkRouteEnsure:
		operacja = helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES
	case opspec.ActionNetworkRollback:
		operacja = helperv1.NetworkRequest_OPERATION_ROLLBACK
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Network{
			Network: &helperv1.NetworkRequest{
				Operation:       operacja,
				Interface:       payload.Interface,
				Mtu:             payload.MTU,
				Routes:          payload.Routes,
				Method:          payload.Method,
				Addresses:       payload.Addresses,
				Gateway:         payload.Gateway,
				Dns:             payload.DNS,
				RollbackSeconds: payload.RollbackSeconds,
				RollbackId:      payload.RollbackID,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetNetworkResult()
	szczegoly := &agentv1.NetworkResult{
		Profiles:         wynik.GetProfiles(),
		Message:          wynik.GetMessage(),
		RollbackId:       wynik.GetRollbackId(),
		RollbackDeadline: wynik.GetRollbackDeadline(),
		Confirmed:        wynik.GetConfirmed(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.NetworkResult = szczegoly
		return odrzucone
	}

	// Operacja bez uzbrojonego wycofania niczego nie zmienila w sieci.
	if wynik.GetRollbackId() == "" {
		return &agentv1.TaskResult{
			TaskId:        task.GetTaskId(),
			Status:        agentv1.TaskResult_STATUS_SUCCEEDED,
			Message:       wynik.GetMessage(),
			NetworkResult: szczegoly,
		}
	}

	termin := terminWycofania(wynik.GetRollbackDeadline())
	if !czekajNaPanel(ctx, adresPanelu, termin.Add(-marginesPotwierdzenia)) {
		// Nie potwierdzamy. Host wroci sam do konfiguracji sprzed zmiany,
		// a operator ma sie o tym dowiedziec od razu, a nie z ciszy.
		szczegoly.Confirmed = false
		return &agentv1.TaskResult{
			TaskId:        task.GetTaskId(),
			Status:        agentv1.TaskResult_STATUS_FAILED,
			Message:       fmt.Sprintf("po zmianie host nie dosiega panelu; wycofanie o %s", wynik.GetRollbackDeadline()),
			ErrorCode:     RejectNetworkUnreachable,
			NetworkResult: szczegoly,
		}
	}

	potwierdzenie, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Network{
			Network: &helperv1.NetworkRequest{
				Operation:  helperv1.NetworkRequest_OPERATION_CONFIRM,
				RollbackId: wynik.GetRollbackId(),
			},
		},
	}, time.Minute)
	if err != nil || !potwierdzenie.GetAccepted() {
		// Zmiana sie udala, ale zegar zostal uzbrojony: za chwile wycofa
		// zmiane, ktora dziala. Operator ma o tym wiedziec.
		komunikat := "nie rozbrojono wycofania"
		if err != nil {
			komunikat += ": " + err.Error()
		} else {
			komunikat += ": " + potwierdzenie.GetMessage()
		}
		szczegoly.Confirmed = false
		return &agentv1.TaskResult{
			TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
			ErrorCode: RejectHelperFailed, Message: komunikat, NetworkResult: szczegoly,
		}
	}

	szczegoly.Profiles = potwierdzenie.GetNetworkResult().GetProfiles()
	szczegoly.Confirmed = true
	return &agentv1.TaskResult{
		TaskId:        task.GetTaskId(),
		Status:        agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:       wynik.GetMessage() + "; lacznosc potwierdzona, wycofanie rozbrojone",
		NetworkResult: szczegoly,
	}
}

// adresPanelu trzyma adres control plane na potrzeby sprawdzenia lacznosci
// po zmianie sieci.
var adresPanelu string

// SetGatewayURL zapamietuje adres control plane.
func SetGatewayURL(gatewayURL string) { adresPanelu = gatewayURL }

// czekajNaPanel sprawdza, czy host nadal dosiega panelu.
//
// Sprawdzamy polaczenie TCP, a nie sesje agenta: sesja moze jeszcze zyc na
// starym gniezdzie, ktore jadro trzyma mimo zmiany adresu, i powiedzialaby
// nam, ze wszystko dziala, kiedy nowe polaczenie juz nie przejdzie.
func czekajNaPanel(ctx context.Context, gatewayURL string, doKiedy time.Time) bool {
	adres := adresGniazda(gatewayURL)
	if adres == "" {
		// Bez znanego adresu panelu nie potrafimy sprawdzic lacznosci,
		// a zgadywanie "chyba dziala" rozbraja zegar ratunkowy.
		return false
	}
	for {
		conn, err := net.DialTimeout("tcp", adres, 5*time.Second)
		if err == nil {
			_ = conn.Close()
			return true
		}
		if time.Now().After(doKiedy) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(odstepProbyLacznosci):
		}
	}
}

func adresGniazda(gatewayURL string) string {
	parsed, err := url.Parse(gatewayURL)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(parsed.Hostname(), port)
}

func terminWycofania(wartosc string) time.Time {
	termin, err := time.Parse(time.RFC3339, wartosc)
	if err != nil {
		return time.Now().Add(2 * time.Minute)
	}
	return termin
}

// ProfileSieci odczytuje profile NetworkManagera przez helpera.
func (e *TaskExecutor) ProfileSieci(ctx context.Context) (json.RawMessage, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Network{
			Network: &helperv1.NetworkRequest{Operation: helperv1.NetworkRequest_OPERATION_READ},
		},
	}, time.Minute)
	if err != nil {
		return nil, err
	}
	if !response.GetAccepted() {
		return nil, fmt.Errorf("%s: %s", response.GetErrorCode(), response.GetMessage())
	}
	return response.GetNetworkResult().GetProfiles(), nil
}
