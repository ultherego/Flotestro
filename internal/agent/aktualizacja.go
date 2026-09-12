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

// upgradeAgent wymienia samego agenta na wskazana wersje.
//
// To jedyna operacja, ktora konczy proces wykonujacy ja. Pakiet agenta jest
// chroniony przed zwykla aktualizacja wlasnie dlatego: host nie moze odciac
// sie od zarzadzania w srodku transakcji, ktorej wynik ma jeszcze odeslac.
// Tutaj robimy to swiadomie i rozliczamy inaczej - sukcesem jest powrot hosta
// z oczekiwana wersja, a nie kod wyjscia menedzera pakietow.
func (e *TaskExecutor) upgradeAgent(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.AgentUpgradePayload) *agentv1.TaskResult {
	if payload.TargetVersion == Version {
		// Powtorzone zlecenie nie jest bledem: host jest juz tam, gdzie mial
		// byc, i nie ma po co restartowac agenta drugi raz.
		return &agentv1.TaskResult{
			Status: agentv1.TaskResult_STATUS_SUCCEEDED, ExitCode: 0,
			Message: "agent jest juz w wersji " + Version,
		}
	}

	manager, err := packages.Detect()
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorUnsupported, err.Error())
	}
	nazwa, err := pakietAgenta(manager.Name(), payload.TargetVersion)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, packages.ErrorUnsupported, err.Error())
	}

	timeout := timeoutOf(task, opspec.ActionAgentUpgrade)
	upgradeCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	// Wynik moze nigdy nie wrocic: instalacja pakietu restartuje agenta,
	// a wraz z nim ten proces. Panel wie o tym i rozstrzyga po powrocie
	// hosta - dlatego meldunek o rozpoczeciu jest tu wazniejszy niz zwykle.
	if e.progress != nil {
		e.progress(&agentv1.TaskProgress{
			TaskId: task.GetTaskId(), Step: 1, Total: 2,
			Message: "instalacja agenta w wersji " + payload.TargetVersion,
		})
	}

	// Metadane repozytorium musza byc swieze: wersja wydana kwadrans temu nie
	// istnieje dla menedzera, ktory ostatni raz patrzyl na repozytorium
	// wczoraj. Odswiezenie jest osobnym, tanim krokiem i nie zmienia hosta.
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
				Packages:  []string{nazwa},
				// Wersja jest wskazana wprost, wiec cofniecie tez jest
				// decyzja operatora - tak dziala powrot po nieudanym wydaniu.
				AllowDowngrade: true,
			},
		},
	}, timeout)
	if err != nil {
		// Zerwane polaczenie z helperem przy tej operacji znaczy zwykle, ze
		// pakiet zdazyl sie zainstalowac, a restart wlasnie trwa - razem
		// z gniazdem helpera. Odeslanie bledu byloby wtedy nieprawda:
		// o powodzeniu rozstrzyga powrot hosta z nowa wersja.
		return &agentv1.TaskResult{
			Status: agentv1.TaskResult_STATUS_UNSPECIFIED, ErrorCode: StatusPoWymianie,
			Message: "instalacja w toku; wynik rozstrzygnie powrot agenta",
		}
	}
	detail := applyToProto(response.GetPackageResult())
	if !response.GetAccepted() {
		wynik := rejected(agentv1.TaskResult_STATUS_FAILED,
			response.GetErrorCode(), response.GetMessage())
		wynik.Detail = &agentv1.TaskResult_PackageApply{PackageApply: detail}
		return wynik
	}

	// Nawet gdy instalacja przeszla bez zerwania polaczenia, sukcesem nie
	// jest kod wyjscia menedzera pakietow: agent moze sie nie podniesc albo
	// podniesc w innej wersji. Zadanie zostaje otwarte do czasu powrotu.
	return &agentv1.TaskResult{
		Status: agentv1.TaskResult_STATUS_UNSPECIFIED, ErrorCode: StatusPoWymianie,
		Message: "pakiet zainstalowany; czekam na powrot agenta w wersji " +
			payload.TargetVersion,
		Detail: &agentv1.TaskResult_PackageApply{PackageApply: detail},
	}
}

// pakietAgenta sklada nazwe pakietu z wersja w zapisie danego menedzera.
//
// Kazdy menedzer wybiera wersje inaczej i nie da sie tego ukryc za wspolnym
// zapisem: apt oczekuje "pakiet=wersja", dnf "pakiet-wersja".
func pakietAgenta(menedzer, wersja string) (string, error) {
	switch menedzer {
	case "apt":
		return packages.AgentPackage + "=" + wersja, nil
	case "dnf":
		return packages.AgentPackage + "-" + wersja, nil
	}
	return "", fmt.Errorf("menedzer %s nie umie wskazac wersji pakietu", menedzer)
}
