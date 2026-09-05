package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// listPackages odczytuje pelna liste zainstalowanych pakietow.
//
// Bez roota i bez helpera: baza dpkg i baza RPM sa czytelne dla wszystkich,
// a kazde przejscie przez roota trzeba uzasadnic. Lista jest duza, wiec idzie
// na zadanie panelu - w inwentarzu zostaje sam odcisk i liczba pakietow.
func (e *TaskExecutor) listPackages(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	odczytCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	menedzer := menedzerHosta(odczytCtx)
	lista := packages.Zainstalowane(odczytCtx, menedzer)
	zakodowana, err := json.Marshal(lista.Packages)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}

	// Ustalenia producenta czytamy przy tej samej okazji: dla dnf leza
	// w metadanych repozytoriow, ktore host i tak ma. To sa fakty o pakietach,
	// tak samo jak sama lista - ocena powstaje w panelu.
	ustalenia, powodUstalen := packages.Ustalenia(odczytCtx, menedzer, lista.Packages)
	zakodowaneUstalenia, err := json.Marshal(ustalenia)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}

	// Nieodczytana lista nie moze wygladac jak host bez pakietow: to jest
	// odpowiedz "nie wiadomo", a na jej podstawie nie wolno powiedziec
	// niczego o podatnosciach.
	komunikat := "odczytano " + itoa(lista.Count) + " pakietow, " +
		itoa(len(ustalenia)) + " ustalen producenta"
	if lista.UnavailableReason != "" {
		komunikat = "listy pakietow nie odczytano: " + lista.UnavailableReason
	}
	return &agentv1.TaskResult{
		TaskId:  task.GetTaskId(),
		Status:  agentv1.TaskResult_STATUS_SUCCEEDED,
		Message: komunikat,
		InstalledPackagesResult: &agentv1.InstalledPackagesResult{
			Packages:                    zakodowana,
			Digest:                      lista.Digest,
			Count:                       uint32(lista.Count),
			Manager:                     lista.Manager,
			UnavailableReason:           lista.UnavailableReason,
			Advisories:                  zakodowaneUstalenia,
			AdvisoriesUnavailableReason: powodUstalen,
		},
	}
}

// menedzerHosta zwraca nazwe menedzera pakietow hosta albo pustke.
func menedzerHosta(ctx context.Context) string {
	menedzer, err := packages.Detect()
	if err != nil {
		return ""
	}
	_ = ctx
	return menedzer.Name()
}

// itoa jest krotkim zapisem liczby w komunikacie.
func itoa(wartosc int) string {
	if wartosc == 0 {
		return "0"
	}
	var cyfry []byte
	for wartosc > 0 {
		cyfry = append([]byte{byte('0' + wartosc%10)}, cyfry...)
		wartosc /= 10
	}
	return string(cyfry)
}

// odciskPakietow liczy odcisk listy pakietow na potrzeby inwentarza.
func odciskPakietow(ctx context.Context, menedzer string) (string, int, string) {
	if menedzer == "" {
		return "", 0, "this host has no supported package manager"
	}
	odczytCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	lista := packages.Zainstalowane(odczytCtx, menedzer)
	return lista.Digest, lista.Count, lista.UnavailableReason
}
