package agent

import (
	"context"
	"strings"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// Kody wyniku odswiezenia inwentarza. Sa czescia kontraktu: to one mowia
// panelowi, dlaczego obraz nie przyszedl.
const (
	// ErrorInventoryUnavailable oznacza brak sesji, w ktorej mozna by
	// odeslac nowy obraz. Odswiezenie bez odbiorcy nie ma sensu.
	ErrorInventoryUnavailable = "inventory_refresh_unavailable"
	// ErrorInventoryFailed oznacza nieudany odczyt hosta.
	ErrorInventoryFailed = "inventory_refresh_failed"
)

// odswiezInwentarza zbiera inwentarz na zadanie i odsyla rewizje, ktora
// z niego powstala.
//
// Zadanie konczy sie dopiero wtedy, gdy nowy obraz naprawde powstal i zostal
// wyslany. Samo przyjecie zlecenia niczego nie dowodzi: odczyt moglby sie nie
// udac albo nie dojsc, a panel dalej pokazywalby stan sprzed kwadransa
// z adnotacja "odswiezono".
//
// Rownolegle prosby o odswiezenie dolaczaja do trwajacego zebrania zamiast
// uruchamiac drugie: host zaplacilby dwa razy za ten sam obraz.
func (e *TaskExecutor) odswiezInwentarza(ctx context.Context,
	task *agentv1.TaskEnvelope) *agentv1.TaskResult {
	if e.odswiezInwentarz == nil {
		// Bez sesji nie ma dokad wyslac obrazu. Odmowa z powodem jest
		// lepsza niz sukces, po ktorym nic nie przyszlo.
		return rejected(agentv1.TaskResult_STATUS_REJECTED, ErrorInventoryUnavailable,
			"agent nie ma sesji, w ktorej moglby odeslac inwentarz")
	}
	moduly := task.GetRefreshInventory().GetModules()

	wynik := e.odswiez(ctx, moduly)
	if wynik.Blad != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, ErrorInventoryFailed,
			wynik.Blad.Error())
	}

	opis := "inwentarz odswiezony"
	if len(wynik.Moduly) > 0 {
		opis += " (" + strings.Join(wynik.Moduly, ", ") + ")"
	}
	if !wynik.Zmieniona {
		// Brak zmiany jest prawdziwa odpowiedzia, a nie porazka: host, ktory
		// wyglada tak samo, wyglada tak samo.
		opis += "; obraz bez zmian"
	}
	return &agentv1.TaskResult{
		Status: agentv1.TaskResult_STATUS_SUCCEEDED, ExitCode: 0, Message: opis,
		InventoryRefreshResult: &agentv1.InventoryRefreshResult{
			Revision: wynik.Rewizja,
			Changed:  wynik.Zmieniona,
			Modules:  wynik.Moduly,
		},
	}
}

// odswiez wola haczyk sesji. Osobna metoda, bo pole i metoda nie moga miec
// tej samej nazwy.
func (e *TaskExecutor) odswiez(ctx context.Context, moduly []string) Odswiezenie {
	return e.odswiezInwentarz(ctx, moduly)
}
