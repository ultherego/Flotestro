package campaigns

import (
	"context"
	"encoding/json"

	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// zajmijPojemnosc pyta budzety, czy flota uniesie kolejna zmiane.
//
// Limit rownoleglosci kampanii i budzet odpowiadaja na dwa rozne pytania.
// Pierwszy mowi, ile hostow ma ruszyc naraz w tej jednej zmianie; drugi - ile
// zmian uniesie flota, lokalizacja i kanal. Dziesiec kampanii po piec hostow
// miesci sie w kazdym limicie kampanii i nadal jest piecdziesiecioma
// jednoczesnymi mutacjami, o ktorych nikt nie zdecydowal.
//
// Zwraca false, gdy pojemnosci nie ma. To nie jest blad: host wraca do kolejki
// ze stanem, ktory nazywa budzet blokujacy - i sprobuje przy nastepnym obiegu.
func (o *Orchestrator) zajmijPojemnosc(ctx context.Context, campaign Campaign,
	target *Target, host *hosts.Host) (bool, error) {
	if o.budzety == nil {
		return true, nil
	}
	action := opspec.ActionType(campaign.ActionType)
	// Repozytorium backupu jest zasobem wspolnym: budzet lokalizacji nie
	// wie nic o backendzie, do ktorego pisze pol floty naraz.
	repozytorium := repozytoriumKampanii(campaign)
	// Roszczacym jest kampania, a nie host: sprawiedliwosc dzieli tokeny
	// miedzy zmiany, nie miedzy maszyny. Inaczej kampania na tysiacu hostow
	// mialaby tysiac razy wiekszy udzial niz kampania na jednym.
	odmowa, err := o.budzety.Zajmij(ctx, target.ID, "campaign:"+campaign.ID,
		budgets.KlasaUtrzymanie, budgets.Potrzeby(action, host.Site, repozytorium))
	if err != nil {
		return false, err
	}
	if odmowa.Pusta() {
		return true, nil
	}

	// Cisza jest tu najgorsza odpowiedzia: host stojacy bez powodu wyglada
	// jak host zapomniany. Stan i komunikat nazywaja budzet i jego zajetosc.
	if target.State != TargetAwaitingBudget || target.ErrorCode != kodBudzetu(odmowa) {
		if err := o.store.UpdateTarget(ctx, target.ID, TargetAwaitingBudget,
			kodBudzetu(odmowa), odmowa.Opis()); err != nil {
			return false, err
		}
	}
	target.State = TargetAwaitingBudget
	target.ErrorCode = kodBudzetu(odmowa)
	return false, nil
}

// kodBudzetu nazywa przeszkode kodem, ktory da sie filtrowac.
func kodBudzetu(odmowa budgets.Odmowa) string {
	return "budget_" + odmowa.Powod
}

// zwolnijPojemnosc oddaje tokeny hosta.
//
// Blad zwolnienia nie zatrzymuje kampanii: dzierzawa i tak wygasnie sama.
// Milczec o nim jednak nie wolno - pojemnosc trzymana dluzej, niz trzeba,
// spowalnia cala flote.
func (o *Orchestrator) zwolnijPojemnosc(ctx context.Context, target *Target) {
	if o.budzety == nil {
		return
	}
	if err := o.budzety.Zwolnij(ctx, target.ID); err != nil {
		o.log.Error("nie zwolniono pojemnosci celu kampanii",
			"host_id", target.HostID, "err", err)
	}
}

// odnowPojemnosc przedluza dzierzawy hostow, ktore nadal pracuja.
//
// Transakcja pakietowa potrafi trwac kwadrans, a dzierzawa jest krotka:
// bez odnawiania pojemnosc wracalaby do puli w polowie pracy i system
// uruchamialby wiecej, niz naprawde uniesie.
func (o *Orchestrator) odnowPojemnosc(ctx context.Context, targets []Target) {
	if o.budzety == nil {
		return
	}
	pracujace := make([]string, 0, len(targets))
	for _, target := range targets {
		if !target.State.Finished() && !target.State.Czeka() {
			pracujace = append(pracujace, target.ID)
		}
	}
	if len(pracujace) == 0 {
		return
	}
	if err := o.budzety.Odnow(ctx, pracujace); err != nil {
		o.log.Error("nie odnowiono pojemnosci kampanii", "err", err)
	}
}

// repozytoriumKampanii wyjmuje z zamowienia adres repozytorium backupu.
//
// Puste znaczy kampanie, ktora backendu nie dotyka - a nie backend nieznany:
// operacje spoza modulu kopii nie maja tu czego szukac.
func repozytoriumKampanii(campaign Campaign) string {
	if len(campaign.Payload) == 0 {
		return ""
	}
	var payload opspec.Payload
	if err := json.Unmarshal(campaign.Payload, &payload); err != nil {
		return ""
	}
	if payload.Backup == nil {
		return ""
	}
	return payload.Backup.Repository
}
