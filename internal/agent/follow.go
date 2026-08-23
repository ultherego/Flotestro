package agent

import (
	"bufio"
	"context"
	"os/exec"
	"strconv"
	"sync"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Ograniczenia podgladu na zywo.
//
// Podglad jest jedyna operacja, ktora trzyma proces na hoscie tak dlugo, jak
// ktos patrzy - i tak dlugo, jak nikt nie patrzy, gdy operator zamknie karte.
// Dlatego kazdy jego wymiar ma gorna granice: czas trwania, tempo i wielkosc
// pojedynczej paczki.
const (
	// maksymalneTempoPodgladu ogranicza ilosc danych na sekunde. Host, ktory
	// wypisuje megabajty logow, nie moze przez to obciazyc ani lacza, ani
	// bazy powiadomien.
	maksymalneTempoPodgladu = 32 << 10
	// odstepPaczki zbiera linie, zanim je wysle. Wysylanie kazdej z osobna
	// kosztowaloby powiadomienie na kazda linie dziennika.
	odstepPaczki = 250 * time.Millisecond
	// maksymalnaPaczka ogranicza jedna wiadomosc. Powiadomienie w bazie ma
	// wlasny limit rozmiaru, wiec paczka musi sie w nim miescic z zapasem.
	maksymalnaPaczka = 6 << 10
	// domyslnyCzasPodgladu obowiazuje, gdy operator nie poda wlasnego.
	domyslnyCzasPodgladu = 5 * time.Minute
)

// anulowania trzyma funkcje przerywajace zadania, ktore da sie bezpiecznie
// przerwac. Nie kazda operacja systemowa taka jest - transakcji pakietowej
// nie wolno urwac w polowie - ale podglad dziennika jest odczytem i jego
// przerwanie niczego nie psuje.
type anulowania struct {
	mu    sync.Mutex
	akcje map[string]context.CancelFunc
}

func nowaTablicaAnulowan() *anulowania {
	return &anulowania{akcje: map[string]context.CancelFunc{}}
}

func (a *anulowania) zarejestruj(taskID string, cancel context.CancelFunc) func() {
	a.mu.Lock()
	a.akcje[taskID] = cancel
	a.mu.Unlock()
	return func() {
		a.mu.Lock()
		delete(a.akcje, taskID)
		a.mu.Unlock()
	}
}

// Anuluj przerywa zadanie, jesli da sie je przerwac. Zwraca informacje, czy
// bylo czego przerywac - anulowanie nieznanego zadania nie jest bledem, bo
// mogło sie wlasnie zakonczyc.
func (a *anulowania) Anuluj(taskID string) bool {
	a.mu.Lock()
	cancel, znane := a.akcje[taskID]
	a.mu.Unlock()
	if znane {
		cancel()
	}
	return znane
}

// followJournal strumieniuje dziennik do control plane.
func (e *TaskExecutor) followJournal(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.JournalPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "brak payloadu podgladu")
	}
	if e.logLines == nil {
		// Bez odbiorcy podglad nie ma sensu i nie ma powodu uruchamiac
		// procesu na hoscie.
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectUnsupported,
			"agent nie ma otwartej sesji do przekazania podgladu")
	}

	czas := time.Duration(payload.FollowSeconds) * time.Second
	if czas <= 0 || czas > 15*time.Minute {
		czas = domyslnyCzasPodgladu
	}
	followCtx, cancel := context.WithTimeout(ctx, czas)
	defer cancel()

	// Operator moze zamknac podglad wczesniej. Anulowanie odczytu niczego
	// nie psuje, wiec tutaj jest wykonywane, a nie tylko odnotowane.
	if e.cancels != nil {
		defer e.cancels.zarejestruj(task.GetTaskId(), cancel)()
	}

	args := argumentyPodgladu(payload)
	cmd := exec.CommandContext(followCtx, journalctlPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	if err := cmd.Start(); err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}

	wyslane, pominiete := e.przekazujLinie(followCtx, task.GetTaskId(), stdout)
	_ = cmd.Wait()

	// Koniec podgladu jest sukcesem: strumien mial sie skonczyc. Wynik mowi,
	// ile linii przeszlo i ile pominieto, bo cicha strata kazalaby operatorowi
	// wierzyc, ze widzial wszystko.
	return &agentv1.TaskResult{
		TaskId:  task.GetTaskId(),
		Status:  agentv1.TaskResult_STATUS_SUCCEEDED,
		Message: podsumowaniePodgladu(wyslane, pominiete),
	}
}

// przekazujLinie czyta wyjscie i wysyla je paczkami z ograniczonym tempem.
func (e *TaskExecutor) przekazujLinie(ctx context.Context, taskID string,
	wyjscie interface{ Read([]byte) (int, error) }) (wyslane, pominiete int) {
	linie := make(chan string, 256)
	go func() {
		defer close(linie)
		skaner := bufio.NewScanner(wyjscie)
		skaner.Buffer(make([]byte, 0, 16<<10), 256<<10)
		for skaner.Scan() {
			select {
			case linie <- skaner.Text():
			default:
				// Kanal pelny oznacza, ze host produkuje szybciej, niz
				// zdazymy wyslac. Linia przepada, ale liczba przepadnietych
				// jedzie dalej.
				pominiete++
			}
		}
	}()

	budzet := nowyBudzetTempa(maksymalneTempoPodgladu)
	tyknięcie := time.NewTicker(odstepPaczki)
	defer tyknięcie.Stop()

	paczka := make([]string, 0, 32)
	rozmiar := 0
	pominietePaczka := 0

	wyslij := func() {
		if len(paczka) == 0 && pominietePaczka == 0 {
			return
		}
		e.logLines(&agentv1.TaskLogLines{
			TaskId:  taskID,
			Lines:   append([]string(nil), paczka...),
			Dropped: uint32(pominietePaczka),
		})
		wyslane += len(paczka)
		paczka = paczka[:0]
		rozmiar = 0
		pominietePaczka = 0
	}

	for {
		select {
		case <-ctx.Done():
			wyslij()
			return wyslane, pominiete + pominietePaczka
		case <-tyknięcie.C:
			wyslij()
		case linia, otwarty := <-linie:
			if !otwarty {
				wyslij()
				return wyslane, pominiete + pominietePaczka
			}
			if !budzet.pozwala(len(linia) + 1) {
				pominiete++
				pominietePaczka++
				continue
			}
			paczka = append(paczka, linia)
			rozmiar += len(linia) + 1
			if rozmiar >= maksymalnaPaczka {
				wyslij()
			}
		}
	}
}

// budzetTempa ogranicza ilosc danych na sekunde.
type budzetTempa struct {
	naSekunde int
	dostepne  int
	ostatnie  time.Time
}

func nowyBudzetTempa(naSekunde int) *budzetTempa {
	return &budzetTempa{naSekunde: naSekunde, dostepne: naSekunde, ostatnie: time.Now()}
}

func (b *budzetTempa) pozwala(bajtow int) bool {
	teraz := time.Now()
	uplynelo := teraz.Sub(b.ostatnie)
	b.ostatnie = teraz
	b.dostepne += int(float64(b.naSekunde) * uplynelo.Seconds())
	if b.dostepne > b.naSekunde {
		b.dostepne = b.naSekunde
	}
	if b.dostepne < bajtow {
		return false
	}
	b.dostepne -= bajtow
	return true
}

// argumentyPodgladu sklada wywolanie z pol typowanych, nigdy ze sklejonego
// ciagu.
func argumentyPodgladu(payload *opspec.JournalPayload) []string {
	args := []string{"--follow", "--no-pager", "--output=short-iso"}
	backlog := payload.Lines
	if backlog == 0 || backlog > 500 {
		backlog = 50
	}
	args = append(args, "--lines", liczba(backlog))
	if payload.Unit != "" {
		args = append(args, "--unit", payload.Unit)
	}
	if payload.MaxPriority != nil {
		args = append(args, "--priority", liczba(*payload.MaxPriority))
	}
	return args
}

func podsumowaniePodgladu(wyslane, pominiete int) string {
	if pominiete == 0 {
		return "podglad zakonczony, linii: " + liczba(uint32(wyslane))
	}
	return "podglad zakonczony, linii: " + liczba(uint32(wyslane)) +
		", pominietych przez limit tempa: " + liczba(uint32(pominiete))
}

// liczba zamienia licznik na tekst argumentu.
func liczba(wartosc uint32) string {
	return strconv.FormatUint(uint64(wartosc), 10)
}
