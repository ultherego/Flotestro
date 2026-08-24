package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	czas "github.com/ultherego/flotestro/internal/modules/time"
	"github.com/ultherego/flotestro/internal/opspec"
)

// czasZapytania ogranicza jedno zapytanie do serwera czasu. Serwer, ktory nie
// odpowiada w kilka sekund, jest dla hosta bezuzyteczny niezaleznie od tego,
// czy odpowie w trzydziesci.
const czasZapytania = 5 * time.Second

// ZbierzCzas czyta stan czasu hosta.
//
// Odczyt nie wymaga roota: timedatectl pyta uslugi przez magistrale systemowa,
// chronyc rozmawia z demonem po petli zwrotnej, a pliki konfiguracyjne czasu
// sa czytelne dla wszystkich.
func ZbierzCzas(ctx context.Context) czas.Snapshot {
	return czas.Zbierz(ctx, wyjsciePolecenia)
}

// applyTime wykonuje operacje modulu czasu.
func (e *TaskExecutor) applyTime(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.TimePayload) *agentv1.TaskResult {
	if payload == nil {
		payload = &opspec.TimePayload{}
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if action == opspec.ActionTimeSyncTest {
		return e.testujCzas(callCtx, task, payload)
	}

	// Serwery sprawdzamy, zanim host odda dzialajace zrodlo. Test jest tu,
	// a nie w helperze, bo nie wymaga roota - helper sprawdza to, co dotyczy
	// bezpieczenstwa zapisu, czyli sama postac wpisow.
	var pomiary []czas.Pomiar
	if action == opspec.ActionTimeConfigApply {
		pomiary = czas.ZapytajWiele(callCtx, payload.Servers, czasZapytania)
		if czas.Osiagalne(pomiary) == 0 {
			return odrzuconyCzas(task, RejectPrecondition,
				"zaden z podanych serwerow czasu nie odpowiedzial: "+opisPomiarow(pomiary), pomiary)
		}
		najlepszy := czas.NajlepszyPomiar(pomiary)
		if czas.Skok(najlepszy) && !payload.AllowStep {
			return odrzuconyCzas(task, RejectPrecondition, fmt.Sprintf(
				"zmiana przestawi zegar o %s wzgledem %s; skok czasu cofa waznosc "+
					"tokenow i certyfikatow, wiec wymaga jawnej zgody",
				sekundy(najlepszy.OffsetSeconds), najlepszy.Server), pomiary)
		}
	}

	operacja := helperv1.TimeRequest_OPERATION_CONFIG_APPLY
	if action == opspec.ActionTimezoneSet {
		operacja = helperv1.TimeRequest_OPERATION_TIMEZONE_SET
	}
	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Time{
			Time: &helperv1.TimeRequest{
				Operation:    operacja,
				Servers:      payload.Servers,
				Timezone:     payload.Timezone,
				AllowStep:    payload.AllowStep,
				EnableDropin: payload.EnableDropIn,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetTimeResult()
	szczegoly := &agentv1.TimeResult{
		Snapshot: wynik.GetSnapshot(),
		Message:  wynik.GetMessage(),
		Probes:   zakodujPomiary(pomiary),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.TimeResult = szczegoly
		return odrzucone
	}
	return &agentv1.TaskResult{
		TaskId:     task.GetTaskId(),
		Status:     agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:    wynik.GetMessage(),
		TimeResult: szczegoly,
	}
}

// testujCzas mierzy przesuniecie wobec wskazanych serwerow.
//
// Bez wskazania panel pyta serwery, ktorych host uzywa: to odpowiada na
// pytanie "czy moj zegar jest dobry", a nie tylko "czy demon dziala".
func (e *TaskExecutor) testujCzas(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.TimePayload) *agentv1.TaskResult {
	snapshot := ZbierzCzas(ctx)
	serwery := payload.Probe
	if len(serwery) == 0 {
		serwery = serweryZKonfiguracji(snapshot)
	}
	if len(serwery) == 0 {
		return odrzuconyCzas(task, RejectPrecondition,
			"ten host nie ma skonfigurowanego zadnego serwera czasu", nil)
	}

	pomiary := czas.ZapytajWiele(ctx, serwery, czasZapytania)
	snapshot.Probes = pomiary
	zakodowany, err := json.Marshal(snapshot)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	return &agentv1.TaskResult{
		TaskId:  task.GetTaskId(),
		Status:  agentv1.TaskResult_STATUS_SUCCEEDED,
		Message: opisPomiarow(pomiary),
		TimeResult: &agentv1.TimeResult{
			Snapshot: zakodowany,
			Message:  opisPomiarow(pomiary),
			Probes:   zakodujPomiary(pomiary),
		},
	}
}

// serweryZKonfiguracji wybiera adresy do zapytania.
//
// Pula rozwija sie na wiele adresow i sama nie jest serwerem, wiec pytamy
// zrodla, ktore demon naprawde wybral; dopiero gdy zadnego nie ma, siegamy
// po wpisy konfiguracyjne.
func serweryZKonfiguracji(snapshot czas.Snapshot) []string {
	var serwery []string
	widziane := map[string]bool{}
	for _, zrodlo := range snapshot.Sources {
		if zrodlo.Address != "" && !widziane[zrodlo.Address] {
			widziane[zrodlo.Address] = true
			serwery = append(serwery, zrodlo.Address)
		}
	}
	if len(serwery) > 0 {
		return ograniczListe(serwery)
	}
	for _, serwer := range snapshot.Configured {
		if serwer.Pool || serwer.Address == "" || widziane[serwer.Address] {
			continue
		}
		widziane[serwer.Address] = true
		serwery = append(serwery, serwer.Address)
	}
	if len(serwery) == 0 {
		for _, serwer := range snapshot.Configured {
			if serwer.Address != "" {
				serwery = append(serwery, serwer.Address)
			}
		}
	}
	return ograniczListe(serwery)
}

func ograniczListe(serwery []string) []string {
	if len(serwery) > czas.LimitSerwerow {
		return serwery[:czas.LimitSerwerow]
	}
	return serwery
}

// opisPomiarow streszcza wynik testu jednym zdaniem.
func opisPomiarow(pomiary []czas.Pomiar) string {
	if len(pomiary) == 0 {
		return "nie zadano zadnego pytania"
	}
	osiagalne := czas.Osiagalne(pomiary)
	opis := strconv.Itoa(osiagalne) + " z " + strconv.Itoa(len(pomiary)) + " serwerow odpowiedzialo"
	if najlepszy := czas.NajlepszyPomiar(pomiary); najlepszy != nil {
		opis += "; przesuniecie " + sekundy(najlepszy.OffsetSeconds) + " wzgledem " + najlepszy.Server
	}
	return opis
}

// sekundy zapisuje przesuniecie w postaci czytelnej dla czlowieka.
func sekundy(wartosc *float64) string {
	if wartosc == nil {
		return "nieznane"
	}
	return strconv.FormatFloat(*wartosc, 'f', 6, 64) + " s"
}

func zakodujPomiary(pomiary []czas.Pomiar) []byte {
	if len(pomiary) == 0 {
		return nil
	}
	zakodowane, err := json.Marshal(pomiary)
	if err != nil {
		return nil
	}
	return zakodowane
}

// odrzuconyCzas zwraca odmowe wraz z pomiarami, ktore ja uzasadniaja.
func odrzuconyCzas(task *agentv1.TaskEnvelope, kod, komunikat string,
	pomiary []czas.Pomiar) *agentv1.TaskResult {
	wynik := rejected(agentv1.TaskResult_STATUS_REJECTED, kod, komunikat)
	wynik.TaskId = task.GetTaskId()
	wynik.TimeResult = &agentv1.TimeResult{Message: komunikat, Probes: zakodujPomiary(pomiary)}
	return wynik
}
