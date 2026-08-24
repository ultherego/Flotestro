package helper

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/power"
	"github.com/ultherego/flotestro/internal/systemd"
)

// applyShutdown wylacza hosta po zadanym opoznieniu.
//
// Opoznienie jest konieczne z tego samego powodu co przy restarcie: bez niego
// host znika, zanim agent odesle wynik, i operacja wygladalaby na zerwana
// zamiast wykonana. Roznica wobec restartu jest jedna, ale zasadnicza - po tej
// operacji nikt nie zobaczy powrotu hosta.
func (s *Server) applyShutdown(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.ShutdownRequest) *helperv1.HelperResponse {
	if err := power.WalidujPowodWylaczenia(action.GetReason()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := power.WalidujOpoznienie(action.GetDelaySeconds()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	tryb := action.GetMode()
	switch tryb {
	case "":
		tryb = power.TrybWylaczyc
	case power.TrybWylaczyc, power.TrybZatrzymac:
	default:
		return reject(ErrorMalformed, "nieobslugiwany tryb wylaczenia "+tryb)
	}

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 2 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Blokada logind jest odpowiedzia hosta na pytanie "czy teraz mozna":
	// aktualizacja w toku albo sesja z otwarta praca. Panel jej nie omija
	// bez decyzji operatora.
	blokady := blokadyWylaczenia(actionCtx)
	if len(blokady) > 0 && !action.GetIgnoreInhibitors() {
		odmowa := reject(ErrorPreconditionFailed,
			"wylaczenie wstrzymane przez blokady: "+opisBlokad(blokady))
		odmowa.PowerResult = &helperv1.PowerResult{
			Message:    odmowa.Message,
			Inhibitors: zakodujBlokady(blokady),
		}
		return odmowa
	}

	delay := action.GetDelaySeconds()
	if delay == 0 {
		delay = 15
	}
	stdout, stderr, exitCode, err := systemd.SchedulePower(actionCtx,
		time.Duration(delay)*time.Second, "Flotestro: "+action.GetReason(), tryb)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	if exitCode != 0 {
		odpowiedz := reject(ErrorExecFailed, strings.TrimSpace(stderr))
		odpowiedz.ExitCode = int32(exitCode)
		return odpowiedz
	}

	termin := time.Now().UTC().Add(time.Duration(delay) * time.Second)
	komunikat := "wylaczenie zaplanowane na " + termin.Format(time.RFC3339)
	if len(blokady) > 0 {
		komunikat += "; blokady pominiete decyzja operatora: " + opisBlokad(blokady)
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		Stdout:   []byte(stdout),
		PowerResult: &helperv1.PowerResult{
			Message:     komunikat,
			Inhibitors:  zakodujBlokady(blokady),
			ScheduledAt: termin.Format(time.RFC3339),
		},
	}
}

// blokadyWylaczenia zwraca blokady, ktore nie pozwalaja na wylaczenie.
//
// Opoznienie ("delay") nie jest przeszkoda: logind sam je odczeka. Blokada
// ("block") jest, i to ona ma zatrzymac operacje.
func blokadyWylaczenia(ctx context.Context) []power.Blokada {
	if !exists(power.SciezkaInhibit) {
		return nil
	}
	wyjscie, _, _ := wyjscieZOstrzezeniami(ctx, power.SciezkaInhibit, "--list", "--no-pager")
	wszystkie, znane := power.ParsujInhibitory(wyjscie)
	if !znane {
		return nil
	}
	var blokujace []power.Blokada
	for _, blokada := range wszystkie {
		if blokada.Blokuje() && (blokada.What == "" || strings.Contains(blokada.What, "shutdown")) {
			blokujace = append(blokujace, blokada)
		}
	}
	return blokujace
}

func opisBlokad(blokady []power.Blokada) string {
	opisy := make([]string, 0, len(blokady))
	for _, blokada := range blokady {
		opis := blokada.Who
		if blokada.Why != "" {
			opis += " (" + blokada.Why + ")"
		}
		opisy = append(opisy, opis)
	}
	return strings.Join(opisy, ", ")
}

func zakodujBlokady(blokady []power.Blokada) []byte {
	if len(blokady) == 0 {
		return nil
	}
	zakodowane, err := json.Marshal(blokady)
	if err != nil {
		return nil
	}
	return zakodowane
}
