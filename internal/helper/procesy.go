package helper

import (
	"context"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/processes"
)

// signalProcess wysyla sygnal do procesu.
//
// Ograniczenia sa sprawdzane tutaj, choc panel juz je sprawdzil: helper dziala
// jako root i nie moze ufac tresci wiadomosci. Czas startu wiaze zadanie
// z konkretnym procesem, bo jadro uzywa numerow PID ponownie.
func (s *Server) signalProcess(_ context.Context, _ *helperv1.HelperRequest,
	action *helperv1.ProcessSignalRequest) *helperv1.HelperResponse {
	err := processes.Wyslij("/proc", action.GetPid(), action.GetExpectedStartTicks(),
		action.GetSignal(), processes.Chronione{Wlasne: processes.WlasnePID()})
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		ProcessSignalResult: &helperv1.ProcessSignalResult{
			Pid:    action.GetPid(),
			Signal: action.GetSignal(),
		},
	}
}
