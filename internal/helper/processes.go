package helper

import (
	"context"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/processes"
)

// signalProcess sends a signal to a process.
func (s *Server) signalProcess(_ context.Context, _ *helperv1.HelperRequest,
	action *helperv1.ProcessSignalRequest) *helperv1.HelperResponse {
	err := processes.Send("/proc", action.GetPid(), action.GetExpectedStartTicks(),
		action.GetSignal(), processes.Protected{Own: processes.OwnPIDs()})
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
