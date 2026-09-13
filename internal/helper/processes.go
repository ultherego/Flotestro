package helper

import (
	"context"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/processes"
)

// signalProcess sends a signal to a process.
//
// The limits are checked here even though the panel already checked them: the
// helper runs as root and cannot trust the content of the message. The start
// time binds the request to one concrete process, because the kernel reuses
// PID numbers.
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
