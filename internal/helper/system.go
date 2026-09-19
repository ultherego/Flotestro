package helper

import (
	"context"
	"encoding/json"
	"os"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/sudoers"
	"github.com/ultherego/flotestro/internal/modules/system"
)

// readSystem reads the facts of the system module that belong to root: the DMI
// serial numbers and the UUID, and the sudo policy files.
func (s *Server) readSystem(_ context.Context, request *helperv1.HelperRequest,
	action *helperv1.SystemRequest) *helperv1.HelperResponse {
	facts := action.GetFacts()
	if len(facts) == 0 {
		return reject(ErrorMalformed, "the order names no fact")
	}
	for _, fact := range facts {
		switch fact {
		case helperv1.SystemRequest_FACT_DMI_IDENTITY, helperv1.SystemRequest_FACT_SUDOERS:
		default:
			return reject(ErrorMalformed, "unknown fact "+fact.String())
		}
	}
	// The reads are file reads of sysfs and /etc: they start no tool and take no
	// lock, so there is nothing for the deadline of the order to cut short.
	root := os.DirFS("/")
	result := &helperv1.SystemResult{}
	for _, fact := range facts {
		switch fact {
		case helperv1.SystemRequest_FACT_DMI_IDENTITY:
			encoded, err := json.Marshal(system.ReadSupplement(root))
			if err != nil {
				return reject(ErrorExecFailed, err.Error())
			}
			result.Dmi = encoded
		case helperv1.SystemRequest_FACT_SUDOERS:
			snapshot := sudoers.ParseSystem(root, time.Now())
			encoded, err := json.Marshal(snapshot)
			if err != nil {
				return reject(ErrorExecFailed, err.Error())
			}
			result.Sudoers = encoded
			s.log.Info("the sudo policy of the host was read",
				"task_id", request.GetTaskId(), "rules", len(snapshot.Rules),
				"files", len(snapshot.Files), "problems", len(snapshot.Problems),
				"unavailable", snapshot.UnavailableReason)
		}
	}
	return &helperv1.HelperResponse{Accepted: true, SystemResult: result}
}
