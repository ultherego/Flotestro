package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// AgentUnit is the service of the agent, the one the wipe disables.
const AgentUnit = "flotestro-agent.service"

// agentStateDir is where the agent keeps its identity and its journal.
const agentStateDir = "/var/lib/flotestro-agent"

// The entries the wipe removes from the state directory.
var wipedEntries = []string{
	"identity",
	"tasks",
	"agent.key",
	"agent.pem",
	"ca.pem",
}

// stopDelay is how long after the reply the agent unit is stopped.
const stopDelay = 5 * time.Second

// applyFinalWipe ends this host's membership in the fleet.
func (s *Server) applyFinalWipe(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.FinalWipeRequest) *helperv1.HelperResponse {
	release, busy := s.hold(GuardHost, request)
	if busy != nil {
		return busy
	}
	defer release()

	stateDir := s.stateDir()
	result := &helperv1.FinalWipeResult{Removed: []string{}}
	for _, entry := range wipedEntries {
		path := filepath.Join(stateDir, entry)
		removed, err := removeEntry(path)
		if err != nil {
			s.log.Error("the final wipe stopped at a path it could not remove",
				"task_id", request.GetTaskId(), "path", path, "err", err)
			response := reject(ErrorExecFailed, "the identity was not removed: "+err.Error())
			response.FinalWipeResult = result
			return response
		}
		if removed {
			result.Removed = append(result.Removed, path)
		}
	}

	actionCtx, cancel := deadline(ctx, request, time.Minute, 5*time.Minute)
	defer cancel()
	if _, stderr, err := s.tool()(actionCtx, 30*time.Second, "systemctl", "disable", AgentUnit); err != nil {
		s.log.Error("the agent service was not disabled after the wipe",
			"task_id", request.GetTaskId(), "err", err, "stderr", firstLineOf(stderr))
		response := reject(ErrorExecFailed, "the identity was removed, but the agent service was not disabled: "+
			firstLineOf(stderr))
		response.FinalWipeResult = result
		return response
	}
	result.ServiceDisabled = true

	// The stop goes through a transient timer: a stop issued now would take
	// the helper's peer down before the reply reaches it.
	if _, stderr, err := s.tool()(actionCtx, 30*time.Second, "systemd-run",
		"--collect", "--quiet", "--no-block",
		"--unit=flotestro-agent-retire",
		"--description=Flotestro: stop the agent after decommission",
		"--on-active="+fmt.Sprint(int(stopDelay.Seconds())),
		"--", "systemctl", "stop", AgentUnit); err != nil {
		// The identity is gone and the service is disabled: the host is out of the
		// fleet whatever happens to the stop.
		s.log.Warn("the stop of the agent service was not scheduled",
			"task_id", request.GetTaskId(), "err", err, "stderr", firstLineOf(stderr))
	} else {
		result.StopScheduled = true
	}

	s.log.Warn("the host left the fleet: the identity was wiped and the agent service disabled",
		"task_id", request.GetTaskId(), "reason", strings.TrimSpace(action.GetReason()),
		"removed", result.Removed, "stop_scheduled", result.StopScheduled)
	return &helperv1.HelperResponse{Accepted: true, FinalWipeResult: result}
}

// stateDir returns the agent's state directory: the injected one in tests,
// the fixed one otherwise.
func (s *Server) stateDir() string {
	if s.agentStateDir != "" {
		return s.agentStateDir
	}
	return agentStateDir
}

// removeEntry removes a file or a directory tree and says whether there was
// anything to remove.
func removeEntry(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return true, os.Remove(path)
	}
	return true, os.RemoveAll(path)
}
