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

// agentStateDir is where the agent keeps its identity and its journal. The
// helper knows the path itself rather than taking it from the request: a
// root process that removes whatever directory the peer names is a root
// process that removes whatever directory the peer names.
const agentStateDir = "/var/lib/flotestro-agent"

// The entries the wipe removes from the state directory. The identity store
// (the generations directory the identitystore package keeps under
// "identity") and the idempotency journal, and the flat identity files of a
// host set up before the store existed. Nothing else: the state file the
// diagnostic tool reads stays, and so does the working directory of the
// tools. The names are spelled here rather than imported: the helper does
// not link the agent's key handling for the sake of one string.
var wipedEntries = []string{
	"identity",
	"tasks",
	"agent.key",
	"agent.pem",
	"ca.pem",
}

// stopDelay is how long after the reply the agent unit is stopped. The
// agent ends on its own on hearing the answer; the stop is for an agent that
// did not, and for a unit whose restart policy would bring it back.
const stopDelay = 5 * time.Second

// applyFinalWipe ends this host's membership in the fleet.
//
// Three things, in this order: the identity and the journal are removed, so
// the host has nothing to introduce itself with; the agent service is
// disabled, so a reboot does not start it; the stop of the service is
// scheduled for after the reply, so the agent hears the answer. The agent
// asked for it on the panel's word - the certificates are revoked by now -
// and the helper does what it is told, but says exactly what it did: the
// removed paths are in the answer and in its own log, and a step that
// failed fails the whole request rather than being passed over.
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
		// The identity is gone and the service is disabled: the host is out
		// of the fleet whatever happens to the stop. It is reported rather
		// than failed - the agent ends on its own on hearing the answer.
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
// anything to remove. A symbolic link is removed as a link, never followed:
// the helper runs as root and does not remove through links.
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
