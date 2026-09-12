package helper

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/docker/compose"
)

// dockerCLI is the only entry point into compose. The arguments are assembled
// in code, never through a shell: there is no "run this command" operation.
const dockerCLI = "/usr/bin/docker"

// composeDirectory holds the manifests during an operation. It belongs to root
// and is shared with nothing else.
func (s *Server) composeDirectory() string {
	directory := os.Getenv("STATE_DIRECTORY")
	if directory == "" {
		directory = "/var/lib/flotestro-helper"
	}
	return filepath.Join(directory, "compose")
}

// composeRunner runs compose with a fixed set of arguments.
func composeRunner(ctx context.Context) compose.Runner {
	return func(callCtx context.Context, args ...string) (string, string, error) {
		full := append([]string{"compose"}, args...)
		cmd := exec.CommandContext(callCtx, dockerCLI, full...)
		cmd.Env = []string{
			"LC_ALL=C", "LANG=C",
			"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME=/var/lib/flotestro-helper",
		}
		stdoutPipe := &buffer{limit: 4 << 20}
		stderrPipe := &buffer{limit: 1 << 20}
		cmd.Stdout = stdoutPipe
		cmd.Stderr = stderrPipe
		err := cmd.Run()
		return string(stdoutPipe.Bytes()), string(stderrPipe.Bytes()), err
	}
}

// applyCompose handles the plan and the deployment of a project.
func (s *Server) applyCompose(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.ComposeRequest) *helperv1.HelperResponse {
	if info, err := os.Stat(dockerCLI); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return reject(ErrorUnsupported, "the host has no Docker client")
	}

	// Compose projects share the same resource with the other container
	// operations: a deployment and a restart of the same project at once give
	// an unpredictable result.
	if !s.containerMutex.TryLock() {
		return reject(ErrorLocked, "another container operation is in flight")
	}
	defer s.containerMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > time.Hour {
		timeout = 15 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	planner := compose.Planner{Runner: composeRunner(actionCtx), Dir: s.composeDirectory()}

	switch action.GetOperation() {
	case helperv1.ComposeRequest_OPERATION_PLAN:
		plan, err := planner.Plan(actionCtx, action.GetProject(), action.GetManifest())
		if err != nil {
			return reject(ErrorExecFailed, err.Error())
		}
		return composeResponse(plan)

	case helperv1.ComposeRequest_OPERATION_DEPLOY:
		executor := compose.Executor{Planner: planner}
		result, err := executor.Deploy(actionCtx, action.GetProject(),
			action.GetManifest(), action.GetPlanDigest())
		if err != nil {
			// The partial result goes into the answer on failure as well:
			// without it there is no telling what managed to take hold.
			response := reject(ErrorExecFailed, err.Error())
			if encoded, marshalErr := json.Marshal(result); marshalErr == nil {
				response.ComposeResult = &helperv1.ComposeResult{Payload: encoded}
			}
			return response
		}
		return composeResponse(result)
	}
	return reject(ErrorUnknownAction, "unknown Compose project operation")
}

func composeResponse(content any) *helperv1.HelperResponse {
	encoded, err := json.Marshal(content)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted:      true,
		ComposeResult: &helperv1.ComposeResult{Payload: encoded},
	}
}

// buffer collects the output up to a limit. Compose can print a lot, and the
// helper runs as root and cannot afford an unbounded allocation.
type buffer struct {
	data  []byte
	limit int
}

func (b *buffer) Write(p []byte) (int, error) {
	if len(b.data) < b.limit {
		allowed := b.limit - len(b.data)
		if allowed > len(p) {
			allowed = len(p)
		}
		b.data = append(b.data, p[:allowed]...)
	}
	return len(p), nil
}

func (b *buffer) Bytes() []byte { return b.data }
