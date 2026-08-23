package agent

import (
	"context"
	"strconv"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
	"time"
)

const journalctlPath = "/usr/bin/journalctl"

// readJournal czyta dziennik lokalnie i zwraca ograniczony wynik.
// Host nie wykonuje zadnej pracy, gdy nikt nie oglada logow: czytamy wylacznie
// na zadanie, bez stalego shippera.
func (e *TaskExecutor) readJournal(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.JournalPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "brak payloadu odczytu")
	}

	// Argumenty budujemy z pol typowanych, nigdy ze sklejonego ciagu.
	args := []string{"--no-pager", "--output=short-iso", "--lines=" + strconv.FormatUint(uint64(payload.Lines), 10)}
	if payload.Unit != "" {
		args = append(args, "--unit="+payload.Unit)
	}
	if payload.MaxPriority != nil {
		args = append(args, "--priority="+strconv.FormatUint(uint64(*payload.MaxPriority), 10))
	}
	if payload.Since != "" {
		args = append(args, "--since="+payload.Since)
	}

	timeout := timeoutOf(task, opspec.ActionReadJournal)
	result := runCommand(ctx, timeout, journalctlPath, args...)
	if !result.Ran {
		status := agentv1.TaskResult_STATUS_FAILED
		if ctx.Err() != nil {
			status = agentv1.TaskResult_STATUS_TIMED_OUT
		}
		return rejected(status, "journal_unavailable", result.Reason())
	}
	if result.ExitCode != 0 {
		return rejected(agentv1.TaskResult_STATUS_FAILED, "journal_failed", result.Reason())
	}

	limit := int(task.GetLimits().GetMaxOutputBytes())
	if limit <= 0 {
		limit = 256 << 10
	}
	stdout, truncated := clampBytes([]byte(result.Stdout), limit)

	return &agentv1.TaskResult{
		Status:          agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode:        0,
		Stdout:          stdout,
		OutputTruncated: truncated,
	}
}

// clampBytes przycina wynik do limitu i sygnalizuje obciecie. Wynik zadania
// nie moze urosnac do dowolnego rozmiaru.
func clampBytes(data []byte, limit int) ([]byte, bool) {
	if len(data) <= limit {
		return data, false
	}
	// Przycinamy od poczatku: przy odczycie dziennika najswiezsze wpisy sa
	// na koncu i to one sa potrzebne.
	return data[len(data)-limit:], true
}

// readLogFile czyta plik logu przez helpera. Agent nie ma dostepu do plikow
// roota i nie moze go miec - allowlista jest wlasnoscia hosta, a jej
// rozstrzyganie nalezy do procesu, ktory ma czym czytac.
func (e *TaskExecutor) readLogFile(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.LogFilePayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"brak payloadu odczytu pliku")
	}
	timeout := timeoutOf(task, opspec.ActionReadLogFile)
	callCtx, cancel := context.WithTimeout(ctx, timeout+15*time.Second)
	defer cancel()

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_LogFile{
			LogFile: &helperv1.LogFileRequest{
				Path:  payload.Path,
				Lines: payload.Lines,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	if !response.GetAccepted() {
		wynik := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		wynik.TaskId = task.GetTaskId()
		return wynik
	}
	wynik := response.GetLogFileResult()
	return &agentv1.TaskResult{
		TaskId: task.GetTaskId(),
		Status: agentv1.TaskResult_STATUS_SUCCEEDED,
		LogFileResult: &agentv1.LogFileResult{
			Path:      wynik.GetPath(),
			Lines:     wynik.GetLines(),
			Truncated: wynik.GetTruncated(),
			SizeBytes: wynik.GetSizeBytes(),
			Allowlist: wynik.GetAllowlist(),
		},
	}
}
