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

// readJournal reads the journal locally and returns a bounded result. The host
// does no work when nobody is looking at the logs: the read happens only on
// request, without a permanent shipper.
func (e *TaskExecutor) readJournal(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.JournalPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "the read payload is missing")
	}

	// The arguments are built from typed fields, never from a concatenated
	// string.
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

// clampBytes trims the result to the limit and signals the cut. The result of a
// task must not grow to an arbitrary size.
func clampBytes(data []byte, limit int) ([]byte, bool) {
	if len(data) <= limit {
		return data, false
	}
	// The cut is made from the start: in a journal read the freshest entries are
	// at the end and those are the ones needed.
	return data[len(data)-limit:], true
}

// readLogFile reads a log file through the helper. The agent has no access to
// the files of root and must not have one - the allowlist is the property of
// the host, and deciding on it belongs to the process that has something to
// read with.
func (e *TaskExecutor) readLogFile(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.LogFilePayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the file read payload is missing")
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
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		return refused
	}
	result := response.GetLogFileResult()
	return &agentv1.TaskResult{
		TaskId: task.GetTaskId(),
		Status: agentv1.TaskResult_STATUS_SUCCEEDED,
		LogFileResult: &agentv1.LogFileResult{
			Path:      result.GetPath(),
			Lines:     result.GetLines(),
			Truncated: result.GetTruncated(),
			SizeBytes: result.GetSizeBytes(),
			Allowlist: result.GetAllowlist(),
		},
	}
}
