package agent

import (
	"context"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// enrollDomain zleca helperowi sprawdzenie warunkow i dolaczenie do domeny.
// Zmiana dotyka SSSD, Kerberosa i PAM, wiec w calosci nalezy do roota.
func (e *TaskExecutor) enrollDomain(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.DomainEnrollPayload, preflightOnly bool) *agentv1.TaskResult {
	action := opspec.ActionDomainEnroll
	if preflightOnly {
		action = opspec.ActionDomainPreflight
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	// The one-time password comes only from the envelope and is written nowhere
	// on the side of the agent.
	var oneTimePassword string
	if enroll := task.GetDomainEnroll(); enroll != nil {
		oneTimePassword = enroll.GetOneTimePassword()
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		MaxOutputBytes: task.GetLimits().GetMaxOutputBytes(),
		Action: &helperv1.HelperRequest_DomainEnroll{
			DomainEnroll: &helperv1.DomainEnrollRequest{
				Domain:          payload.Domain,
				Realm:           payload.Realm,
				Server:          payload.Server,
				Hostname:        payload.Hostname,
				OneTimePassword: oneTimePassword,
				PreflightOnly:   preflightOnly,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	detail := enrollResultToAgent(response.GetEnrollResult())
	if !response.GetAccepted() {
		// A failed preflight is a negative result and not a breakdown: the
		// conditions are described in the details so that they can be fixed.
		result := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		result.Stderr = response.GetStderr()
		result.Detail = &agentv1.TaskResult_DomainEnroll{DomainEnroll: detail}
		return result
	}

	status := agentv1.TaskResult_STATUS_SUCCEEDED
	message := "the conditions were checked"
	if preflightOnly {
		// An unmet blocking condition is a negative result and not a read
		// failure. A task ending in success would hide the verdict.
		if blocked := blockingChecks(detail); len(blocked) > 0 {
			return &agentv1.TaskResult{
				Status:    agentv1.TaskResult_STATUS_FAILED,
				ExitCode:  1,
				ErrorCode: "preflight_failed",
				Message:   "the host does not meet the conditions: " + strings.Join(blocked, "; "),
				Detail:    &agentv1.TaskResult_DomainEnroll{DomainEnroll: detail},
			}
		}
	}
	if !preflightOnly {
		message = "the host joined the domain"
		// The verification after the join decides the result: running the command
		// alone does not mean a working integration.
		if failed := failedVerifications(detail); len(failed) > 0 {
			status = agentv1.TaskResult_STATUS_FAILED
			message = "the host joined, but the verification did not pass: " + failed[0]
		}
	}

	return &agentv1.TaskResult{
		Status:   status,
		ExitCode: 0,
		Message:  message,
		Detail:   &agentv1.TaskResult_DomainEnroll{DomainEnroll: detail},
	}
}

// blockingChecks wymienia niespelnione warunki blokujace.
func blockingChecks(detail *agentv1.DomainEnrollResult) []string {
	if detail == nil {
		return nil
	}
	var blocked []string
	for _, check := range detail.GetChecks() {
		if check.GetBlocking() && !check.GetPassed() {
			blocked = append(blocked, check.GetName())
		}
	}
	return blocked
}

func failedVerifications(detail *agentv1.DomainEnrollResult) []string {
	if detail == nil {
		return nil
	}
	var failed []string
	for _, check := range detail.GetVerifications() {
		if check.GetBlocking() && !check.GetPassed() {
			failed = append(failed, check.GetName()+": "+check.GetDetail())
		}
	}
	return failed
}

func enrollResultToAgent(result *helperv1.DomainEnrollResult) *agentv1.DomainEnrollResult {
	if result == nil {
		return nil
	}
	return &agentv1.DomainEnrollResult{
		Checks:        enrollChecks(result.GetChecks()),
		Enrolled:      result.GetEnrolled(),
		HostPrincipal: result.GetHostPrincipal(),
		Verifications: enrollChecks(result.GetVerifications()),
	}
}

func enrollChecks(checks []*helperv1.EnrollCheck) []*agentv1.PreflightCheck {
	result := make([]*agentv1.PreflightCheck, 0, len(checks))
	for _, check := range checks {
		result = append(result, &agentv1.PreflightCheck{
			Name:     check.GetName(),
			Passed:   check.Passed,
			Detail:   check.GetDetail(),
			Blocking: check.GetBlocking(),
		})
	}
	return result
}
