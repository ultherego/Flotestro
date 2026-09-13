package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	hosttime "github.com/ultherego/flotestro/internal/modules/time"
	"github.com/ultherego/flotestro/internal/opspec"
)

// queryTimeout limits a single query to a time server. A server that does not
// answer within a few seconds is useless to the host regardless of whether it
// answers within thirty.
const queryTimeout = 5 * time.Second

// CollectTime reads the time state of the host.
//
// The read needs no root: timedatectl asks the services over the system bus,
// chronyc talks to the daemon over the loopback, and the time configuration
// files are readable by everyone.
func CollectTime(ctx context.Context) hosttime.Snapshot {
	return hosttime.Collect(ctx, commandOutput)
}

// applyTime performs the operations of the time module.
func (e *TaskExecutor) applyTime(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.TimePayload) *agentv1.TaskResult {
	if payload == nil {
		payload = &opspec.TimePayload{}
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if action == opspec.ActionTimeSyncTest {
		return e.testTime(callCtx, task, payload)
	}

	// The servers are checked before the host gives up a working source. The
	// test is here and not in the helper, because it needs no root - the helper
	// checks what concerns the safety of the write, that is the shape of the
	// entries themselves.
	var probes []hosttime.Probe
	if action == opspec.ActionTimeConfigApply {
		probes = hosttime.QueryMany(callCtx, payload.Servers, queryTimeout)
		if hosttime.Reachable(probes) == 0 {
			return timeRefusal(task, RejectPrecondition,
				"none of the given time servers answered: "+describeProbes(probes), probes)
		}
		best := hosttime.BestProbe(probes)
		if hosttime.Steps(best) && !payload.AllowStep {
			return timeRefusal(task, RejectPrecondition, fmt.Sprintf(
				"the change will move the clock by %s against %s; a time step revokes "+
					"the validity of tokens and certificates, so it needs explicit consent",
				seconds(best.OffsetSeconds), best.Server), probes)
		}
	}

	operation := helperv1.TimeRequest_OPERATION_CONFIG_APPLY
	switch action {
	case opspec.ActionTimezoneSet:
		operation = helperv1.TimeRequest_OPERATION_TIMEZONE_SET
	case opspec.ActionTimePlan:
		// The plan computes the difference against the panel file without
		// touching the host; the reachability of the servers is checked only by
		// the change itself.
		operation = helperv1.TimeRequest_OPERATION_PLAN
	}
	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Time{
			Time: &helperv1.TimeRequest{
				Operation:    operation,
				Servers:      payload.Servers,
				Timezone:     payload.Timezone,
				AllowStep:    payload.AllowStep,
				EnableDropin: payload.EnableDropIn,
				PlanHash:     payload.PlanHash,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetTimeResult()
	details := &agentv1.TimeResult{
		Snapshot: result.GetSnapshot(),
		Message:  result.GetMessage(),
		Probes:   encodeProbes(probes),
		Plan:     result.GetPlan(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.TimeResult = details
		return refused
	}
	return &agentv1.TaskResult{
		TaskId:     task.GetTaskId(),
		Status:     agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:    result.GetMessage(),
		TimeResult: details,
	}
}

// testTime measures the offset against the given servers.
//
// Without any given, the panel asks the servers the host uses: that answers the
// question "is my clock right" and not only "is the daemon running".
func (e *TaskExecutor) testTime(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.TimePayload) *agentv1.TaskResult {
	snapshot := CollectTime(ctx)
	servers := payload.Probe
	if len(servers) == 0 {
		servers = serversFromConfiguration(snapshot)
	}
	if len(servers) == 0 {
		return timeRefusal(task, RejectPrecondition,
			"this host has no time server configured", nil)
	}

	probes := hosttime.QueryMany(ctx, servers, queryTimeout)
	snapshot.Probes = probes
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	return &agentv1.TaskResult{
		TaskId:  task.GetTaskId(),
		Status:  agentv1.TaskResult_STATUS_SUCCEEDED,
		Message: describeProbes(probes),
		TimeResult: &agentv1.TimeResult{
			Snapshot: encoded,
			Message:  describeProbes(probes),
			Probes:   encodeProbes(probes),
		},
	}
}

// serversFromConfiguration picks the addresses to query.
//
// A pool expands into many addresses and is not a server itself, so the sources
// the daemon really picked are asked; only when there is none do the
// configuration entries come into play.
func serversFromConfiguration(snapshot hosttime.Snapshot) []string {
	var servers []string
	seen := map[string]bool{}
	for _, source := range snapshot.Sources {
		if source.Address != "" && !seen[source.Address] {
			seen[source.Address] = true
			servers = append(servers, source.Address)
		}
	}
	if len(servers) > 0 {
		return limitList(servers)
	}
	for _, server := range snapshot.Configured {
		if server.Pool || server.Address == "" || seen[server.Address] {
			continue
		}
		seen[server.Address] = true
		servers = append(servers, server.Address)
	}
	if len(servers) == 0 {
		for _, server := range snapshot.Configured {
			if server.Address != "" {
				servers = append(servers, server.Address)
			}
		}
	}
	return limitList(servers)
}

func limitList(servers []string) []string {
	if len(servers) > hosttime.ServerLimit {
		return servers[:hosttime.ServerLimit]
	}
	return servers
}

// describeProbes sums the result of the test up in one sentence.
func describeProbes(probes []hosttime.Probe) string {
	if len(probes) == 0 {
		return "no question was asked"
	}
	reachable := hosttime.Reachable(probes)
	description := strconv.Itoa(reachable) + " of " + strconv.Itoa(len(probes)) + " servers answered"
	if best := hosttime.BestProbe(probes); best != nil {
		description += "; offset " + seconds(best.OffsetSeconds) + " against " + best.Server
	}
	return description
}

// seconds writes the offset in a form readable by a human.
func seconds(value *float64) string {
	if value == nil {
		return "unknown"
	}
	return strconv.FormatFloat(*value, 'f', 6, 64) + " s"
}

func encodeProbes(probes []hosttime.Probe) []byte {
	if len(probes) == 0 {
		return nil
	}
	encoded, err := json.Marshal(probes)
	if err != nil {
		return nil
	}
	return encoded
}

// timeRefusal returns a refusal together with the probes that justify it.
func timeRefusal(task *agentv1.TaskEnvelope, code, message string,
	probes []hosttime.Probe) *agentv1.TaskResult {
	result := rejected(agentv1.TaskResult_STATUS_REJECTED, code, message)
	result.TaskId = task.GetTaskId()
	result.TimeResult = &agentv1.TimeResult{Message: message, Probes: encodeProbes(probes)}
	return result
}
