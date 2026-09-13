package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/dns"
	"github.com/ultherego/flotestro/internal/modules/network"
	"github.com/ultherego/flotestro/internal/opspec"
)

const (
	resolvConfPath = "/etc/resolv.conf"
	resolvectlPath = "/usr/bin/resolvectl"
	getentPath     = "/usr/bin/getent"
)

// CollectDNS reads the state of the resolver of the host.
//
// The read needs no root: resolv.conf is readable by everyone, and resolvectl
// asks the services over the system bus.
func CollectDNS(ctx context.Context) dns.Snapshot {
	snapshot := dns.Snapshot{ObservedAt: time.Now().UTC(), ResolvConf: resolvConfPath}

	target, _ := os.Readlink(resolvConfPath)
	snapshot.ResolvConfTarget = target
	content, err := os.ReadFile(resolvConfPath)
	if err != nil {
		snapshot.UnavailableReason = "resolv.conf: " + err.Error()
	}
	snapshot.Owner = dns.ResolvConfOwner(target, string(content))

	// resolvectl gives more than the file: the per-link state, DNSSEC and
	// DNS-over-TLS. Without it only the file is left, and it says no more than
	// where the queries go.
	if network.Exists(resolvectlPath) {
		if output, err := commandOutput(ctx, resolvectlPath, "status", "--no-pager"); err == nil {
			fromResolved := dns.ParseResolvectl(output)
			fromResolved.ObservedAt = snapshot.ObservedAt
			fromResolved.ResolvConf = snapshot.ResolvConf
			fromResolved.ResolvConfTarget = snapshot.ResolvConfTarget
			fromResolved.Owner = snapshot.Owner
			snapshot = fromResolved
		}
	}
	if len(snapshot.Servers) == 0 {
		servers, domains := dns.ParseResolvConf(string(content))
		snapshot.Servers = servers
		snapshot.SearchDomains = append(snapshot.SearchDomains, domains...)
		if snapshot.Mode == "" {
			snapshot.Mode = dns.ModeFile
		}
	}

	// The write goes through the connection profile. Without NetworkManager the
	// panel has nothing to change the resolver with in a way that survives the
	// next network event - and it says so directly instead of writing to a file
	// that will disappear anyway.
	if network.Exists(network.NmcliPath) {
		snapshot.Writable = true
		snapshot.WriteAdapter = network.AdapterNetworkManager
	} else {
		snapshot.ReadOnlyReason = "resolver is owned by " + describeOwner(snapshot.Owner) +
			" and this host has no NetworkManager to change it through"
	}
	return snapshot
}

func describeOwner(owner string) string {
	if owner == "" {
		return "an unidentified writer"
	}
	return owner
}

// applyDNS performs the operations of the DNS module.
func (e *TaskExecutor) applyDNS(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.DNSPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "the DNS payload is missing")
	}
	timeout := timeoutOf(task, action)

	if action == opspec.ActionDNSResolveTest {
		// The test needs no root and changes nothing on the host, so it does not
		// go through the helper: every trip through root has to be justified.
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		results := testNames(callCtx, payload.Names)
		encoded, err := json.Marshal(struct {
			Queries []dns.QueryResult `json:"queries"`
		}{results})
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
		}
		return &agentv1.TaskResult{
			TaskId:    task.GetTaskId(),
			Status:    agentv1.TaskResult_STATUS_SUCCEEDED,
			Message:   testSummary(results),
			DnsResult: &agentv1.DnsResult{Queries: encoded},
		}
	}

	operation := helperv1.DnsRequest_OPERATION_APPLY
	if action == opspec.ActionDNSPlan {
		// The plan computes the difference against the profile the host has,
		// without touching it.
		operation = helperv1.DnsRequest_OPERATION_PLAN
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Dns{
			Dns: &helperv1.DnsRequest{
				Operation:       operation,
				Interface:       payload.Interface,
				Servers:         payload.Servers,
				SearchDomains:   payload.SearchDomains,
				IgnoreAutoDns:   payload.IgnoreAutoDNS,
				RollbackSeconds: payload.RollbackSeconds,
				PlanHash:        payload.PlanHash,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetDnsResult()
	details := &agentv1.DnsResult{
		Profiles:         result.GetProfiles(),
		Message:          result.GetMessage(),
		RollbackId:       result.GetRollbackId(),
		RollbackDeadline: result.GetRollbackDeadline(),
		Plan:             result.GetPlan(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.DnsResult = details
		return refused
	}

	// A bad resolver cuts the host off from the directory and from Kerberos, so
	// the change is armed with a rollback just like an address change.
	if result.GetRollbackId() != "" {
		deadline := rollbackDeadline(result.GetRollbackDeadline())
		if !waitForPanel(ctx, panelAddressOf, deadline.Add(-confirmationMargin)) {
			return &agentv1.TaskResult{
				TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
				ErrorCode: RejectNetworkUnreachable,
				Message:   "after the resolver change the host does not reach the panel; rollback at " + result.GetRollbackDeadline(),
				DnsResult: details,
			}
		}
		confirmation, err := e.helper.Call(ctx, &helperv1.HelperRequest{
			TaskId: task.GetTaskId(), TimeoutSeconds: 60,
			Action: &helperv1.HelperRequest_Network{
				Network: &helperv1.NetworkRequest{
					Operation:  helperv1.NetworkRequest_OPERATION_CONFIRM,
					RollbackId: result.GetRollbackId(),
				},
			},
		}, time.Minute)
		if err != nil || !confirmation.GetAccepted() {
			return &agentv1.TaskResult{
				TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
				ErrorCode: RejectHelperFailed, Message: "the rollback was not disarmed",
				DnsResult: details,
			}
		}
		details.Confirmed = true
		details.Message = result.GetMessage() + "; connectivity confirmed, the rollback was disarmed"
		return &agentv1.TaskResult{
			TaskId:    task.GetTaskId(),
			Status:    agentv1.TaskResult_STATUS_SUCCEEDED,
			Message:   details.Message,
			DnsResult: details,
		}
	}

	return &agentv1.TaskResult{
		TaskId:    task.GetTaskId(),
		Status:    agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:   result.GetMessage(),
		DnsResult: details,
	}
}

// testNames resolves the names from the host.
func testNames(ctx context.Context, names []string) []dns.QueryResult {
	results := make([]dns.QueryResult, 0, len(names))
	for _, name := range names {
		results = append(results, testName(ctx, name))
	}
	return results
}

// testName asks one question and describes the answer.
//
// The result is named, because the duration is filled in from a defer: without
// that the measurement would be lost at every early return and every query
// would seem to take zero milliseconds.
func testName(ctx context.Context, name string) (result dns.QueryResult) {
	result = dns.QueryResult{Name: name}
	if !dns.ValidTestName(name) {
		result.Error = "the name was rejected by the agent"
		return result
	}
	start := time.Now()
	defer func() { result.TookMillis = time.Since(start).Milliseconds() }()

	if network.Exists(resolvectlPath) {
		// The legend carries the protocol and the source of the answer, so it is
		// not switched off: the operator asks not only "which address" but also
		// "who told me that".
		output, errorMessage, err := outputWithError(ctx, resolvectlPath, "query", name)
		if err == nil {
			result.Addresses, result.Server = addressesFromResolvectl(output)
			if len(result.Addresses) == 0 {
				// An empty answer without a reason would be silence: a name
				// without an address and a name that did not resolve are two
				// different things.
				result.Error = "the resolver returned no address"
			}
			return result
		}
		// The message of the resolver says what happened ("Name ... not found",
		// "No appropriate name servers"). The exit code says nothing.
		result.Error = firstMeaningfulLine(errorMessage + "\n" + output)
		if result.Error == "" {
			result.Error = "the name did not resolve"
		}
		return result
	}

	// A host without resolvectl is asked the way every other program asks.
	output, _, err := outputWithError(ctx, getentPath, "ahosts", name)
	if err != nil {
		result.Error = "the name did not resolve"
		return result
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && !seen[fields[0]] {
			seen[fields[0]] = true
			result.Addresses = append(result.Addresses, fields[0])
		}
	}
	return result
}

// addressesFromResolvectl reads the answer of "resolvectl query".
//
// An answer line has the form "name: address -- link: enp0s8", and the legend
// lines start with two dashes and say where the answer came from. The source is
// taken from the legend, because it is what answers the question "who told me
// that" - and in a DNS diagnosis that is the whole question.
func addressesFromResolvectl(output string) (addresses []string, server string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "--") {
			description := strings.TrimSpace(strings.TrimPrefix(line, "--"))
			switch {
			case strings.HasPrefix(description, "Data from:"):
				server = strings.TrimSpace(strings.TrimPrefix(description, "Data from:"))
			case server == "" && strings.HasPrefix(description, "Information acquired via protocol "):
				description = strings.TrimPrefix(description, "Information acquired via protocol ")
				protocol, _, _ := strings.Cut(description, " ")
				server = protocol
			}
			continue
		}
		_, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		// The tail of the line after "--" describes the link, not the address.
		value, _, _ = strings.Cut(value, "--")
		fields := strings.Fields(value)
		if len(fields) > 0 {
			addresses = append(addresses, fields[0])
		}
	}
	return addresses, server
}

// firstMeaningfulLine returns the first non-empty line of the message.
func firstMeaningfulLine(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "--") {
			return line
		}
	}
	return ""
}

func testSummary(results []dns.QueryResult) string {
	resolved := 0
	for _, result := range results {
		if len(result.Addresses) > 0 {
			resolved++
		}
	}
	return strconv.Itoa(resolved) + " of " + strconv.Itoa(len(results)) + " names resolved"
}

func commandOutput(ctx context.Context, path string, arguments ...string) (string, error) {
	output, _, err := outputWithError(ctx, path, arguments...)
	return output, err
}

// outputWithError returns both streams. The error message is the content of the
// answer here and not noise: it is what says why the name did not resolve.
func outputWithError(ctx context.Context, path string, arguments ...string) (string, string, error) {
	callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(callCtx, path, arguments...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C"}
	var errorStream bytes.Buffer
	cmd.Stderr = &errorStream
	output, err := cmd.Output()
	return string(output), errorStream.String(), err
}
