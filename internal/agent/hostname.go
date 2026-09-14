package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// RejectHostnameConflict marks a rename refused because the new name already
// points somewhere else in DNS. The host reports the finding and changes
// nothing: a name that resolves to another machine is somebody else's name
// until the record says otherwise.
const RejectHostnameConflict = "hostname_conflict"

// Names of the rename preflight checks. They are part of the result, so the
// panel can show every check by name.
const (
	CheckHostnameDNS         = "dns"
	CheckHostnameCertificate = "agent_certificate"
	CheckHostnameCurrent     = "current_name"
)

// dnsLookupTimeout bounds the preflight query. A resolver that does not
// answer in this time is reported as unknown, not waited for.
const dnsLookupTimeout = 10 * time.Second

// setHostname renames the host through the helper, after a preflight the
// agent runs itself.
//
// The preflight answers two questions the operator cannot answer from the
// panel: whether the new name resolves in DNS to something else than this
// host, and whether the agent's own certificate is bound to the name. The
// first refuses the rename; the second is information - the panel knows
// the host by identifier, so the certificate survives. Both go into the
// result, whether the rename happened or not.
func (e *TaskExecutor) setHostname(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.HostnamePayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the hostname payload is missing")
	}
	timeout := timeoutOf(task, opspec.ActionSystemHostnameSet)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	current, _ := os.Hostname()
	checks := hostnamePreflight(callCtx, payload.Hostname, current, e.hostID)
	result := &agentv1.HostnameResult{Previous: current, Current: payload.Hostname, Checks: checks}
	for _, check := range checks {
		if check.GetBlocking() && check.Passed != nil && !check.GetPassed() {
			refused := rejected(agentv1.TaskResult_STATUS_REJECTED, RejectHostnameConflict,
				check.GetName()+": "+check.GetDetail())
			refused.TaskId = task.GetTaskId()
			refused.HostnameResult = result
			return refused
		}
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Hostname{
			Hostname: &helperv1.HostnameRequest{Hostname: payload.Hostname, Pretty: payload.Pretty},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	if renamed := response.GetHostnameResult(); renamed != nil {
		result.Previous = renamed.GetPrevious()
		result.Current = renamed.GetCurrent()
		result.Changed = renamed.GetChanged()
		result.HostsFileUpdated = renamed.GetHostsFileUpdated()
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_FAILED, response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.HostnameResult = result
		return refused
	}

	message := "the host was renamed to " + result.Current
	if !result.Changed {
		message = "the host already had the name " + result.Current
	}
	// The panel learns the new name from the inventory, not from the result:
	// the name is a fact of the host, and the system module carries it. A
	// fresh picture goes out right away rather than at the next cycle, so
	// the host is not listed under a name it no longer answers to.
	if result.Changed && e.inventoryRefresh != nil {
		e.refresh(callCtx, []string{ModuleSystem})
	}
	return &agentv1.TaskResult{
		TaskId:         task.GetTaskId(),
		Status:         agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:        message,
		HostnameResult: result,
	}
}

// hostnamePreflight runs the checks of a rename. Every check reports what
// it found; a check that could not be made says so instead of passing.
func hostnamePreflight(ctx context.Context, requested, current, hostID string) []*agentv1.PreflightCheck {
	checks := []*agentv1.PreflightCheck{
		{
			Name: CheckHostnameCurrent, Passed: boolPtr(true), Blocking: false,
			Detail: fmt.Sprintf("the host currently answers to %q", current),
		},
	}
	checks = append(checks, dnsCheck(ctx, requested, ownAddresses()))
	checks = append(checks, certificateCheck(hostID, current))
	return checks
}

// dnsCheck asks the resolver about the new name and compares the answer
// with the addresses this host has.
//
// A name that does not resolve passes: the record is not there yet, and
// creating it is the operator's next step. A name that resolves to one of
// this host's addresses passes: the record is already right. A name that
// resolves elsewhere fails and blocks the rename. A resolver that does not
// answer leaves the check unknown - the agent does not guess.
func dnsCheck(ctx context.Context, name string, own map[string]bool) *agentv1.PreflightCheck {
	check := &agentv1.PreflightCheck{Name: CheckHostnameDNS, Blocking: true}
	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(lookupCtx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			check.Passed = boolPtr(true)
			check.Detail = fmt.Sprintf("%s does not resolve in DNS yet; the record is the next step", name)
			return check
		}
		check.Detail = fmt.Sprintf("the resolver did not answer for %s: %s", name, err)
		return check
	}
	var foreign, matching []string
	for _, address := range addresses {
		text := address.IP.String()
		if own[text] {
			matching = append(matching, text)
		} else {
			foreign = append(foreign, text)
		}
	}
	if len(matching) > 0 {
		check.Passed = boolPtr(true)
		check.Detail = fmt.Sprintf("%s resolves to this host (%s)", name, strings.Join(matching, ", "))
		if len(foreign) > 0 {
			check.Detail += "; it also names " + strings.Join(foreign, ", ")
		}
		return check
	}
	check.Passed = boolPtr(false)
	check.Detail = fmt.Sprintf("%s resolves to %s, which is not an address of this host",
		name, strings.Join(foreign, ", "))
	return check
}

// certificateCheck says whether the rename touches the agent's identity
// towards the panel. The panel issues the certificate for the host
// identifier, not for the name - so as long as the identifier is what the
// agent presents, no re-enrollment is needed.
func certificateCheck(hostID, current string) *agentv1.PreflightCheck {
	check := &agentv1.PreflightCheck{Name: CheckHostnameCertificate, Blocking: false}
	switch {
	case hostID == "":
		check.Detail = "the agent has not loaded its certificate; whether it names the host could not be checked"
	case hostID == current:
		check.Passed = boolPtr(false)
		check.Detail = fmt.Sprintf("the agent's certificate names the hostname %q; re-enrollment is needed after the rename", current)
	default:
		check.Passed = boolPtr(true)
		check.Detail = fmt.Sprintf("the agent's certificate names the host identifier %s, not the hostname; no re-enrollment needed", hostID)
	}
	return check
}

// ownAddresses lists the addresses of this host's interfaces, as text.
func ownAddresses() map[string]bool {
	own := map[string]bool{}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return own
	}
	for _, address := range addresses {
		switch value := address.(type) {
		case *net.IPNet:
			own[value.IP.String()] = true
		case *net.IPAddr:
			own[value.IP.String()] = true
		}
	}
	return own
}

// SetHostIdentity tells the executor what the agent's certificate names.
// The rename preflight compares it with the hostname: a certificate issued
// for the identifier survives a rename, one issued for the name does not.
func (e *TaskExecutor) SetHostIdentity(hostID string) {
	e.hostID = hostID
}
