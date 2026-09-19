package agent

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// IdentityState describes the integration of the host with the domain.
type IdentityState struct {
	Enrolled bool     `json:"enrolled"`
	Domain   string   `json:"domain,omitempty"`
	Realm    string   `json:"realm,omitempty"`
	Servers  []string `json:"servers,omitempty"`

	SSSDInstalled bool  `json:"sssd_installed"`
	SSSDRunning   bool  `json:"sssd_running"`
	SSSDOnline    *bool `json:"sssd_online,omitempty"`

	CacheAgeSeconds *uint64 `json:"cache_age_seconds,omitempty"`

	HostPrincipal    string   `json:"host_principal,omitempty"`
	KeytabKVNO       *uint32  `json:"keytab_kvno,omitempty"`
	ClockSkewSeconds *float64 `json:"clock_skew_seconds,omitempty"`
	TimeSynchronized bool     `json:"time_synchronized"`

	ConfigIssues      []string `json:"config_issues,omitempty"`
	UnavailableReason string   `json:"unavailable_reason,omitempty"`

	// SSSDOfflinePolicy is what sssd. conf says happens to logins during a
	// directory outage.
	SSSDOfflinePolicy *SSSDOfflinePolicy `json:"sssd_offline_policy,omitempty"`
}

// SSSDOfflinePolicy is the offline behaviour SSSD was configured with for the
// joined domain.
type SSSDOfflinePolicy struct {
	CacheCredentials                 *bool    `json:"cache_credentials,omitempty"`
	OfflineCredentialsExpirationDays *uint32  `json:"offline_credentials_expiration_days,omitempty"`
	EntryCacheTimeoutSeconds         *uint32  `json:"entry_cache_timeout_seconds,omitempty"`
	StorePasswordIfOffline           *bool    `json:"krb5_store_password_if_offline,omitempty"`
	Defaulted                        []string `json:"defaulted,omitempty"`
	UnavailableReason                string   `json:"unavailable_reason,omitempty"`
}

const ipaConfigPath = "/etc/ipa/default.conf"

// ReadIdentityState collects the domain state locally.
func ReadIdentityState(ctx context.Context) IdentityState {
	state := IdentityState{
		SSSDInstalled: exists("/usr/sbin/sssd") || exists("/usr/lib/systemd/system/sssd.service"),
	}

	config := parseIPAConfig()
	state.Enrolled = len(config) > 0
	state.Domain = config["domain"]
	state.Realm = config["realm"]
	if server := config["server"]; server != "" {
		state.Servers = append(state.Servers, server)
	}
	if !state.Enrolled {
		// A host outside a domain is a valid state, not missing data.
		return state
	}

	state.SSSDRunning = unitActive(ctx, "sssd.service")
	state.ClockSkewSeconds, state.TimeSynchronized = clockState(ctx)
	return state
}

// PrivilegedIdentity completes the state with the data that requires root.
type PrivilegedIdentity struct {
	HostPrincipal     string
	KeytabKVNO        *uint32
	CacheAgeSeconds   *uint64
	SSSDOnline        *bool
	ConfigIssues      []string
	UnavailableReason string
	SSSDOfflinePolicy *SSSDOfflinePolicy
}

// Merge joins the result from the helper into the state read without
// privileges.
func (s IdentityState) Merge(privileged PrivilegedIdentity) IdentityState {
	s.HostPrincipal = privileged.HostPrincipal
	s.KeytabKVNO = privileged.KeytabKVNO
	s.CacheAgeSeconds = privileged.CacheAgeSeconds
	s.SSSDOnline = privileged.SSSDOnline
	s.ConfigIssues = privileged.ConfigIssues
	s.UnavailableReason = privileged.UnavailableReason
	s.SSSDOfflinePolicy = privileged.SSSDOfflinePolicy
	return s
}

// sssdOfflinePolicyFromHelper takes the policy out of the helper's answer.
func sssdOfflinePolicyFromHelper(message *helperv1.SssdOfflinePolicy) *SSSDOfflinePolicy {
	if message == nil {
		return nil
	}
	return &SSSDOfflinePolicy{
		CacheCredentials:                 message.CacheCredentials,
		OfflineCredentialsExpirationDays: message.OfflineCredentialsExpirationDays,
		EntryCacheTimeoutSeconds:         message.EntryCacheTimeoutSeconds,
		StorePasswordIfOffline:           message.Krb5StorePasswordIfOffline,
		Defaulted:                        message.GetDefaulted(),
		UnavailableReason:                message.GetUnavailableReason(),
	}
}

// sssdOfflinePolicyToProto carries the policy to the control plane. Nil stays
// nil and an unread value stays unset; the wire adds no certainty.
func sssdOfflinePolicyToProto(policy *SSSDOfflinePolicy) *agentv1.SssdOfflinePolicy {
	if policy == nil {
		return nil
	}
	return &agentv1.SssdOfflinePolicy{
		CacheCredentials:                 policy.CacheCredentials,
		OfflineCredentialsExpirationDays: policy.OfflineCredentialsExpirationDays,
		EntryCacheTimeoutSeconds:         policy.EntryCacheTimeoutSeconds,
		Krb5StorePasswordIfOffline:       policy.StorePasswordIfOffline,
		Defaulted:                        policy.Defaulted,
		UnavailableReason:                policy.UnavailableReason,
	}
}

// parseIPAConfig reads /etc/ipa/default.conf. The presence of the file is the
// only certain local proof that the host was joined to a domain.
func parseIPAConfig() map[string]string {
	file, err := os.Open(ipaConfigPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	config := map[string]string{}
	for line := range iterLines(ipaConfigPath) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "[") {
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		config[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return config
}

func unitActive(ctx context.Context, unit string) bool {
	result := runCommand(ctx, 10*time.Second, "/usr/bin/systemctl", "is-active", "--quiet", unit)
	return result.Ran && result.ExitCode == 0
}

// clockState reads the drift of the clock. Kerberos stops working at a
// difference of minutes, so this value is an early warning.
func clockState(ctx context.Context) (skew *float64, synchronized bool) {
	result := runCommand(ctx, 15*time.Second, "/usr/bin/chronyc", "-c", "tracking")
	if !result.Ran || result.ExitCode != 0 {
		return nil, false
	}
	// The -c format is comma-separated values; field 5 is the system offset
	// in seconds, and field 1 the address of the source.
	fields := strings.Split(strings.TrimSpace(result.Stdout), ",")
	if len(fields) < 6 {
		return nil, false
	}
	if parsed, err := strconv.ParseFloat(fields[4], 64); err == nil {
		skew = &parsed
	}
	synchronized = fields[1] != "" && fields[1] != "0.0.0.0"
	return skew, synchronized
}

// leaveDomain asks the helper to take the host out of its domain.
func (e *TaskExecutor) leaveDomain(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.DomainLeavePayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectUnknownAction,
			"the leave order names no domain")
	}
	timeout := timeoutOf(task, opspec.ActionDomainLeave)
	callCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		MaxOutputBytes: task.GetLimits().GetMaxOutputBytes(),
		Action: &helperv1.HelperRequest_DomainLeave{
			DomainLeave: &helperv1.DomainLeaveRequest{
				Domain: payload.Domain,
				Realm:  payload.Realm,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	// The leave answers in the join's shape with enrolled = false, so the
	// panel reads the checks and the verifications the way it already does.
	detail := enrollResultToAgent(response.GetEnrollResult())
	if !response.GetAccepted() {
		// A refusal before the uninstall - the preflight, a held guard - is a
		// rejection: nothing changed.
		status := agentv1.TaskResult_STATUS_FAILED
		if response.GetErrorCode() == "preflight_failed" || response.GetErrorCode() == "locked" {
			status = agentv1.TaskResult_STATUS_REJECTED
		}
		result := rejected(status, response.GetErrorCode(), response.GetMessage())
		result.Stderr = response.GetStderr()
		result.Detail = &agentv1.TaskResult_DomainEnroll{DomainEnroll: detail}
		return result
	}

	status := agentv1.TaskResult_STATUS_SUCCEEDED
	message := "the host left the domain"
	if failed := failedVerifications(detail); len(failed) > 0 {
		status = agentv1.TaskResult_STATUS_FAILED
		message = "the uninstall ran, but the host is not out of the domain: " + failed[0]
	}
	return &agentv1.TaskResult{
		Status:   status,
		ExitCode: 0,
		Message:  message,
		Detail:   &agentv1.TaskResult_DomainEnroll{DomainEnroll: detail},
	}
}

// renewKeytab asks the helper to fetch a new key of a service principal into
// the host's own keytab.
func (e *TaskExecutor) renewKeytab(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.KeytabPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the keytab payload is missing")
	}
	if err := opspec.ValidateServicePrincipal(payload.Principal); err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, err.Error())
	}
	timeout := timeoutOf(task, opspec.ActionIdentityKeytabRenew)
	callCtx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		MaxOutputBytes: task.GetLimits().GetMaxOutputBytes(),
		Action: &helperv1.HelperRequest_KeytabRenew{
			KeytabRenew: &helperv1.KeytabRenewRequest{Principal: payload.Principal},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	var detail *agentv1.KeytabRenewResult
	if renewed := response.GetKeytabRenewResult(); renewed != nil {
		detail = &agentv1.KeytabRenewResult{
			Principal:       renewed.GetPrincipal(),
			KvnoBeforeKnown: renewed.GetKvnoBeforeKnown(),
			KvnoBefore:      renewed.GetKvnoBefore(),
			KvnoAfter:       renewed.GetKvnoAfter(),
		}
	}
	if !response.GetAccepted() {
		// A refusal before the fetch - a held guard, a principal the helper would
		// not pass on - is a rejection: nothing changed.
		status := agentv1.TaskResult_STATUS_FAILED
		if response.GetErrorCode() == "locked" || response.GetErrorCode() == "malformed_request" {
			status = agentv1.TaskResult_STATUS_REJECTED
		}
		result := rejected(status, response.GetErrorCode(), response.GetMessage())
		result.TaskId = task.GetTaskId()
		result.Stderr = response.GetStderr()
		result.KeytabRenewResult = detail
		return result
	}
	message := "the keytab of " + payload.Principal + " was renewed"
	if detail != nil {
		message += ": key version " + strconv.FormatUint(uint64(detail.GetKvnoBefore()), 10) +
			" became " + strconv.FormatUint(uint64(detail.GetKvnoAfter()), 10)
	}
	return &agentv1.TaskResult{
		TaskId:            task.GetTaskId(),
		Status:            agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:           message,
		KeytabRenewResult: detail,
	}
}
