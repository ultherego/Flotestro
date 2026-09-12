package helper

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// enrollDomain checks the conditions and joins the host to the directory
// domain.
//
// The preflight always runs, also during a full join: a failed blocking
// condition stops the operation before anything changes on the host.
func (s *Server) enrollDomain(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.DomainEnrollRequest) *helperv1.HelperResponse {
	result := &helperv1.DomainEnrollResult{}

	hostname := action.GetHostname()
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	result.Checks = runPreflight(ctx, action, hostname)

	if action.GetPreflightOnly() {
		s.log.Info("preflight of the domain join",
			"task_id", request.GetTaskId(), "hostname", hostname,
			"checks", len(result.Checks))
		return &helperv1.HelperResponse{Accepted: true, EnrollResult: result}
	}

	if blocked := blockingFailures(result.Checks); len(blocked) > 0 {
		response := reject("preflight_failed",
			"the conditions of the join are not met: "+strings.Join(blocked, "; "))
		response.EnrollResult = result
		return response
	}
	if action.GetOneTimePassword() == "" {
		response := reject("missing_credential",
			"the one-time join password is missing")
		response.EnrollResult = result
		return response
	}

	// At most one join runs at a time: it changes the configuration of SSSD,
	// Kerberos and PAM at once.
	if !s.enrollMutex.TryLock() {
		response := reject(ErrorLocked, "another domain join is in flight")
		response.EnrollResult = result
		return response
	}
	defer s.enrollMutex.Unlock()

	args := []string{
		"--unattended", "--mkhomedir", "--no-ntp",
		"--domain=" + action.GetDomain(),
		"--realm=" + action.GetRealm(),
		"--hostname=" + hostname,
		"--password=" + action.GetOneTimePassword(),
	}
	if server := action.GetServer(); server != "" {
		args = append(args, "--server="+server)
	}

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 10 * time.Minute
	}
	enrollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout, stderr, err := runIdentityTool(enrollCtx, timeout, "ipa-client-install", args...)
	if err != nil {
		// The one-time password must not reach the error message or the logs.
		response := reject("enroll_failed", redactSecret(err.Error(), action.GetOneTimePassword()))
		response.EnrollResult = result
		response.Stderr = []byte(redactSecret(stderr, action.GetOneTimePassword()))
		return response
	}
	_ = stdout

	result.Enrolled = true
	result.Verifications = verifyEnrollment(ctx, action.GetDomain(), hostname)
	if principal, _, keytabErr := readHostKeytab(ctx); keytabErr == nil {
		result.HostPrincipal = principal
	}

	s.log.Info("the host joined the domain",
		"task_id", request.GetTaskId(), "hostname", hostname,
		"domain", action.GetDomain(), "principal", result.HostPrincipal)

	return &helperv1.HelperResponse{Accepted: true, EnrollResult: result}
}

// runPreflight checks the conditions of the join. Every condition has its own
// result, because the operator has to know which one exactly is not met.
func runPreflight(ctx context.Context, action *helperv1.DomainEnrollRequest, hostname string) []*helperv1.EnrollCheck {
	var checks []*helperv1.EnrollCheck

	// The FQDN: ipa-client-install refuses to work with a short name alone.
	checks = append(checks, check("fqdn", strings.Contains(hostname, "."), true,
		"host name: "+hostname))

	// Forward and reverse name resolution.
	addresses, err := net.LookupHost(hostname)
	forward := err == nil && len(addresses) > 0
	checks = append(checks, check("dns_forward", forward, true, describeLookup(addresses, err)))

	if forward {
		names, reverseErr := net.LookupAddr(addresses[0])
		matches := reverseErr == nil && containsHost(names, hostname)
		// A missing reverse record does not block the join, but it is sometimes
		// the cause of later Kerberos problems.
		checks = append(checks, check("dns_reverse", matches, false, describeLookup(names, reverseErr)))
	}

	// The directory server has to be reachable on the Kerberos and LDAP ports.
	if server := action.GetServer(); server != "" {
		for _, port := range []string{"88", "389", "443"} {
			reachable := dialable(ctx, server, port)
			checks = append(checks, check("port_"+port, reachable, true,
				server+":"+port))
		}
	}

	// A conflict with an existing domain: joining another realm again would
	// destroy a working configuration.
	existing := parseExistingRealm()
	switch {
	case existing == "":
		checks = append(checks, check("realm_conflict", true, true, "the host is in no domain"))
	case existing == action.GetRealm():
		checks = append(checks, check("realm_conflict", true, true,
			"the host is already in the domain "+existing))
	default:
		checks = append(checks, check("realm_conflict", false, true,
			"the host belongs to another domain: "+existing))
	}

	// The client packages.
	_, _, clientErr := runIdentityTool(ctx, 10*time.Second, "ipa-client-install", "--version")
	checks = append(checks, check("ipa_client", clientErr == nil, true, describeError(clientErr)))

	// Time synchronization: Kerberos stops working at a drift of minutes.
	skew, synchronized := clockStatus(ctx)
	checks = append(checks, check("time", synchronized, false, skew))

	return checks
}

// verifyEnrollment confirms that the host really uses the domain. Only a
// positive result allows the join to count as finished.
func verifyEnrollment(ctx context.Context, domain, hostname string) []*helperv1.EnrollCheck {
	var checks []*helperv1.EnrollCheck

	_, _, keytabErr := runIdentityTool(ctx, 15*time.Second, "klist", "-k", "/etc/krb5.keytab")
	checks = append(checks, check("keytab", keytabErr == nil, true, describeError(keytabErr)))

	online, _, statusErr := sssdStatus(ctx, domain)
	checks = append(checks, check("sssd", statusErr == nil && online != nil && *online, true,
		describeError(statusErr)))

	// NSS has to resolve domain accounts; without that the join is only
	// apparent.
	out, _, nssErr := runIdentityTool(ctx, 20*time.Second, "getent", "passwd", "admin")
	checks = append(checks, check("nss", nssErr == nil && strings.TrimSpace(out) != "", true,
		describeError(nssErr)))

	// The sudo responder delivers the rules from the directory.
	sudoOut, _, sudoErr := runIdentityTool(ctx, 20*time.Second, "sssctl", "domain-status", domain)
	checks = append(checks, check("sudo_responder", sudoErr == nil, false,
		firstLineOf(sudoOut)))

	return checks
}

func check(name string, passed, blocking bool, detail string) *helperv1.EnrollCheck {
	value := passed
	return &helperv1.EnrollCheck{Name: name, Passed: &value, Detail: detail, Blocking: blocking}
}

func blockingFailures(checks []*helperv1.EnrollCheck) []string {
	var failures []string
	for _, item := range checks {
		if item.GetBlocking() && !item.GetPassed() {
			failures = append(failures, item.GetName()+" ("+item.GetDetail()+")")
		}
	}
	return failures
}

// parseExistingRealm reads the realm from the existing IPA configuration.
func parseExistingRealm() string {
	data, err := os.ReadFile("/etc/ipa/default.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found && strings.TrimSpace(key) == "realm" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func dialable(ctx context.Context, host, port string) bool {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func clockStatus(ctx context.Context) (string, bool) {
	out, _, err := runIdentityTool(ctx, 10*time.Second, "chronyc", "-c", "tracking")
	if err != nil {
		return describeError(err), false
	}
	fields := strings.Split(strings.TrimSpace(out), ",")
	if len(fields) < 6 {
		return "unreadable chronyc output", false
	}
	synchronized := fields[1] != "" && fields[1] != "0.0.0.0"
	return "offset " + fields[4] + " s", synchronized
}

func containsHost(names []string, hostname string) bool {
	target := strings.TrimSuffix(strings.ToLower(hostname), ".")
	for _, name := range names {
		if strings.TrimSuffix(strings.ToLower(name), ".") == target {
			return true
		}
	}
	return false
}

func describeLookup(values []string, err error) string {
	if err != nil {
		return err.Error()
	}
	return strings.Join(values, ", ")
}

func describeError(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// redactSecret removes the one-time password from messages. A secret in a log
// is a disclosed secret.
func redactSecret(text, secret string) string {
	if secret == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, "[removed]")
}
