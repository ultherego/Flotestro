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
func (s *Server) enrollDomain(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.DomainEnrollRequest) *helperv1.HelperResponse {
	result := &helperv1.DomainEnrollResult{}

	// One limit for the whole order: the preflight, the join and the checks after
	// it.
	ctx, cancel := deadline(ctx, request, 10*time.Minute, 30*time.Minute)
	defer cancel()

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
	release, busy := s.hold(GuardIdentity, request)
	if busy != nil {
		busy.EnrollResult = result
		return busy
	}
	defer release()

	// The one-time password travels in argv, so it is readable in the process
	// list of the host for the length of the join.
	args := enrollArguments(action, hostname)

	stdout, stderr, err := runIdentityToolStrict(ctx, timeLimit(request, 10*time.Minute, 30*time.Minute),
		"ipa-client-install", args...)
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

// enrollArguments builds the argv of the join, the one-time password
// among them: the unattended tool takes it nowhere else.
func enrollArguments(action *helperv1.DomainEnrollRequest, hostname string) []string {
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
	return args
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

// leaveDomain takes the host out of its directory domain.
func (s *Server) leaveDomain(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.DomainLeaveRequest) *helperv1.HelperResponse {
	// The leave reports through the same shape as the join: the checks before,
	// the verifications after, and enrolled - false once the host is out.
	result := &helperv1.DomainEnrollResult{}

	ctx, cancel := deadline(ctx, request, 10*time.Minute, 30*time.Minute)
	defer cancel()

	result.Checks = runLeavePreflight(ctx, action)
	if blocked := blockingFailures(result.Checks); len(blocked) > 0 {
		response := reject("preflight_failed",
			"the conditions of leaving are not met: "+strings.Join(blocked, "; "))
		response.EnrollResult = result
		return response
	}

	// The same guard as the join: SSSD, Kerberos and PAM change at once.
	release, busy := s.hold(GuardIdentity, request)
	if busy != nil {
		busy.EnrollResult = result
		return busy
	}
	defer release()

	// --uninstall unenrolls the host in the directory with its own keytab and
	// restores the files the join changed.
	_, stderr, err := runIdentityToolStrict(ctx, timeLimit(request, 10*time.Minute, 30*time.Minute),
		"ipa-client-install", "--uninstall", "--unattended")
	if err != nil {
		response := reject("leave_failed", err.Error())
		response.EnrollResult = result
		response.Stderr = []byte(stderr)
		return response
	}

	result.Verifications = verifyLeave(ctx, action.GetDomain())

	s.log.Info("the host left the domain",
		"task_id", request.GetTaskId(), "domain", action.GetDomain(), "realm", action.GetRealm())

	return &helperv1.HelperResponse{Accepted: true, EnrollResult: result}
}

// runLeavePreflight checks the conditions of leaving. Every condition has
// its own result, for the same reason as in the join.
func runLeavePreflight(ctx context.Context, action *helperv1.DomainLeaveRequest) []*helperv1.EnrollCheck {
	var checks []*helperv1.EnrollCheck

	// The host has to be in a domain, and in the one the order names: the order
	// comes from the panel's view of the host, and that view can be older than
	// the host.
	existing := parseExistingRealm()
	switch {
	case existing == "":
		checks = append(checks, check("enrolled", false, true, "the host is in no domain"))
	case action.GetRealm() != "" && existing != action.GetRealm():
		checks = append(checks, check("enrolled", true, true, "the host is in the domain "+existing))
		checks = append(checks, check("realm_match", false, true,
			"the order names "+action.GetRealm()+", the host is in "+existing))
	default:
		checks = append(checks, check("enrolled", true, true, "the host is in the domain "+existing))
		checks = append(checks, check("realm_match", true, true, existing))
	}

	// The client packages: --uninstall is the same tool as the join.
	_, _, clientErr := runIdentityTool(ctx, 10*time.Second, "ipa-client-install", "--version")
	checks = append(checks, check("ipa_client", clientErr == nil, true, describeError(clientErr)))

	return checks
}

// verifyLeave confirms that the host really left: the client configuration and
// the host keytab are gone.
func verifyLeave(ctx context.Context, domain string) []*helperv1.EnrollCheck {
	var checks []*helperv1.EnrollCheck

	_, configErr := os.Stat("/etc/ipa/default.conf")
	checks = append(checks, check("ipa_config", os.IsNotExist(configErr), true,
		describeAbsence("/etc/ipa/default.conf", configErr)))

	// The keytab is advisory: ipa-client-install --uninstall unenrolls the host
	// and removes its configuration, but leaves /etc/krb5.
	_, keytabErr := os.Stat("/etc/krb5.keytab")
	checks = append(checks, check("keytab", os.IsNotExist(keytabErr), false,
		describeAbsence("/etc/krb5.keytab", keytabErr)))

	// SSSD must no longer know the domain. Advisory: an SSSD that keeps a
	// stale domain in its configuration is a warning, not a member host.
	if domain != "" {
		_, _, statusErr := runIdentityTool(ctx, 20*time.Second, "sssctl", "domain-status", domain)
		checks = append(checks, check("sssd_domain_gone", statusErr != nil, false,
			describeError(statusErr)))
	}

	return checks
}

// describeAbsence says whether a file the leave removes is really gone.
func describeAbsence(path string, err error) string {
	switch {
	case err == nil:
		return path + " is still present"
	case os.IsNotExist(err):
		return path + " is gone"
	default:
		return path + ": " + err.Error()
	}
}
