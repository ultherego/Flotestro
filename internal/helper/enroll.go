package helper

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// enrollDomain sprawdza warunki i dolacza hosta do domeny katalogu.
//
// Preflight jest zawsze wykonywany, takze przy pelnym dolaczeniu: nieudany
// warunek blokujacy zatrzymuje operacje, zanim cokolwiek zmieni sie na hoscie.
func (s *Server) enrollDomain(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.DomainEnrollRequest) *helperv1.HelperResponse {
	result := &helperv1.DomainEnrollResult{}

	hostname := action.GetHostname()
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	result.Checks = runPreflight(ctx, action, hostname)

	if action.GetPreflightOnly() {
		s.log.Info("preflight dolaczenia do domeny",
			"task_id", request.GetTaskId(), "hostname", hostname,
			"sprawdzen", len(result.Checks))
		return &helperv1.HelperResponse{Accepted: true, EnrollResult: result}
	}

	if blocked := blockingFailures(result.Checks); len(blocked) > 0 {
		response := reject("preflight_failed",
			"warunki dolaczenia nie sa spelnione: "+strings.Join(blocked, "; "))
		response.EnrollResult = result
		return response
	}
	if action.GetOneTimePassword() == "" {
		response := reject("missing_credential",
			"brak jednorazowego hasla dolaczenia")
		response.EnrollResult = result
		return response
	}

	// Jednoczesnie dziala najwyzej jedno dolaczenie: zmienia konfiguracje
	// SSSD, Kerberosa i PAM naraz.
	if !s.enrollMutex.TryLock() {
		response := reject(ErrorLocked, "inne dolaczenie do domeny jest w toku")
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
		// Haslo jednorazowe nie moze trafic do komunikatu bledu ani do logow.
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

	s.log.Info("host dolaczony do domeny",
		"task_id", request.GetTaskId(), "hostname", hostname,
		"domena", action.GetDomain(), "principal", result.HostPrincipal)

	return &helperv1.HelperResponse{Accepted: true, EnrollResult: result}
}

// runPreflight sprawdza warunki dolaczenia. Kazdy warunek ma wlasny wynik,
// bo operator musi wiedziec, ktory dokladnie nie jest spelniony.
func runPreflight(ctx context.Context, action *helperv1.DomainEnrollRequest, hostname string) []*helperv1.EnrollCheck {
	var checks []*helperv1.EnrollCheck

	// Nazwa FQDN: ipa-client-install odmawia pracy na samej nazwie krotkiej.
	checks = append(checks, check("fqdn", strings.Contains(hostname, "."), true,
		"nazwa hosta: "+hostname))

	// Rozwiazywanie nazwy w przod i wstecz.
	addresses, err := net.LookupHost(hostname)
	forward := err == nil && len(addresses) > 0
	checks = append(checks, check("dns_forward", forward, true, describeLookup(addresses, err)))

	if forward {
		names, reverseErr := net.LookupAddr(addresses[0])
		matches := reverseErr == nil && containsHost(names, hostname)
		// Brak rekordu wstecznego nie blokuje dolaczenia, ale bywa przyczyna
		// pozniejszych problemow z Kerberosem.
		checks = append(checks, check("dns_reverse", matches, false, describeLookup(names, reverseErr)))
	}

	// Serwer katalogu musi byc osiagalny na portach Kerberosa i LDAP.
	if server := action.GetServer(); server != "" {
		for _, port := range []string{"88", "389", "443"} {
			reachable := dialable(ctx, server, port)
			checks = append(checks, check("port_"+port, reachable, true,
				server+":"+port))
		}
	}

	// Konflikt istniejacej domeny: ponowne dolaczenie do innego realm
	// zniszczyloby dzialajaca konfiguracje.
	existing := parseExistingRealm()
	switch {
	case existing == "":
		checks = append(checks, check("realm_conflict", true, true, "host nie jest w zadnej domenie"))
	case existing == action.GetRealm():
		checks = append(checks, check("realm_conflict", true, true,
			"host jest juz w domenie "+existing))
	default:
		checks = append(checks, check("realm_conflict", false, true,
			"host nalezy do innej domeny: "+existing))
	}

	// Pakiety klienta.
	_, _, clientErr := runIdentityTool(ctx, 10*time.Second, "ipa-client-install", "--version")
	checks = append(checks, check("klient_ipa", clientErr == nil, true, describeError(clientErr)))

	// Synchronizacja czasu: Kerberos przestaje dzialac przy rozjezdzie rzedu minut.
	skew, synchronized := clockStatus(ctx)
	checks = append(checks, check("czas", synchronized, false, skew))

	return checks
}

// verifyEnrollment potwierdza, ze host faktycznie korzysta z domeny.
// Dopiero pozytywny wynik pozwala uznac dolaczenie za zakonczone.
func verifyEnrollment(ctx context.Context, domain, hostname string) []*helperv1.EnrollCheck {
	var checks []*helperv1.EnrollCheck

	_, _, keytabErr := runIdentityTool(ctx, 15*time.Second, "klist", "-k", "/etc/krb5.keytab")
	checks = append(checks, check("keytab", keytabErr == nil, true, describeError(keytabErr)))

	online, _, statusErr := sssdStatus(ctx, domain)
	checks = append(checks, check("sssd", statusErr == nil && online != nil && *online, true,
		describeError(statusErr)))

	// NSS musi rozwiazywac konta domenowe; bez tego dolaczenie jest pozorne.
	out, _, nssErr := runIdentityTool(ctx, 20*time.Second, "getent", "passwd", "admin")
	checks = append(checks, check("nss", nssErr == nil && strings.TrimSpace(out) != "", true,
		describeError(nssErr)))

	// Responder sudo dostarcza reguly z katalogu.
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

// parseExistingRealm czyta realm z istniejacej konfiguracji IPA.
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
		return "nieczytelny wynik chronyc", false
	}
	synchronized := fields[1] != "" && fields[1] != "0.0.0.0"
	return "odchylenie " + fields[4] + " s", synchronized
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

// redactSecret usuwa haslo jednorazowe z komunikatow. Sekret w logu jest
// sekretem ujawnionym.
func redactSecret(text, secret string) string {
	if secret == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, "[usuniete]")
}
