package helper

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// The preflight runs the real tools of the host: name resolution, a TCP
// dial and a version query of ipa-client-install. On the machine running
// the unit tests those tools are absent or answer at once, so every scenario
// below is arranged so that its verdict does not depend on what the machine
// happens to have. The realm check reads /etc/ipa/default.conf at a fixed
// path, so the "host already in another domain" branch has no unit test:
// it needs a joined host, which the lab provides.

// enrollRequest wraps the join order in the envelope enrollDomain reads the
// deadline from.
func enrollRequest(action *helperv1.DomainEnrollRequest) *helperv1.HelperRequest {
	return &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		TaskId:          "task-enroll",
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Minute)),
		TimeoutSeconds:  60,
		MaxOutputBytes:  4096,
		Action:          &helperv1.HelperRequest_DomainEnroll{DomainEnroll: action},
	}
}

// findCheck returns the check of that name; a missing check fails the test,
// because a preflight that skips a condition passes it silently.
func findCheck(t *testing.T, checks []*helperv1.EnrollCheck, name string) *helperv1.EnrollCheck {
	t.Helper()
	for _, item := range checks {
		if item.GetName() == name {
			return item
		}
	}
	t.Fatalf("the preflight has no check named %s: %v", name, checkNames(checks))
	return nil
}

func checkNames(checks []*helperv1.EnrollCheck) []string {
	names := make([]string, 0, len(checks))
	for _, item := range checks {
		names = append(names, item.GetName())
	}
	return names
}

// TestThePreflightRefusesAShortHostName checks the first condition of a
// join: ipa-client-install needs a fully qualified name, and the preflight
// says so as a blocking failure instead of letting the tool find out.
func TestThePreflightRefusesAShortHostName(t *testing.T) {
	checks := runPreflight(context.Background(),
		&helperv1.DomainEnrollRequest{Domain: "flotestro.test", Realm: "FLOTESTRO.TEST"}, "web1")

	fqdn := findCheck(t, checks, "fqdn")
	if fqdn.GetPassed() || !fqdn.GetBlocking() {
		t.Fatalf("a short name passed the fqdn check: %+v", fqdn)
	}
	if !strings.Contains(fqdn.GetDetail(), "web1") {
		t.Fatalf("the detail does not name the host: %q", fqdn.GetDetail())
	}
	failures := blockingFailures(checks)
	if len(failures) == 0 || !strings.HasPrefix(failures[0], "fqdn (") {
		t.Fatalf("the blocking failures do not start with the fqdn check: %v", failures)
	}
}

// TestThePreflightRefusesANameThatDoesNotResolve uses a name under the
// reserved .invalid domain, which no resolver answers, so the forward lookup
// fails wherever the test runs. Without a forward record the reverse check
// is not even attempted: it would only repeat the same failure.
func TestThePreflightRefusesANameThatDoesNotResolve(t *testing.T) {
	const hostname = "web1.does-not-exist.invalid"
	checks := runPreflight(context.Background(),
		&helperv1.DomainEnrollRequest{Domain: "flotestro.test", Realm: "FLOTESTRO.TEST"}, hostname)

	if fqdn := findCheck(t, checks, "fqdn"); !fqdn.GetPassed() {
		t.Fatalf("a qualified name failed the fqdn check: %+v", fqdn)
	}
	forward := findCheck(t, checks, "dns_forward")
	if forward.GetPassed() || !forward.GetBlocking() {
		t.Fatalf("a name that does not resolve passed the forward check: %+v", forward)
	}
	if forward.GetDetail() == "" {
		t.Fatal("the failed lookup carries no detail for the operator")
	}
	for _, item := range checks {
		if item.GetName() == "dns_reverse" {
			t.Fatalf("a reverse check was made without an address to reverse: %+v", item)
		}
	}
	failures := strings.Join(blockingFailures(checks), "; ")
	if !strings.Contains(failures, "dns_forward (") {
		t.Fatalf("the blocking failures do not name the lookup: %s", failures)
	}
}

// TestThePreflightReportsEachClosedPort checks that the directory server is
// probed on every port the join needs, one verdict per port, so the operator
// learns which firewall rule is missing. The loopback address with nothing
// listening refuses at once, so the probe is quick and its result certain.
func TestThePreflightReportsEachClosedPort(t *testing.T) {
	ports := []string{"88", "389", "443"}
	for _, port := range ports {
		// A directory or a web server on the developer's machine would turn
		// the closed port into an open one; the test then has nothing to say.
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second); err == nil {
			_ = conn.Close()
			t.Skipf("something listens on 127.0.0.1:%s", port)
		}
	}

	started := time.Now()
	checks := runPreflight(context.Background(), &helperv1.DomainEnrollRequest{
		Domain: "flotestro.test", Realm: "FLOTESTRO.TEST", Server: "127.0.0.1",
	}, "web1.flotestro.test")
	// Three refused connections take milliseconds; anything longer means the
	// probe waited for a timeout it should not need on a closed port.
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("the preflight took %s", elapsed)
	}

	for _, port := range ports {
		check := findCheck(t, checks, "port_"+port)
		if check.GetPassed() || !check.GetBlocking() {
			t.Errorf("a closed port %s passed: %+v", port, check)
		}
		if check.GetDetail() != "127.0.0.1:"+port {
			t.Errorf("the detail of port %s is %q", port, check.GetDetail())
		}
	}
}

// TestThePreflightSkipsThePortsWithoutAServer guards that a join without a
// named server - discovery through DNS - is not refused for ports nobody
// asked to probe.
func TestThePreflightSkipsThePortsWithoutAServer(t *testing.T) {
	checks := runPreflight(context.Background(),
		&helperv1.DomainEnrollRequest{Domain: "flotestro.test", Realm: "FLOTESTRO.TEST"}, "web1")
	for _, item := range checks {
		if strings.HasPrefix(item.GetName(), "port_") {
			t.Fatalf("a port was probed although no server was named: %+v", item)
		}
	}
}

// TestAHostInNoDomainPassesTheRealmCheck checks the realm conflict for the
// common case of a fresh host. The check reads the IPA client configuration
// at its fixed path; a machine that is itself joined to a domain cannot run
// this test and says so.
func TestAHostInNoDomainPassesTheRealmCheck(t *testing.T) {
	if _, err := os.Stat("/etc/ipa/default.conf"); err == nil {
		t.Skip("this machine is joined to a domain; the fresh-host case cannot be observed here")
	}
	if realm := parseExistingRealm(); realm != "" {
		t.Fatalf("a host without an IPA configuration reports the realm %q", realm)
	}
	checks := runPreflight(context.Background(),
		&helperv1.DomainEnrollRequest{Domain: "flotestro.test", Realm: "FLOTESTRO.TEST"}, "web1")
	conflict := findCheck(t, checks, "realm_conflict")
	if !conflict.GetPassed() || !conflict.GetBlocking() {
		t.Fatalf("a host in no domain failed the realm check: %+v", conflict)
	}
	if !strings.Contains(conflict.GetDetail(), "no domain") {
		t.Fatalf("the detail does not say the host is in no domain: %q", conflict.GetDetail())
	}
}

// TestTheJoinStopsAtAFailedPreflight is the point of the preflight: a
// blocking failure ends the order before ipa-client-install starts, with the
// typed code, the list of failed conditions and every check attached, so the
// operator sees what to fix. The one-time password stays out of the answer.
func TestTheJoinStopsAtAFailedPreflight(t *testing.T) {
	const password = "one-time-secret-4711"
	action := &helperv1.DomainEnrollRequest{
		Domain: "flotestro.test", Realm: "FLOTESTRO.TEST",
		// A short name fails the first condition whatever the machine.
		Hostname:        "web1",
		OneTimePassword: password,
	}
	response := testServer().enrollDomain(context.Background(), enrollRequest(action), action)

	if response.GetAccepted() {
		t.Fatal("a join with a failed preflight was accepted")
	}
	if response.GetErrorCode() != "preflight_failed" {
		t.Fatalf("code = %q, expected preflight_failed", response.GetErrorCode())
	}
	if !strings.Contains(response.GetMessage(), "fqdn") {
		t.Fatalf("the message does not name the failed condition: %q", response.GetMessage())
	}
	if strings.Contains(response.GetMessage(), password) {
		t.Fatal("the one-time password reached the message")
	}
	result := response.GetEnrollResult()
	if result == nil || len(result.GetChecks()) == 0 {
		t.Fatal("the refusal carries no checks")
	}
	if result.GetEnrolled() {
		t.Fatal("a refused join reports the host as enrolled")
	}
	if fqdn := findCheck(t, result.GetChecks(), "fqdn"); fqdn.GetPassed() {
		t.Fatalf("the attached checks do not show the failure: %+v", fqdn)
	}
}

// TestAPreflightOnlyOrderReportsWithoutJoining checks the dry run: the
// operator asks what would block the join, gets every check, and nothing is
// attempted - also when the conditions are not met.
func TestAPreflightOnlyOrderReportsWithoutJoining(t *testing.T) {
	action := &helperv1.DomainEnrollRequest{
		Domain: "flotestro.test", Realm: "FLOTESTRO.TEST", Hostname: "web1", PreflightOnly: true,
	}
	response := testServer().enrollDomain(context.Background(), enrollRequest(action), action)

	if !response.GetAccepted() {
		t.Fatalf("a preflight-only order was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	result := response.GetEnrollResult()
	if result == nil || len(result.GetChecks()) == 0 {
		t.Fatal("the preflight-only answer carries no checks")
	}
	if result.GetEnrolled() {
		t.Fatal("a preflight-only order reports the host as enrolled")
	}
	if len(blockingFailures(result.GetChecks())) == 0 {
		t.Fatal("the dry run hides the failed conditions")
	}
}

// TestAJoinWithoutThePasswordIsRefusedAfterThePreflight guards the order of
// the refusals: the conditions of the host come before the credential, so an
// operator who fixes the missing password on a host that cannot join anyway
// is not sent around twice. A short name fails the preflight whatever the
// machine, so the refusal has to be the preflight, not the credential.
func TestAJoinWithoutThePasswordIsRefusedAfterThePreflight(t *testing.T) {
	action := &helperv1.DomainEnrollRequest{
		Domain: "flotestro.test", Realm: "FLOTESTRO.TEST", Hostname: "web1",
	}
	response := testServer().enrollDomain(context.Background(), enrollRequest(action), action)
	if response.GetAccepted() {
		t.Fatal("a join without a password was accepted")
	}
	// The short name fails the preflight, so the missing credential is not
	// the first thing the operator hears about.
	if response.GetErrorCode() != "preflight_failed" {
		t.Fatalf("code = %q, expected preflight_failed before missing_credential", response.GetErrorCode())
	}
}

// TestBlockingFailuresIgnoreAdvisoryChecks checks the split between what
// stops the join and what only warns: a missing reverse record or an
// unsynchronised clock are reported, not enforced.
func TestBlockingFailuresIgnoreAdvisoryChecks(t *testing.T) {
	checks := []*helperv1.EnrollCheck{
		check("dns_reverse", false, false, "no PTR record"),
		check("time", false, false, "chronyc: missing"),
		check("fqdn", true, true, "host name: web1.flotestro.test"),
	}
	if failures := blockingFailures(checks); len(failures) != 0 {
		t.Fatalf("advisory checks were counted as blocking: %v", failures)
	}
	checks = append(checks, check("port_88", false, true, "ipa.flotestro.test:88"))
	failures := blockingFailures(checks)
	if len(failures) != 1 || failures[0] != "port_88 (ipa.flotestro.test:88)" {
		t.Fatalf("blocking failures = %v", failures)
	}
}

// fakeIdentityTool records the directory tool calls, each with what it got
// on its standard input, instead of running them. Every tool answers as if
// it succeeded: the tests below are about what the helper hands to the
// tools, not about what the tools say back.
type fakeIdentityTool struct {
	calls    [][]string
	inputs   []string
	failures []fakeFailure
}

// fakeFailure makes a tool whose argv carries the marker end with the
// given code and stderr, the way the real one fails: with a banner on
// stdout first.
type fakeFailure struct {
	tool, marker string
	code         int
	stderr       string
}

func (f *fakeIdentityTool) fail(tool, marker string, code int, stderr string) {
	f.failures = append(f.failures, fakeFailure{tool: tool, marker: marker, code: code, stderr: stderr})
}

func (f *fakeIdentityTool) run(_ context.Context, _ time.Duration, input io.Reader,
	tool string, args ...string) (string, string, error) {
	f.calls = append(f.calls, append([]string{tool}, args...))
	text := ""
	if input != nil {
		data, _ := io.ReadAll(input)
		text = string(data)
	}
	f.inputs = append(f.inputs, text)
	for _, failure := range f.failures {
		if failure.tool != tool {
			continue
		}
		for _, arg := range args {
			if arg == failure.marker {
				return "This program will set up IPA client.\n", failure.stderr,
					&exitStatusError{tool: tool, code: failure.code, stderr: failure.stderr}
			}
		}
	}
	return "", "", nil
}

// call returns the first recorded call of the tool whose argv contains the
// marker, with what it got on stdin.
func (f *fakeIdentityTool) call(tool, marker string) ([]string, string, bool) {
	for i, call := range f.calls {
		if call[0] != tool {
			continue
		}
		for _, arg := range call[1:] {
			if arg == marker {
				return call[1:], f.inputs[i], true
			}
		}
	}
	return nil, "", false
}

// useFakeIdentityTool puts the fake in place of the real tools for the
// length of the test.
func useFakeIdentityTool(t *testing.T) *fakeIdentityTool {
	t.Helper()
	fake := &fakeIdentityTool{}
	previous := identityToolRunner
	identityToolRunner = fake.run
	t.Cleanup(func() { identityToolRunner = previous })
	return fake
}

// resolvableHostname finds a qualified name the machine running the tests
// resolves, so the preflight of a join can pass without a directory. A
// machine that resolves none of the candidates cannot observe a join
// reaching the tool and says so.
func resolvableHostname(t *testing.T) string {
	t.Helper()
	candidates := []string{"localhost.localdomain", "localhost."}
	if own, err := os.Hostname(); err == nil && strings.Contains(own, ".") {
		candidates = append([]string{own}, candidates...)
	}
	for _, candidate := range candidates {
		if addresses, err := net.LookupHost(candidate); err == nil && len(addresses) > 0 {
			return candidate
		}
	}
	t.Skip("no qualified name resolves on this machine; the join cannot pass its preflight here")
	return ""
}

// TestTheJoinArgumentsCarryThePassword pins the measured residual: the
// unattended tool takes the one-time password nowhere but in argv (it
// refuses -W without a terminal), so the argv carries it, and every
// message of the result is redacted instead.
func TestTheJoinArgumentsCarryThePassword(t *testing.T) {
	args := enrollArguments(&helperv1.DomainEnrollRequest{
		Domain: "flotestro.test", Realm: "FLOTESTRO.TEST", Server: "ipa.flotestro.test",
		OneTimePassword: "one-time-secret-4711",
	}, "web1.flotestro.test")
	for _, wanted := range []string{"--password=one-time-secret-4711", "--unattended", "--domain=flotestro.test",
		"--realm=FLOTESTRO.TEST", "--hostname=web1.flotestro.test", "--server=ipa.flotestro.test"} {
		found := false
		for _, arg := range args {
			if arg == wanted {
				found = true
			}
		}
		if !found {
			t.Errorf("the argv lacks %s: %v", wanted, args)
		}
	}
	for _, arg := range args {
		if arg == "-W" {
			t.Fatalf("the argv asks for a prompt the unattended tool refuses: %v", args)
		}
	}
}

// TestAJoinThatExitsWithAnErrorIsNotASuccess guards the verdict: the tool
// prints its banner before it fails, and a banner on stdout must not turn
// a non-zero exit into a join. The preflight is the real one, so the test
// needs a name that resolves and a machine that is in no domain.
func TestAJoinThatExitsWithAnErrorIsNotASuccess(t *testing.T) {
	if _, err := os.Stat("/etc/ipa/default.conf"); err == nil {
		t.Skip("this machine is joined to a domain; the realm check would refuse the join")
	}
	hostname := resolvableHostname(t)
	fake := useFakeIdentityTool(t)
	fake.fail("ipa-client-install", "--unattended", 1, "Password must be provided in non-interactive mode")

	const password = "one-time-secret-4711"
	action := &helperv1.DomainEnrollRequest{
		Domain: "flotestro.test", Realm: "FLOTESTRO.TEST",
		Hostname: hostname, OneTimePassword: password,
	}
	response := testServer().enrollDomain(context.Background(), enrollRequest(action), action)
	if response.GetAccepted() || response.GetEnrollResult().GetEnrolled() {
		t.Fatalf("a join that failed is reported as a success: %+v", response)
	}
	if response.GetErrorCode() != "enroll_failed" {
		t.Fatalf("error code = %q, expected enroll_failed", response.GetErrorCode())
	}
	if strings.Contains(response.GetMessage(), password) || strings.Contains(string(response.GetStderr()), password) {
		t.Fatalf("the password leaked into the result: %s", response.GetMessage())
	}
}

// TestTheRealRunnerHandsTheInputToTheTool checks the runner itself, with a
// real process: what is given as input arrives on the tool's standard
// input. cat echoes it back, and it lives at a fixed path on every Linux.
func TestTheRealRunnerHandsTheInputToTheTool(t *testing.T) {
	if _, err := os.Stat("/usr/bin/cat"); err != nil {
		t.Skip("/usr/bin/cat is missing")
	}
	stdout, _, err := execIdentityTool(context.Background(), 10*time.Second,
		strings.NewReader("one-time-secret-4711\n"), "cat")
	if err != nil {
		t.Fatalf("cat: %v", err)
	}
	if stdout != "one-time-secret-4711\n" {
		t.Fatalf("cat read %q from its standard input", stdout)
	}
}

// TestALeaveOfAHostInNoDomainIsRefused is the first condition of leaving:
// a host that is in no domain has nothing to leave, and the order stops
// before ipa-client-install --uninstall runs.
func TestALeaveOfAHostInNoDomainIsRefused(t *testing.T) {
	if _, err := os.Stat("/etc/ipa/default.conf"); err == nil {
		t.Skip("this machine is joined to a domain; the fresh-host case cannot be observed here")
	}
	fake := useFakeIdentityTool(t)

	action := &helperv1.DomainLeaveRequest{Domain: "flotestro.test", Realm: "FLOTESTRO.TEST"}
	request := &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		TaskId:          "task-leave",
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Minute)),
		TimeoutSeconds:  60,
		MaxOutputBytes:  4096,
		Action:          &helperv1.HelperRequest_DomainLeave{DomainLeave: action},
	}
	response := testServer().leaveDomain(context.Background(), request, action)

	if response.GetAccepted() {
		t.Fatal("a leave of a host in no domain was accepted")
	}
	if response.GetErrorCode() != "preflight_failed" {
		t.Fatalf("code = %q, expected preflight_failed", response.GetErrorCode())
	}
	if !strings.Contains(response.GetMessage(), "enrolled") {
		t.Fatalf("the message does not name the failed condition: %q", response.GetMessage())
	}
	enrolled := findCheck(t, response.GetEnrollResult().GetChecks(), "enrolled")
	if enrolled.GetPassed() || !enrolled.GetBlocking() {
		t.Fatalf("a host in no domain passed the enrolled check: %+v", enrolled)
	}
	if _, _, ok := fake.call("ipa-client-install", "--uninstall"); ok {
		t.Fatalf("the uninstall ran despite the failed preflight: %v", fake.calls)
	}
	if response.GetEnrollResult().GetEnrolled() {
		t.Fatal("a refused leave reports the host as enrolled")
	}
}

// TestTheLeaveVerificationsNameWhatIsLeftBehind pins the meaning of the
// checks after a leave on a machine that was never joined: the client
// configuration and the keytab are absent, and that is what "gone" means.
func TestTheLeaveVerificationsNameWhatIsLeftBehind(t *testing.T) {
	if _, err := os.Stat("/etc/ipa/default.conf"); err == nil {
		t.Skip("this machine is joined to a domain")
	}
	if _, err := os.Stat("/etc/krb5.keytab"); err == nil {
		t.Skip("this machine has a host keytab")
	}
	useFakeIdentityTool(t)

	checks := verifyLeave(context.Background(), "flotestro.test")
	// The configuration decides membership; the keytab is a warning, since
	// the uninstall may leave the file where it holds keys of its own.
	for name, blocking := range map[string]bool{"ipa_config": true, "keytab": false} {
		item := findCheck(t, checks, name)
		if !item.GetPassed() || item.GetBlocking() != blocking {
			t.Errorf("%s: %+v", name, item)
		}
		if !strings.Contains(item.GetDetail(), "gone") {
			t.Errorf("%s does not say the file is gone: %q", name, item.GetDetail())
		}
	}
	if describeAbsence("/etc/ipa/default.conf", nil) != "/etc/ipa/default.conf is still present" {
		t.Error("a present file is not named as still present")
	}
}
