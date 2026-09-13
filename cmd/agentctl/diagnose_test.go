package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
)

func TestRenderTextPrintsOneLinePerCheckWithTheCode(t *testing.T) {
	report := Report{OK: false, Checks: []Check{
		pass("config", "/etc/flotestro/agent.yaml"),
		fail("tls.enrollment", "tls_name_mismatch", "the certificate is valid for gateway.example.com, not enroll.example.com"),
		notRun("identity", "the configuration did not load"),
	}}
	var out bytes.Buffer
	renderText(&out, report)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines = %d, we want 3 checks and a result: %q", len(lines), out.String())
	}
	if !strings.HasPrefix(lines[0], "config") || !strings.Contains(lines[0], "pass") {
		t.Fatalf("line 0 = %q", lines[0])
	}
	// The code sits on the line of the check: it is what the operator quotes
	// and what a runbook matches.
	if !strings.Contains(lines[1], "tls_name_mismatch") || !strings.Contains(lines[1], "not enroll.example.com") {
		t.Fatalf("line 1 = %q", lines[1])
	}
	if !strings.Contains(lines[2], "not_run") {
		t.Fatalf("line 2 = %q", lines[2])
	}
	if lines[3] != "Result: 1 failed" {
		t.Fatalf("line 3 = %q", lines[3])
	}
}

func TestRenderJSONPrintsTheReportAsItIs(t *testing.T) {
	offset := int64(12)
	report := Report{OK: false, Checks: []Check{
		pass("config", ""),
		{Name: "clock", Status: StatusPass, OffsetMS: &offset},
		{Name: "dns.enrollment", Status: StatusPass, Addresses: []string{"10.20.0.12"}},
		fail("tls.enrollment", "tls_name_mismatch", "certificate is valid for gateway.example.com, not enroll.example.com"),
		notRun("identity", "the configuration did not load"),
	}}
	var out bytes.Buffer
	if err := renderJSON(&out, report); err != nil {
		t.Fatal(err)
	}

	var decoded struct {
		OK     bool                     `json:"ok"`
		Checks []map[string]interface{} `json:"checks"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if decoded.OK || len(decoded.Checks) != 5 {
		t.Fatalf("decoded = %+v", decoded)
	}
	// A passed check carries no error code and no empty detail: the JSON is
	// the typed result and nothing more.
	if _, present := decoded.Checks[0]["error_code"]; present {
		t.Fatalf("a passed check carries an error_code: %v", decoded.Checks[0])
	}
	if _, present := decoded.Checks[0]["detail"]; present {
		t.Fatalf("an empty detail was printed: %v", decoded.Checks[0])
	}
	if decoded.Checks[1]["offset_ms"] != float64(12) {
		t.Fatalf("clock = %v", decoded.Checks[1])
	}
	addresses, _ := decoded.Checks[2]["addresses"].([]interface{})
	if len(addresses) != 1 || addresses[0] != "10.20.0.12" {
		t.Fatalf("dns = %v", decoded.Checks[2])
	}
	if decoded.Checks[3]["error_code"] != "tls_name_mismatch" || decoded.Checks[3]["status"] != "fail" {
		t.Fatalf("tls = %v", decoded.Checks[3])
	}
	if decoded.Checks[4]["status"] != "not_run" {
		t.Fatalf("identity = %v", decoded.Checks[4])
	}
}

func TestClockCheckJudgesTheOffsetFromTheHeader(t *testing.T) {
	remote := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	date := remote.Format(http.TimeFormat)
	cases := []struct {
		name   string
		local  time.Time
		status string
		code   string
		offset int64
	}{
		{"in step", remote.Add(200 * time.Millisecond), StatusPass, "", 200},
		{"a little ahead", remote.Add(45 * time.Second), StatusWarn, "clock_skew", 45000},
		{"far behind", remote.Add(-6 * time.Minute), StatusFail, "clock_skew", -360000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check := clockCheck(c.local, date)
			if check.Status != c.status || check.ErrorCode != c.code {
				t.Fatalf("check = %+v, we want %s/%s", check, c.status, c.code)
			}
			if check.OffsetMS == nil || *check.OffsetMS != c.offset {
				t.Fatalf("offset = %v, we want %d", check.OffsetMS, c.offset)
			}
		})
	}
}

func TestClockCheckWithoutADateIsAWarningNotAFailure(t *testing.T) {
	// No header means the clock was not measured; it does not mean the
	// clock is wrong.
	check := clockCheck(time.Now(), "")
	if check.Status != StatusWarn || check.ErrorCode != "clock_unverified" {
		t.Fatalf("check = %+v", check)
	}
	check = clockCheck(time.Now(), "yesterday")
	if check.Status != StatusWarn || check.ErrorCode != "clock_unverified" {
		t.Fatalf("check = %+v", check)
	}
}

// timeoutError stands in for a handshake that ran out of time.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestTLSErrorMapsOntoStableCodes(t *testing.T) {
	mismatch := x509.HostnameError{
		Certificate: &x509.Certificate{DNSNames: []string{"gateway.example.com"}},
		Host:        "enroll.example.com",
	}
	cases := []struct {
		name   string
		err    error
		code   string
		detail string
	}{
		{"unknown authority", x509.UnknownAuthorityError{}, "tls_unknown_authority", "bootstrap_ca_file"},
		{"name mismatch", mismatch, "tls_name_mismatch", "valid for gateway.example.com, not enroll.example.com"},
		{"expired", x509.CertificateInvalidError{Reason: x509.Expired}, "tls_certificate_invalid", "see clock"},
		// The handshake wraps the verification error; the mapping has to
		// look through the wrapper.
		{"wrapped", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, "tls_unknown_authority", ""},
		{"further wrapped", fmt.Errorf("handshake: %w", mismatch), "tls_name_mismatch", ""},
		{"timeout", timeoutError{}, "connect_timeout", "timed out"},
		{"anything else", errors.New("remote error: tls: handshake failure"), "tls_handshake_failed", "handshake failure"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, detail := tlsError("enroll.example.com", c.err)
			if code != c.code {
				t.Fatalf("code = %q, we want %q (%s)", code, c.code, detail)
			}
			if !strings.Contains(detail, c.detail) {
				t.Fatalf("detail = %q, we want %q in it", detail, c.detail)
			}
		})
	}
}

func TestPacnewCheckSeesAnUnmergedConfiguration(t *testing.T) {
	directory := t.TempDir()
	d := diagnostics{ConfigPath: filepath.Join(directory, "agent.yaml")}
	if check := d.checkPacnew(); check.Status != StatusPass {
		t.Fatalf("check = %+v", check)
	}
	for _, suffix := range []string{".pacnew", ".rpmnew", ".dpkg-dist"} {
		t.Run(suffix, func(t *testing.T) {
			leftover := d.ConfigPath + suffix
			if err := os.WriteFile(leftover, []byte("schema_version: 1\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(leftover)
			check := d.checkPacnew()
			// A warning rather than a failure: the host runs on the old
			// settings, and somebody has to know that.
			if check.Status != StatusWarn || check.ErrorCode != "config_unmerged_update" {
				t.Fatalf("check = %+v", check)
			}
			if !strings.Contains(check.Detail, leftover) {
				t.Fatalf("detail = %q", check.Detail)
			}
		})
	}
}

func TestMachineIDCheck(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "machine-id")
	d := diagnostics{MachineIDPath: path}
	if check := d.checkMachineID(); check.ErrorCode != "machine_id_missing" {
		t.Fatalf("check = %+v", check)
	}
	if err := os.WriteFile(path, []byte("not-an-id\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if check := d.checkMachineID(); check.ErrorCode != "machine_id_invalid" {
		t.Fatalf("check = %+v", check)
	}
	if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if check := d.checkMachineID(); check.Status != StatusPass {
		t.Fatalf("check = %+v", check)
	}
}

// testDiagnostics wires a diagnosis to a temporary directory and to a network
// that answers the way the test says.
func testDiagnostics(t *testing.T, configuration string) (diagnostics, string) {
	t.Helper()
	directory := t.TempDir()
	content := strings.Replace(configuration, `  state_dir: "/var/lib/flotestro-agent"`,
		`  state_dir: "`+directory+`"`, 1)
	configPath := filepath.Join(directory, "agent.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	machineID := filepath.Join(directory, "machine-id")
	if err := os.WriteFile(machineID, []byte("0123456789abcdef0123456789abcdef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	return diagnostics{
		ConfigPath:      configPath,
		EnvironmentPath: filepath.Join(directory, "agent.env"),
		MachineIDPath:   machineID,
		Environ:         map[string]string{},
		Now:             func() time.Time { return now },
		Timeout:         time.Second,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		},
		LookupHost: func(ctx context.Context, host string) ([]string, error) {
			return []string{"10.20.0.12"}, nil
		},
		Socket: func(path string) error { return nil },
		Capabilities: func() agent.Capabilities {
			return agent.Capabilities{{Name: "packages", Available: true}, {Name: "docker"}}
		},
		Identity: func(stateDir string) agent.StoredIdentity {
			return agent.StoredIdentity{Present: true, HostID: "9b6dd18a", NotAfter: now.Add(20 * 24 * time.Hour)}
		},
	}, directory
}

func checkNamed(t *testing.T, report Report, name string) Check {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("no check %q in %+v", name, report.Checks)
	return Check{}
}

func TestDiagnoseRunsEveryCheckIndependently(t *testing.T) {
	d, _ := testDiagnostics(t, goodConfiguration)
	report := d.run(context.Background())

	names := make([]string, 0, len(report.Checks))
	for _, check := range report.Checks {
		names = append(names, check.Name)
	}
	want := []string{"config", "machine_id", "clock", "dns.enrollment", "dns.gateway",
		"tls.enrollment", "tls.gateway", "identity", "helper.socket", "capabilities", "pacnew"}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatalf("checks = %v, we want %v", names, want)
	}
	if report.OK {
		t.Fatalf("the report passed with a closed port: %+v", report.Checks)
	}

	for _, name := range []string{"config", "machine_id", "dns.enrollment", "dns.gateway",
		"identity", "helper.socket", "capabilities", "pacnew"} {
		if check := checkNamed(t, report, name); check.Status != StatusPass {
			t.Fatalf("%s = %+v", name, check)
		}
	}
	// A closed port fails the TLS checks and leaves the clock unmeasured; it
	// does not stop the local checks after it.
	for _, name := range []string{"tls.enrollment", "tls.gateway"} {
		if check := checkNamed(t, report, name); check.Status != StatusFail || check.ErrorCode != "connect_failed" {
			t.Fatalf("%s = %+v", name, check)
		}
	}
	if check := checkNamed(t, report, "clock"); check.Status != StatusNotRun {
		t.Fatalf("clock = %+v", check)
	}
	if check := checkNamed(t, report, "dns.enrollment"); len(check.Addresses) != 1 || check.Addresses[0] != "10.20.0.12" {
		t.Fatalf("dns.enrollment = %+v", check)
	}
	if check := checkNamed(t, report, "identity"); check.DaysLeft == nil || *check.DaysLeft != 20 {
		t.Fatalf("identity = %+v", check)
	}
	if check := checkNamed(t, report, "capabilities"); *check.Available != 1 || *check.Total != 2 {
		t.Fatalf("capabilities = %+v", check)
	}
}

func TestDiagnoseSkipsTLSWhenTheNameDoesNotResolve(t *testing.T) {
	d, _ := testDiagnostics(t, goodConfiguration)
	dialed := false
	d.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("connection refused")
	}
	d.LookupHost = func(ctx context.Context, host string) ([]string, error) {
		return nil, errors.New("no such host")
	}
	report := d.run(context.Background())

	if check := checkNamed(t, report, "dns.enrollment"); check.ErrorCode != "dns_resolve_failed" {
		t.Fatalf("dns.enrollment = %+v", check)
	}
	// A name that does not resolve makes the handshake meaningless: the
	// check says why instead of failing a second time for the same reason.
	if check := checkNamed(t, report, "tls.enrollment"); check.Status != StatusNotRun || !strings.Contains(check.Detail, "dns.enrollment") {
		t.Fatalf("tls.enrollment = %+v", check)
	}
	if dialed {
		t.Fatal("the TLS check dialed a name that did not resolve")
	}
}

func TestDiagnoseReportsTheOverridesWithoutTheToken(t *testing.T) {
	d, directory := testDiagnostics(t, goodConfiguration)
	env := "FLOTESTRO_ENROLLMENT_TOKEN=flt_secret_value\nFLOTESTRO_GATEWAY_URL=\"https://backup.example.com:8443\"\n"
	if err := os.WriteFile(filepath.Join(directory, "agent.env"), []byte(env), 0o640); err != nil {
		t.Fatal(err)
	}
	report := d.run(context.Background())

	check := checkNamed(t, report, "config")
	if check.Status != StatusWarn || check.ErrorCode != "enrollment_token_lingering" {
		t.Fatalf("config = %+v", check)
	}
	joined := strings.Join(check.Overrides, "\n")
	if !strings.Contains(joined, "FLOTESTRO_GATEWAY_URL=https://backup.example.com:8443") {
		t.Fatalf("overrides = %q", joined)
	}
	if !strings.Contains(joined, "FLOTESTRO_ENROLLMENT_TOKEN set") || strings.Contains(joined, "flt_secret_value") {
		t.Fatalf("the token is shown or missing: %q", joined)
	}
	// The variable replaces the gateway of the file, so the diagnosis
	// checks what the daemon really connects to.
	if check := checkNamed(t, report, "tls.gateway"); !strings.Contains(check.Detail, "backup.example.com") {
		t.Fatalf("tls.gateway = %+v", check)
	}
}

func TestDiagnoseFallsBackToTheEnvironmentFile(t *testing.T) {
	d, directory := testDiagnostics(t, goodConfiguration)
	if err := os.Remove(d.ConfigPath); err != nil {
		t.Fatal(err)
	}
	env := "FLOTESTRO_ENROLLMENT_URL=https://enroll.example.com\nFLOTESTRO_GATEWAY_URL=https://gw.example.com:8443\n"
	if err := os.WriteFile(filepath.Join(directory, "agent.env"), []byte(env), 0o640); err != nil {
		t.Fatal(err)
	}
	report := d.run(context.Background())

	if check := checkNamed(t, report, "config"); check.Status != StatusWarn || check.ErrorCode != "config_legacy_env" {
		t.Fatalf("config = %+v", check)
	}
	// The host still works on the variables, so the rest of the diagnosis
	// runs on them rather than stopping at the missing file.
	if check := checkNamed(t, report, "dns.enrollment"); check.Status != StatusPass {
		t.Fatalf("dns.enrollment = %+v", check)
	}
}

func TestDiagnoseStopsAtAConfigurationThatDoesNotLoad(t *testing.T) {
	d, _ := testDiagnostics(t, "schema_version: 2\n")
	report := d.run(context.Background())

	if check := checkNamed(t, report, "config"); check.ErrorCode != "config_schema_unsupported" {
		t.Fatalf("config = %+v", check)
	}
	if check := checkNamed(t, report, "tls.enrollment"); check.Status != StatusNotRun {
		t.Fatalf("tls.enrollment = %+v", check)
	}
	// The checks that need no configuration still run.
	if check := checkNamed(t, report, "machine_id"); check.Status != StatusPass {
		t.Fatalf("machine_id = %+v", check)
	}
	if report.OK {
		t.Fatal("the report passed without a configuration")
	}
}
