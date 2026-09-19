package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/ctl"
)

func TestRenderTextPrintsOneLinePerCheckWithTheCode(t *testing.T) {
	report := ctl.Report{OK: false, Checks: []ctl.Check{
		ctl.Pass("config", "/etc/flotestro/relay.yaml"),
		ctl.Fail("tls.gateway", "tls_name_mismatch", "the certificate is valid for gw.example.com, not gateway.example.com"),
		ctl.Warn("buffer", "relay_buffer_high", "900.0 KiB of 1.0 MiB"),
		ctl.NotRun("upstream", "no state file"),
	}}
	var out bytes.Buffer
	ctl.RenderText(&out, report)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("lines = %d, we want 4 checks and a result: %q", len(lines), out.String())
	}
	// The code sits on the line of the check: it is what the operator
	// quotes and what a runbook matches.
	if !strings.Contains(lines[1], "tls_name_mismatch") || !strings.Contains(lines[1], "not gateway.example.com") {
		t.Fatalf("line 1 = %q", lines[1])
	}
	if !strings.Contains(lines[2], "warn") || !strings.Contains(lines[2], "relay_buffer_high") {
		t.Fatalf("line 2 = %q", lines[2])
	}
	if lines[4] != "Result: 1 failed" {
		t.Fatalf("line 4 = %q", lines[4])
	}
}

func TestRenderJSONCarriesTheBufferNumbers(t *testing.T) {
	used, limit := int64(3072), int64(1<<20)
	check := ctl.Pass("buffer", "3.0 KiB of 1.0 MiB")
	check.UsedBytes = &used
	check.MaxBytes = &limit
	var out bytes.Buffer
	if err := ctl.RenderJSON(&out, ctl.Report{OK: true, Checks: []ctl.Check{check}}); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		OK     bool                     `json:"ok"`
		Checks []map[string]interface{} `json:"checks"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if !decoded.OK || len(decoded.Checks) != 1 {
		t.Fatalf("decoded = %+v", decoded)
	}
	if decoded.Checks[0]["used_bytes"] != float64(3072) || decoded.Checks[0]["max_bytes"] != float64(1<<20) {
		t.Fatalf("buffer = %v", decoded.Checks[0])
	}
	if _, present := decoded.Checks[0]["error_code"]; present {
		t.Fatalf("a passed check carries an error_code: %v", decoded.Checks[0])
	}
}

// testDiagnostics wires a diagnosis to a temporary directory and to a network
// that answers the way the test says: the names resolve, every port is closed,
// and the relay has written a healthy state.
func testDiagnostics(t *testing.T) (diagnostics, string, time.Time) {
	t.Helper()
	path, directory := configurationFile(t, goodConfiguration)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	contact := now.Add(-30 * time.Second)
	state := ctl.RelayState{
		Gateway: "https://gw.example.com:8443", Listen: "0.0.0.0:8453",
		BufferBytes: 2048, BufferMaxBytes: 1 << 20, BufferedItems: 1,
		UpstreamOK: true, LastUpstreamAt: &contact,
	}
	return diagnostics{
		ConfigPath: path,
		Now:        func() time.Time { return now },
		Network: ctl.Network{
			Now:     func() time.Time { return now },
			Timeout: time.Second,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("connection refused")
			},
			LookupHost: func(ctx context.Context, host string) ([]string, error) {
				return []string{"192.168.56.10"}, nil
			},
		},
		Identity: func(stateDir string) storedIdentity {
			return storedIdentity{Present: true, RelayID: "4c1d9e2a", NotAfter: now.Add(5 * 24 * time.Hour)}
		},
		State:     func(stateDir string) (ctl.RelayState, error) { return state, nil },
		Listener:  func(address string) error { return nil },
		ReadFile:  os.ReadFile,
		FreeSpace: func(path string) (int64, error) { return 10 << 30, nil },
		Writable:  func(dir string) error { return nil },
	}, directory, now
}

func checkNamed(t *testing.T, report ctl.Report, name string) ctl.Check {
	t.Helper()
	check, ok := report.Find(name)
	if !ok {
		t.Fatalf("no check %q in %+v", name, report.Checks)
	}
	return check
}

func TestDiagnoseRunsEveryCheckIndependently(t *testing.T) {
	d, _, _ := testDiagnostics(t)
	report := d.run(context.Background())

	names := make([]string, 0, len(report.Checks))
	for _, check := range report.Checks {
		names = append(names, check.Name)
	}
	want := []string{"config", "identity", "clock", "dns.enrollment", "dns.gateway",
		"tls.enrollment", "tls.gateway", "state_dir", "buffer", "upstream", "listener", "pacnew"}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatalf("checks = %v, we want %v", names, want)
	}
	if report.OK {
		t.Fatalf("the report passed with a closed port: %+v", report.Checks)
	}
	for _, name := range []string{"config", "identity", "dns.enrollment", "dns.gateway",
		"state_dir", "buffer", "upstream", "listener", "pacnew"} {
		if check := checkNamed(t, report, name); check.Status != ctl.StatusPass {
			t.Fatalf("%s = %+v", name, check)
		}
	}
	// A closed port fails the TLS checks and leaves the clock unmeasured;
	// it does not stop the local checks after it.
	for _, name := range []string{"tls.enrollment", "tls.gateway"} {
		if check := checkNamed(t, report, name); check.Status != ctl.StatusFail || check.ErrorCode != "connect_failed" {
			t.Fatalf("%s = %+v", name, check)
		}
	}
	if check := checkNamed(t, report, "clock"); check.Status != ctl.StatusNotRun {
		t.Fatalf("clock = %+v", check)
	}
	if check := checkNamed(t, report, "identity"); check.DaysLeft == nil || *check.DaysLeft != 5 {
		t.Fatalf("identity = %+v", check)
	}
	if check := checkNamed(t, report, "state_dir"); check.FreeBytes == nil || *check.FreeBytes != 10<<30 {
		t.Fatalf("state_dir = %+v", check)
	}
	if check := checkNamed(t, report, "buffer"); check.UsedBytes == nil || *check.UsedBytes != 2048 || *check.MaxBytes != 1<<20 {
		t.Fatalf("buffer = %+v", check)
	}
}

func TestDiagnoseSkipsTLSWhenTheNameDoesNotResolve(t *testing.T) {
	d, _, _ := testDiagnostics(t)
	dialed := false
	d.Network.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("connection refused")
	}
	d.Network.LookupHost = func(ctx context.Context, host string) ([]string, error) {
		return nil, errors.New("no such host")
	}
	report := d.run(context.Background())

	if check := checkNamed(t, report, "dns.gateway"); check.ErrorCode != "dns_resolve_failed" {
		t.Fatalf("dns.gateway = %+v", check)
	}
	// A name that does not resolve makes the handshake meaningless: the
	// check says why instead of failing a second time for the same reason.
	if check := checkNamed(t, report, "tls.gateway"); check.Status != ctl.StatusNotRun || !strings.Contains(check.Detail, "dns.gateway") {
		t.Fatalf("tls.gateway = %+v", check)
	}
	if dialed {
		t.Fatal("the TLS check dialed a name that did not resolve")
	}
}

func TestDiagnoseWarnsOnAFillingBufferAndASilentCentre(t *testing.T) {
	d, _, now := testDiagnostics(t)
	contact := now.Add(-15 * time.Minute)
	since := now.Add(-12 * time.Minute)
	d.State = func(stateDir string) (ctl.RelayState, error) {
		return ctl.RelayState{
			Gateway: "https://gw.example.com:8443", BufferBytes: 800 << 10, BufferMaxBytes: 1 << 20,
			BufferedItems: 40, BufferingSince: &since, UpstreamOK: false,
			LastUpstreamAt: &contact, LastUpstreamError: "connection refused",
		}, nil
	}
	report := d.run(context.Background())

	// The buffer above seventy percent is the alert of the document; the
	// relay still works, so it is a warning rather than a failure.
	check := checkNamed(t, report, "buffer")
	if check.Status != ctl.StatusWarn || check.ErrorCode != "relay_buffer_high" {
		t.Fatalf("buffer = %+v", check)
	}
	if !strings.Contains(check.Detail, "oldest up to 12m0s") {
		t.Fatalf("buffer detail = %q", check.Detail)
	}
	check = checkNamed(t, report, "upstream")
	if check.Status != ctl.StatusWarn || check.ErrorCode != "relay_upstream_stale" {
		t.Fatalf("upstream = %+v", check)
	}
	if !strings.Contains(check.Detail, "15m0s ago") || !strings.Contains(check.Detail, "connection refused") {
		t.Fatalf("upstream detail = %q", check.Detail)
	}
}

func TestDiagnoseReportsDroppedResultsAndAnUnreachedCentre(t *testing.T) {
	d, _, _ := testDiagnostics(t)
	d.State = func(stateDir string) (ctl.RelayState, error) {
		return ctl.RelayState{Gateway: "https://gw.example.com:8443", BufferMaxBytes: 1 << 20,
			BufferDropped: 3, LastUpstreamError: "dial tcp: i/o timeout"}, nil
	}
	report := d.run(context.Background())
	if check := checkNamed(t, report, "buffer"); check.ErrorCode != "relay_buffer_dropping" {
		t.Fatalf("buffer = %+v", check)
	}
	// A centre never reached is a failure: the relay is up and serves
	// nobody.
	check := checkNamed(t, report, "upstream")
	if check.Status != ctl.StatusFail || check.ErrorCode != "relay_upstream_unreached" || !strings.Contains(check.Detail, "i/o timeout") {
		t.Fatalf("upstream = %+v", check)
	}
}

func TestDiagnoseWithoutAStateFileLeavesTheDaemonChecksUnrun(t *testing.T) {
	d, _, _ := testDiagnostics(t)
	d.State = func(stateDir string) (ctl.RelayState, error) { return ctl.RelayState{}, os.ErrNotExist }
	report := d.run(context.Background())
	for _, name := range []string{"buffer", "upstream"} {
		if check := checkNamed(t, report, name); check.Status != ctl.StatusNotRun {
			t.Fatalf("%s = %+v", name, check)
		}
	}
}

func TestDiagnoseChecksTheStateDirectory(t *testing.T) {
	d, _, _ := testDiagnostics(t)
	d.Writable = func(dir string) error { return errors.New("permission denied") }
	if check := checkNamed(t, d.run(context.Background()), "state_dir"); check.ErrorCode != "state_dir_unwritable" {
		t.Fatalf("state_dir = %+v", check)
	}
	d.Writable = func(dir string) error { return nil }
	d.FreeSpace = func(path string) (int64, error) { return 4 << 20, nil }
	check := checkNamed(t, d.run(context.Background()), "state_dir")
	if check.Status != ctl.StatusWarn || check.ErrorCode != "state_dir_low_space" {
		t.Fatalf("state_dir = %+v", check)
	}
	d.ConfigPath = filepath.Join(t.TempDir(), "relay.yaml")
	content := strings.Replace(goodConfiguration, `  state_dir: "/var/lib/flotestro-relay"`,
		`  state_dir: "/nonexistent/flotestro-relay"`, 1)
	if err := os.WriteFile(d.ConfigPath, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	if check := checkNamed(t, d.run(context.Background()), "state_dir"); check.ErrorCode != "state_dir_missing" {
		t.Fatalf("state_dir = %+v", check)
	}
}

func TestDiagnoseFlagsAnExpiringIdentity(t *testing.T) {
	d, _, now := testDiagnostics(t)
	d.Identity = func(stateDir string) storedIdentity {
		return storedIdentity{Present: true, RelayID: "4c1d9e2a", NotAfter: now.Add(6 * time.Hour)}
	}
	check := checkNamed(t, d.run(context.Background()), "identity")
	// Less than a day left on a seven-day certificate means the renewal
	// has been failing since yesterday.
	if check.Status != ctl.StatusWarn || check.ErrorCode != "identity_expiring" {
		t.Fatalf("identity = %+v", check)
	}
	d.Identity = func(stateDir string) storedIdentity { return storedIdentity{Err: "identity_missing"} }
	if check := checkNamed(t, d.run(context.Background()), "identity"); check.ErrorCode != "identity_missing" {
		t.Fatalf("identity = %+v", check)
	}
}

func TestDiagnoseStopsAtAConfigurationThatDoesNotLoad(t *testing.T) {
	d, _, _ := testDiagnostics(t)
	if err := os.WriteFile(d.ConfigPath, []byte("schema_version: 2\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	report := d.run(context.Background())
	if check := checkNamed(t, report, "config"); check.ErrorCode != "relay_config_schema_unsupported" {
		t.Fatalf("config = %+v", check)
	}
	for _, name := range []string{"identity", "tls.gateway", "listener"} {
		if check := checkNamed(t, report, name); check.Status != ctl.StatusNotRun {
			t.Fatalf("%s = %+v", name, check)
		}
	}
	if report.OK {
		t.Fatal("the report passed without a configuration")
	}
}

func TestDiagnoseRefusesAnOpenConfiguration(t *testing.T) {
	d, _, _ := testDiagnostics(t)
	if err := os.Chmod(d.ConfigPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if check := checkNamed(t, d.run(context.Background()), "config"); check.ErrorCode != "config_permissions_open" {
		t.Fatalf("config = %+v", check)
	}
}

func TestListenerProbeUsesTheLoopbackForAWildcard(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	if err := listenerWorks("0.0.0.0:" + port); err != nil {
		t.Fatalf("the wildcard was not probed on the loopback: %v", err)
	}
	if err := listenerWorks("127.0.0.1:1"); err == nil {
		t.Fatal("a closed port passed")
	}
}
