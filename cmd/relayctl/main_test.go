package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/ctl"
)

const goodConfiguration = `
schema_version: 1
relay:
  name: "relay-lab-01"
  site: "lab"
  listen: "0.0.0.0:8453"
  advertised_names:
    - "relay-lab-01.flotestro.test"
    - "192.168.56.60"
  state_dir: "/var/lib/flotestro-relay"
  buffer_max_bytes: 1048576
upstream:
  enrollment_url: "https://enroll.example.com:8444"
  gateway_urls:
    - "https://gw.example.com:8443"
`

// configurationFile writes a configuration with the state directory pointed
// at a temporary one, and returns the path of the file and the directory.
func configurationFile(t *testing.T, content string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	content = strings.Replace(content, `  state_dir: "/var/lib/flotestro-relay"`,
		`  state_dir: "`+directory+`"`, 1)
	path := filepath.Join(directory, "relay.yaml")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return path, directory
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
	}{
		{"without a command", nil, 2},
		{"an unknown command", []string{"order"}, 2},
		{"version", []string{"version"}, 0},
		{"usage", []string{"help"}, 0},
		{"diagnose with an unknown flag", []string{"diagnose", "--verbose"}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(c.args, &out, &errOut); code != c.code {
				t.Fatalf("code = %d, we want %d (%s%s)", code, c.code,
					out.String(), errOut.String())
			}
		})
	}
}

// testStatus wires the status to a temporary directory, a stopped clock and
// a listener that answers.
func testStatus(t *testing.T) (status, string, time.Time) {
	t.Helper()
	path, directory := configurationFile(t, goodConfiguration)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	return status{
		ConfigPath: path,
		Now:        func() time.Time { return now },
		Identity: func(stateDir string) storedIdentity {
			return storedIdentity{Present: true, RelayID: "4c1d9e2a", Subject: "relay-lab-01",
				Serial: "1234567890", NotAfter: now.Add(5 * 24 * time.Hour),
				Names: []string{"relay-lab-01.flotestro.test"}}
		},
		State:    ctl.ReadRelayState,
		Listener: func(address string) error { return nil },
	}, directory, now
}

func TestStatusShowsTheIdentityAndTheBuffer(t *testing.T) {
	s, directory, now := testStatus(t)
	contact := now.Add(-40 * time.Second)
	since := now.Add(-3 * time.Minute)
	centre := 2
	writer := ctl.NewRelayStateWriter(directory, "4c1d9e2a", "test")
	writer.Update(func(state *ctl.RelayState) {
		state.Gateway = "https://gw.example.com:8443"
		state.Sessions = 2
		state.BufferBytes = 3 << 10
		state.BufferMaxBytes = 1 << 20
		state.BufferedItems = 4
		state.BufferingSince = &since
		state.UpstreamOK = true
		state.LastUpstreamAt = &contact
		state.CentreSessions = &centre
	})

	var out bytes.Buffer
	if code := s.run(&out); code != 0 {
		t.Fatalf("code = %d: %s", code, out.String())
	}
	text := out.String()
	for _, want := range []string{
		"Identity:     relay/4c1d9e2a (CN relay-lab-01)",
		"Certificate:  serial 1234567890, valid until 2026-09-18T12:00:00Z (5d 00h)",
		"Names:        relay-lab-01.flotestro.test",
		"Centre:       https://gw.example.com:8443, last contact 2026-09-13T11:59:20Z (40s ago)",
		"Buffer:       3.0 KiB of 1.0 MiB, 4 items, oldest up to 3m0s",
		"Sessions:     2 agents (the centre sees 2)",
		"Listener:     accepting connections on 0.0.0.0:8453",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output lacks %q:\n%s", want, text)
		}
	}
}

func TestStatusWithoutAStateFileIsNotAFailure(t *testing.T) {
	// A relay that has not run yet has nothing to report about the centre;
	// that is not a fault of the relay.
	s, _, _ := testStatus(t)
	var out bytes.Buffer
	if code := s.run(&out); code != 0 {
		t.Fatalf("code = %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "Centre:       no record - the relay has not run yet") {
		t.Fatalf("output = %s", out.String())
	}
}

func TestStatusCountsTheProblems(t *testing.T) {
	s, directory, now := testStatus(t)
	s.Identity = func(stateDir string) storedIdentity { return storedIdentity{Err: "identity_missing"} }
	s.Listener = func(address string) error { return os.ErrNotExist }
	contact := now.Add(-time.Hour)
	writer := ctl.NewRelayStateWriter(directory, "", "test")
	writer.Update(func(state *ctl.RelayState) {
		state.Gateway = "https://gw.example.com:8443"
		state.LastUpstreamAt = &contact
		state.LastUpstreamError = "connection refused"
		state.BufferMaxBytes = 1 << 20
		state.BufferDropped = 7
	})
	var out bytes.Buffer
	if code := s.run(&out); code != 1 {
		t.Fatalf("code = %d: %s", code, out.String())
	}
	text := out.String()
	for _, want := range []string{
		"Identity:     missing (identity_missing)",
		"Centre:       https://gw.example.com:8443, unreachable since 2026-09-13T11:00:00Z (1h0m0s ago): connection refused",
		"DROPPED 7 results",
		"Listener:     not accepting connections on 0.0.0.0:8453",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output lacks %q:\n%s", want, text)
		}
	}
}

func TestStatusWithoutAConfigurationStops(t *testing.T) {
	s, _, _ := testStatus(t)
	s.ConfigPath = filepath.Join(t.TempDir(), "missing.yaml")
	var out bytes.Buffer
	if code := s.run(&out); code != 1 {
		t.Fatalf("code = %d: %s", code, out.String())
	}
	if !strings.HasPrefix(out.String(), "Config:       ERROR") {
		t.Fatalf("output = %s", out.String())
	}
}
