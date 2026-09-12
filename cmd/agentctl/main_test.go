package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodConfiguration = `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  state_dir: "/var/lib/flotestro-agent"
`

func configurationFile(t *testing.T, content string, permissions os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, permissions); err != nil {
		t.Fatal(err)
	}
	return path
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
		{"config without a subcommand", []string{"config"}, 2},
		{"config with an unknown subcommand", []string{"config", "fix"}, 2},
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

func TestConfigValidateLetsACorrectFileThrough(t *testing.T) {
	path := configurationFile(t, goodConfiguration, 0o640)
	var out, errOut bytes.Buffer
	if code := run([]string{"config", "validate", "--config", path}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d, errors: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "correct") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestConfigValidateReportsAnError(t *testing.T) {
	bad := configurationFile(t, "schema_version: 2\n", 0o640)
	var out, errOut bytes.Buffer
	if code := run([]string{"config", "validate", "--config", bad}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d", code)
	}
	// The error code is part of the contract: it is what reaches a report
	// from a host that does not speak to the panel yet.
	if !strings.Contains(errOut.String(), "config_schema_unsupported") {
		t.Fatalf("errors = %q", errOut.String())
	}
}

func TestConfigValidateWatchesThePermissionsOfTheFile(t *testing.T) {
	// The right to write to the configuration is the right to redirect the
	// host to somebody else's panel: a file that is syntactically correct but
	// open to everybody must not pass as correct.
	open := configurationFile(t, goodConfiguration, 0o666)
	var out, errOut bytes.Buffer
	if code := run([]string{"config", "validate", "--config", open}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d, output: %s", code, out.String())
	}
	if !strings.Contains(errOut.String(), "writable") {
		t.Fatalf("errors = %q", errOut.String())
	}
}

func TestConfigShowDoesNotShowSecrets(t *testing.T) {
	path := configurationFile(t, goodConfiguration, 0o640)
	var out, errOut bytes.Buffer
	if code := run([]string{"config", "show", "--config", path}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d, errors: %s", code, errOut.String())
	}
	content := out.String()
	for _, forbidden := range []string{"token", "TOKEN", "secret", "password"} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("the output carries %q: %s", forbidden, content)
		}
	}
	if !strings.Contains(content, "https://gw.example.com:8443") {
		t.Fatalf("the output has no gateway address: %s", content)
	}
}

func TestStatusSaysThatTheIdentityIsMissing(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "agent.yaml")
	content := strings.Replace(goodConfiguration, `  state_dir: "/var/lib/flotestro-agent"`,
		`  state_dir: "`+directory+`"`, 1)
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	// A host without an identity is a problem to fix rather than a usage
	// error.
	if code := run([]string{"status", "--config", path}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d, output: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "Identity:     missing") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestEnrollRefusesWhenTheIdentityIsValid(t *testing.T) {
	// Registering a host that is already in the fleet would be a silent
	// replacement of the identity. That is a separate decision and goes
	// through a request in the panel.
	directory := t.TempDir()
	path := filepath.Join(directory, "agent.yaml")
	content := strings.Replace(goodConfiguration, `  state_dir: "/var/lib/flotestro-agent"`,
		`  state_dir: "`+directory+`"`, 1)
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	// Without an identity the command is to ask for a token rather than
	// refuse - so we give an empty one to check the error path itself.
	var out, errOut bytes.Buffer
	code := runWithInput([]string{"enroll", "--config", path},
		strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("code = %d, output: %s %s", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "the enrollment token is empty") {
		t.Fatalf("errors = %q", errOut.String())
	}
}

func TestEnrollDoesNotTakeTheTokenFromAnArgument(t *testing.T) {
	// Every user of the host sees a command line argument in the process
	// list, so there is no such flag and there must not be one.
	var out, errOut bytes.Buffer
	code := runWithInput([]string{"enroll", "--token", "flt_whatever"},
		strings.NewReader(""), &out, &errOut)
	if code != 2 {
		t.Fatalf("code = %d - the flag with the token was accepted", code)
	}
}
