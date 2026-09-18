package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/identitystore"
)

// testReset wires a reset to a temporary state directory, a host that
// calls itself web-01 and a recovery that never touches a gateway.
func testReset(t *testing.T) (*identityReset, *[]string) {
	t.Helper()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	var tokens []string
	r := &identityReset{
		StateDir: t.TempDir(),
		Hostname: func() string { return "web-01" },
		Now:      func() time.Time { return now },
		Identity: func(stateDir string) agent.StoredIdentity {
			return agent.StoredIdentity{Present: true, HostID: "9b6dd18a", NotAfter: now.Add(20 * 24 * time.Hour)}
		},
		ReadToken: func() ([]byte, error) { return []byte("flt_recovery"), nil },
		Gateways:  []string{"https://gw.example.com:8443"},
		Recover: func(ctx context.Context, token []byte, gatewayURL string) (*agent.Identity, error) {
			tokens = append(tokens, string(token))
			return &agent.Identity{HostID: "9b6dd18a", NotAfter: now.Add(30 * 24 * time.Hour)}, nil
		},
	}
	return r, &tokens
}

func TestResetNeedsTheTypedConfirmation(t *testing.T) {
	r, tokens := testReset(t)
	var out, errOut bytes.Buffer
	// Without the confirmation the request is refused, and refused before
	// the token is asked for or anything goes to the panel.
	if code := r.run(context.Background(), &out, &errOut); code != 2 {
		t.Fatalf("code = %d, we want 2: %s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "confirmation_required") {
		t.Fatalf("errors = %q", errOut.String())
	}
	if len(*tokens) != 0 {
		t.Fatal("a reset without a confirmation reached the recovery")
	}

	// The wrong name is a wrong host: the operator may be on another
	// machine than the one they think.
	r.Confirm = "web-02"
	out.Reset()
	errOut.Reset()
	if code := r.run(context.Background(), &out, &errOut); code != 2 {
		t.Fatalf("code = %d, we want 2: %s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "confirmation_mismatch") {
		t.Fatalf("errors = %q", errOut.String())
	}
	if len(*tokens) != 0 {
		t.Fatal("a reset with the wrong confirmation reached the recovery")
	}
}

func TestResetReplacesTheIdentityWithTheToken(t *testing.T) {
	r, tokens := testReset(t)
	r.Confirm = "web-01"
	r.RevokeOld = true
	var out, errOut bytes.Buffer
	if code := r.run(context.Background(), &out, &errOut); code != 0 {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}
	if len(*tokens) != 1 || (*tokens)[0] != "flt_recovery" {
		t.Fatalf("tokens = %q", *tokens)
	}
	text := out.String()
	for _, line := range []string{
		"Current:      host/9b6dd18a", "kept until the new identity is verified",
		"Replaced:     host/9b6dd18a", "Certificate:  valid until",
		// Revocation is not something this host can do; the operator is
		// told where the decision lies.
		"revoked by the panel, not by this host", "revoke_old_immediately",
		"systemctl restart flotestro-agent.service",
	} {
		if !strings.Contains(text, line) {
			t.Fatalf("the output has no %q:\n%s", line, text)
		}
	}
	// The token itself is nowhere in the output.
	if strings.Contains(text+errOut.String(), "flt_recovery") {
		t.Fatal("the output carries the token")
	}
}

func TestResetKeepsTheCurrentIdentityWhenTheNewOneIsRejected(t *testing.T) {
	r, _ := testReset(t)
	r.Confirm = "web-01"
	r.Recover = func(context.Context, []byte, string) (*agent.Identity, error) {
		return nil, &agent.EnrollmentError{Code: agent.CodeIdentityRejected, Err: errors.New("bad certificate")}
	}
	var out, errOut bytes.Buffer
	if code := r.run(context.Background(), &out, &errOut); code != 1 {
		t.Fatalf("code = %d, we want 1: %s%s", code, out.String(), errOut.String())
	}
	// The code is what the operator matches against the table of errors.
	if !strings.Contains(errOut.String(), "identity_rejected") {
		t.Fatalf("errors = %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "the current identity host/9b6dd18a was kept") {
		t.Fatalf("errors = %q", errOut.String())
	}
}

func TestResetRefusesAnEmptyToken(t *testing.T) {
	r, tokens := testReset(t)
	r.Confirm = "web-01"
	r.ReadToken = func() ([]byte, error) { return nil, nil }
	var out, errOut bytes.Buffer
	if code := r.run(context.Background(), &out, &errOut); code != 1 {
		t.Fatalf("code = %d, we want 1: %s%s", code, out.String(), errOut.String())
	}
	if len(*tokens) != 0 {
		t.Fatal("an empty token reached the recovery")
	}
}

func TestResetDiscardsThePendingAttempt(t *testing.T) {
	r, tokens := testReset(t)
	store := identitystore.New(r.StateDir)
	if _, err := store.PreparePending(rand.Reader, r.Now(), "machine", nil, nil, "flt_ab12"); err != nil {
		t.Fatal(err)
	}
	r.DiscardPending = true
	var out, errOut bytes.Buffer
	// Discarding alone needs neither a confirmation nor a token: it is
	// housekeeping, and the reset itself starts only with the confirmation.
	if code := r.run(context.Background(), &out, &errOut); code != 0 {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}
	if _, err := os.Stat(store.PendingPath()); !os.IsNotExist(err) {
		t.Fatal("the pending record stayed")
	}
	if len(*tokens) != 0 {
		t.Fatal("discarding the attempt reached the recovery")
	}
	if !strings.Contains(out.String(), "Discarded:    the record") {
		t.Fatalf("output = %q", out.String())
	}

	// With the confirmation the discarding is followed by the reset.
	r.Confirm = "web-01"
	out.Reset()
	if code := r.run(context.Background(), &out, &errOut); code != 0 {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}
	if len(*tokens) != 1 {
		t.Fatalf("recoveries = %d", len(*tokens))
	}
	if !strings.Contains(out.String(), "Discarded:    nothing") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestResetDoesNotTakeTheTokenFromAnArgument(t *testing.T) {
	// Like enroll: a command line argument is seen by every user of the
	// host in the process list.
	var out, errOut bytes.Buffer
	code := runWithInput([]string{"identity", "reset", "--confirm", "web-01", "--token", "flt_whatever"},
		strings.NewReader(""), &out, &errOut)
	if code != 2 {
		t.Fatalf("code = %d - the flag with the token was accepted", code)
	}
}

func TestStatusShowsThePendingAttempt(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "agent.yaml")
	content := strings.Replace(goodConfiguration, `  state_dir: "/var/lib/flotestro-agent"`,
		`  state_dir: "`+directory+`"`, 1)
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	store := identitystore.New(directory)
	pending, err := store.PreparePending(rand.Reader, time.Now().Add(-90*time.Minute), "machine", nil, nil, "flt_ab12")
	if err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	run([]string{"status", "--config", path}, &out, &errOut)
	text := out.String()
	if !strings.Contains(text, "Pending:      enrollment attempt "+pending.ClientRequestID) {
		t.Fatalf("output = %q", text)
	}
	if !strings.Contains(text, "token prefix flt_ab12") {
		t.Fatalf("output = %q", text)
	}
	if !strings.Contains(text, "1h30m") {
		t.Fatalf("the age is missing: %q", text)
	}
	// The key and the request stay in the record; the status names the
	// attempt, it does not repeat it.
	if strings.Contains(text, "PRIVATE KEY") || strings.Contains(text, "CERTIFICATE REQUEST") {
		t.Fatal("the status prints the material of the attempt")
	}

	// An attempt without a recognisable token says so.
	if err := store.RemovePending(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PreparePending(rand.Reader, time.Now(), "machine", nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	run([]string{"status", "--config", path}, &out, &errOut)
	if !strings.Contains(out.String(), "token prefix unknown") {
		t.Fatalf("output = %q", out.String())
	}
}
