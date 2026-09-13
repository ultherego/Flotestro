package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
)

// testRenewal wires a forced renewal to a temporary state directory, a clock
// the test moves and a renewal that never touches a gateway.
func testRenewal(t *testing.T) (*renewal, *time.Time, *int) {
	t.Helper()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	calls := 0
	r := &renewal{
		StateDir:   t.TempDir(),
		GatewayURL: "https://gw.example.com:8443",
		Now:        func() time.Time { return now },
		Identity: func(stateDir string) agent.StoredIdentity {
			return agent.StoredIdentity{Present: true, HostID: "9b6dd18a", NotAfter: now.Add(20 * 24 * time.Hour)}
		},
		Renew: func(ctx context.Context, stateDir, gatewayURL string) (*agent.Identity, error) {
			calls++
			return &agent.Identity{HostID: "9b6dd18a", NotAfter: now.Add(30 * 24 * time.Hour)}, nil
		},
	}
	return r, &now, &calls
}

func TestRenewIsRateLimitedLocally(t *testing.T) {
	r, now, calls := testRenewal(t)
	var out, errOut bytes.Buffer
	if code := r.run(context.Background(), &out, &errOut); code != 0 {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}
	if *calls != 1 {
		t.Fatalf("renewals = %d", *calls)
	}
	if !strings.Contains(out.String(), "Renewed:      host/9b6dd18a") {
		t.Fatalf("output = %q", out.String())
	}

	// Five minutes later the request is refused, and refused before the
	// gateway is asked.
	*now = now.Add(5 * time.Minute)
	out.Reset()
	errOut.Reset()
	if code := r.run(context.Background(), &out, &errOut); code != 2 {
		t.Fatalf("code = %d, we want 2: %s%s", code, out.String(), errOut.String())
	}
	if *calls != 1 {
		t.Fatalf("renewals = %d - the refusal reached the gateway", *calls)
	}
	if !strings.Contains(errOut.String(), "the last forced renewal was 5m0s ago") {
		t.Fatalf("errors = %q", errOut.String())
	}

	// Eleven minutes after the first one the way is open again.
	*now = now.Add(6 * time.Minute)
	out.Reset()
	errOut.Reset()
	if code := r.run(context.Background(), &out, &errOut); code != 0 {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}
	if *calls != 2 {
		t.Fatalf("renewals = %d", *calls)
	}
}

func TestRenewRecordsTheAttemptEvenWhenTheGatewayRefuses(t *testing.T) {
	// A refusal counts as an attempt: a script retrying a failure in a loop
	// is exactly what the limit is for.
	r, now, _ := testRenewal(t)
	r.Renew = func(ctx context.Context, stateDir, gatewayURL string) (*agent.Identity, error) {
		return nil, errors.New("the renewal was refused: quarantined")
	}
	var out, errOut bytes.Buffer
	if code := r.run(context.Background(), &out, &errOut); code != 1 {
		t.Fatalf("code = %d: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "quarantined") {
		t.Fatalf("errors = %q", errOut.String())
	}
	*now = now.Add(time.Minute)
	errOut.Reset()
	if code := r.run(context.Background(), &out, &errOut); code != 2 {
		t.Fatalf("code = %d, we want 2: %s", code, errOut.String())
	}
}

func TestRenewNeedsAnIdentity(t *testing.T) {
	r, _, calls := testRenewal(t)
	r.Identity = func(stateDir string) agent.StoredIdentity {
		return agent.StoredIdentity{Err: "no such file"}
	}
	var out, errOut bytes.Buffer
	if code := r.run(context.Background(), &out, &errOut); code != 1 {
		t.Fatalf("code = %d: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "identity_missing") {
		t.Fatalf("errors = %q", errOut.String())
	}
	if *calls != 0 {
		t.Fatal("a renewal without an identity reached the gateway")
	}
	// A host without an identity made no attempt, so nothing is recorded.
	if _, err := os.Stat(filepath.Join(r.StateDir, forcedRenewalFile)); !os.IsNotExist(err) {
		t.Fatalf("the record exists: %v", err)
	}
}

func TestRenewRefusesAnExpiredCertificate(t *testing.T) {
	r, now, calls := testRenewal(t)
	r.Identity = func(stateDir string) agent.StoredIdentity {
		return agent.StoredIdentity{Present: true, Expired: true, HostID: "9b6dd18a", NotAfter: now.Add(-time.Hour)}
	}
	var out, errOut bytes.Buffer
	if code := r.run(context.Background(), &out, &errOut); code != 1 {
		t.Fatalf("code = %d: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "identity_expired") || *calls != 0 {
		t.Fatalf("errors = %q, renewals = %d", errOut.String(), *calls)
	}
}

func TestRenewIgnoresADamagedRecord(t *testing.T) {
	// The record is a courtesy to the operator rather than a lock: a damaged
	// one must not block the renewal for good.
	r, _, calls := testRenewal(t)
	if err := os.WriteFile(filepath.Join(r.StateDir, forcedRenewalFile), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := r.run(context.Background(), &out, &errOut); code != 0 || *calls != 1 {
		t.Fatalf("code = %d, renewals = %d: %s", code, *calls, errOut.String())
	}
}
