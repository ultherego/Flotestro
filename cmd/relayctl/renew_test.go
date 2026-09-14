package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/ctl"
	"github.com/ultherego/flotestro/internal/identitystore"
)

// testRenewal wires a forced renewal to a temporary state directory, a
// clock the test moves and a renewal that never touches the centre.
func testRenewal(t *testing.T) (*renewal, *time.Time, *int) {
	t.Helper()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	calls := 0
	r := &renewal{
		StateDir:   t.TempDir(),
		GatewayURL: "https://gw.example.com:8443",
		Names:      []string{"relay-lab-01.flotestro.test"},
		Now:        func() time.Time { return now },
		Identity: func(stateDir string) storedIdentity {
			return storedIdentity{Present: true, RelayID: "4c1d9e2a", NotAfter: now.Add(5 * 24 * time.Hour)}
		},
		Renew: func(ctx context.Context, stateDir, gatewayURL string, names []string) (*identitystore.Identity, error) {
			calls++
			return &identitystore.Identity{HostID: "4c1d9e2a", NotAfter: now.Add(7 * 24 * time.Hour)}, nil
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
	if !strings.Contains(out.String(), "Renewed:      relay/4c1d9e2a") {
		t.Fatalf("output = %q", out.String())
	}

	// Five minutes later the request is refused, and refused before the
	// centre is asked.
	*now = now.Add(5 * time.Minute)
	out.Reset()
	errOut.Reset()
	if code := r.run(context.Background(), &out, &errOut); code != 2 {
		t.Fatalf("code = %d, we want 2: %s%s", code, out.String(), errOut.String())
	}
	if *calls != 1 {
		t.Fatalf("renewals = %d - the refusal reached the centre", *calls)
	}
	if !strings.Contains(errOut.String(), "allowed in 5m0s") {
		t.Fatalf("errors = %q", errOut.String())
	}

	// After the interval the renewal goes through again.
	*now = now.Add(6 * time.Minute)
	out.Reset()
	errOut.Reset()
	if code := r.run(context.Background(), &out, &errOut); code != 0 || *calls != 2 {
		t.Fatalf("code = %d, renewals = %d: %s", code, *calls, errOut.String())
	}
}

func TestRenewRecordsARefusedAttempt(t *testing.T) {
	// A refusal by the centre counts as an attempt: a script retrying a
	// failure in a loop is exactly what the limit is for.
	r, now, calls := testRenewal(t)
	r.Renew = func(ctx context.Context, stateDir, gatewayURL string, names []string) (*identitystore.Identity, error) {
		*calls++
		return nil, os.ErrDeadlineExceeded
	}
	var out, errOut bytes.Buffer
	if code := r.run(context.Background(), &out, &errOut); code != 1 {
		t.Fatalf("code = %d: %s", code, errOut.String())
	}
	*now = now.Add(time.Minute)
	errOut.Reset()
	if code := r.run(context.Background(), &out, &errOut); code != 2 || *calls != 1 {
		t.Fatalf("code = %d, renewals = %d: %s", code, *calls, errOut.String())
	}
}

func TestRenewRefusesWithoutAnIdentity(t *testing.T) {
	r, _, calls := testRenewal(t)
	r.Identity = func(stateDir string) storedIdentity { return storedIdentity{Err: "no such file"} }
	var out, errOut bytes.Buffer
	if code := r.run(context.Background(), &out, &errOut); code != 1 {
		t.Fatalf("code = %d: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "identity_missing") || *calls != 0 {
		t.Fatalf("errors = %q, renewals = %d", errOut.String(), *calls)
	}
	// A relay without an identity made no attempt, so nothing is recorded.
	if _, err := os.Stat(filepath.Join(r.StateDir, ctl.ForcedRenewalFile)); !os.IsNotExist(err) {
		t.Fatalf("the record exists: %v", err)
	}
}

func TestRenewRefusesAnExpiredCertificate(t *testing.T) {
	r, now, calls := testRenewal(t)
	r.Identity = func(stateDir string) storedIdentity {
		return storedIdentity{Present: true, Expired: true, RelayID: "4c1d9e2a", NotAfter: now.Add(-time.Hour)}
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
	// The record is a courtesy to the operator rather than a lock: a
	// damaged one must not block the renewal for good.
	r, _, calls := testRenewal(t)
	if err := os.WriteFile(filepath.Join(r.StateDir, ctl.ForcedRenewalFile), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := r.run(context.Background(), &out, &errOut); code != 0 || *calls != 1 {
		t.Fatalf("code = %d, renewals = %d: %s", code, *calls, errOut.String())
	}
}

func TestSplitNamesSeparatesAddressesFromNames(t *testing.T) {
	dns, addresses := splitNames([]string{"relay-lab-01.flotestro.test", "192.168.56.60", "::1"})
	if len(dns) != 1 || dns[0] != "relay-lab-01.flotestro.test" {
		t.Fatalf("dns = %v", dns)
	}
	if len(addresses) != 2 || addresses[0].String() != "192.168.56.60" || addresses[1].String() != "::1" {
		t.Fatalf("addresses = %v", addresses)
	}
}
