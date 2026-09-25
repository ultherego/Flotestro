//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/vuln"
)

// Every replica used to download and parse every vulnerability feed, then
// rewrite the findings of every host: duplicated work whose last commit won,
// whichever of them had read the fresher inputs. One instance does the pass,
// under a lease of the same shape the alert evaluator has.
func TestOnlyOneInstanceCorrelatesVulnerabilities(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

	// The panel's own scheduler may hold the lease; the test takes it over the
	// way another instance would and gives it back afterwards.
	first, second := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `
		update monitoring_leases set holder = null, lease_until = null
		 where name = 'vuln_correlator'`); err != nil {
		t.Fatalf("freeing the lease: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			update monitoring_leases set holder = null, lease_until = null
			 where name = 'vuln_correlator'`)
	})

	store := vuln.NewStore(pool)
	take := func(instance string) bool {
		t.Helper()
		held, err := store.TakeCorrelatorLease(ctx, instance)
		if err != nil {
			t.Fatalf("taking the lease: %v", err)
		}
		return held
	}

	if !take(first) {
		t.Fatal("the free lease was not taken")
	}
	if take(second) {
		t.Fatal("two instances hold the correlator lease at once")
	}
	// The holder renews rather than losing it to itself.
	if !take(first) {
		t.Error("the holder could not renew its own lease")
	}
	if err := store.ReleaseCorrelatorLease(ctx, first); err != nil {
		t.Fatalf("giving the lease back: %v", err)
	}
	if !take(second) {
		t.Error("a lease given back was not taken by the next instance")
	}
}
