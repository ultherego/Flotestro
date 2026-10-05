//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/leases"
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
	var taken leases.Lease
	take := func(instance string) bool {
		t.Helper()
		lease, held, err := store.TakeCorrelatorLease(ctx, instance)
		if err != nil {
			t.Fatalf("taking the lease: %v", err)
		}
		if held {
			taken = lease
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
	if err := store.ReleaseCorrelatorLease(ctx, taken); err != nil {
		t.Fatalf("giving the lease back: %v", err)
	}
	if !take(second) {
		t.Error("a lease given back was not taken by the next instance")
	}
}

// A pass holds the lease for thirty minutes and writes the assessment of every
// host under it. A pass that runs or pauses past the term loses it, another
// instance takes it over and finishes a fresher assessment - and the first one
// used to come back and write over it, because it had asked about the lease
// half an hour earlier and the answer said nothing about this moment. The
// write carries the lease now (audit of 6c38561, OBS-01).
func TestAPassThatLostTheLeaseWritesNoAssessment(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

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

	name := uniqueName("vulnfence")
	var hostID string
	if err := pool.QueryRow(ctx, `
		insert into hosts (id, machine_id, hostname, site, environment, os_family, os_distribution,
		                   os_version, architecture, agent_version, connection_state, lifecycle_state,
		                   enrolled_at)
		values (gen_random_uuid(), $1, $1, 'lab', 'test', 'debian', 'debian', '12', 'x86_64',
		        '0.56.0', 'offline', 'active', now())
		returning id`, name).Scan(&hostID); err != nil {
		t.Fatalf("inserting the synthetic host: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `delete from hosts where id = $1::uuid`, hostID)
	})

	store := vuln.NewStore(pool)
	first, held, err := store.TakeCorrelatorLease(ctx, uuid.NewString())
	if err != nil || !held {
		t.Fatalf("taking the lease: held=%v err=%v", held, err)
	}
	evaluated := time.Now().UTC()
	state := vuln.HostState{Distribution: "debian", Release: "bookworm", Provider: "debian",
		EvaluatedAt: &evaluated}
	if err := store.SaveAdvisories(ctx, first, hostID, nil, state); err != nil {
		t.Fatalf("the instance holding the lease could not write the assessment: %v", err)
	}

	// The term runs out while that pass is still working, and the next instance
	// takes the lease over with a new token.
	if _, err := pool.Exec(ctx, `
		update monitoring_leases set lease_until = now() - interval '1 minute'
		 where name = 'vuln_correlator'`); err != nil {
		t.Fatalf("expiring the term: %v", err)
	}
	second, held, err := store.TakeCorrelatorLease(ctx, uuid.NewString())
	if err != nil || !held {
		t.Fatalf("the next instance did not take the lease: held=%v err=%v", held, err)
	}
	if second.Token == first.Token {
		t.Fatalf("the lease changed hands without changing token (%d)", second.Token)
	}

	// The pass that lost it comes back. Both of its writes find out here.
	if err := store.SaveAdvisories(ctx, first, hostID, nil, state); !errors.Is(err, leases.ErrLost) {
		t.Errorf("the assessment of the pass that lost the lease answered %v, expected ErrLost", err)
	}
	if err := store.RecordEvaluationFailure(ctx, first, hostID, vuln.SourceSave,
		time.Now()); !errors.Is(err, leases.ErrLost) {
		t.Errorf("the failure of the pass that lost the lease answered %v, expected ErrLost", err)
	}
	// The instance that holds it writes as before.
	if err := store.SaveAdvisories(ctx, second, hostID, nil, state); err != nil {
		t.Errorf("the instance holding the lease could not write: %v", err)
	}
}
