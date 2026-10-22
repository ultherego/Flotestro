//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/vuln"
)

// TestAFeedIsNotHeldBackForAReleaseTheFleetStoppedUsing runs the sanity gate on the
// real store. The releases of a fetch come from the fleet: retire the last host
// of one and the next fetch does not name it. That froze the whole provider -
// every later fetch was held as a candidate and the snapshot in force aged into
// feed_stale for every host of the family. A release the fetch asked for and did
// not get is still a loss, and the control below says so.
func TestAFeedIsNotHeldBackForAReleaseTheFleetStoppedUsing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	store := vuln.NewStore(pool)
	provider := "gate-test-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `delete from vuln_snapshots where provider = $1`, provider)
	})

	advisories := func(releases ...string) []vuln.Advisory {
		var out []vuln.Advisory
		for _, release := range releases {
			for i := 0; i < 3; i++ {
				out = append(out, vuln.Advisory{
					Provider: provider, AdvisoryID: "CVE-2026-" + release + "-" + string(rune(0x31+i)), CVEIDs: []string{"CVE-2026-0001"},
					Distribution: "gate", Release: release, SourcePackage: "pkg" + string(rune('a'+i)),
					Status: "resolved", FixedVersion: "1.0",
				})
			}
		}
		return out
	}
	fetch := func(digest string, requested, covered []string) error {
		_, err := store.SaveSnapshot(ctx, vuln.Snapshot{
			Provider: provider, Digest: digest, Releases: covered, Requested: requested,
		}, advisories(covered...), 0)
		return err
	}

	if err := fetch("first-"+provider, []string{"r1", "r2"}, []string{"r1", "r2"}); err != nil {
		t.Fatalf("the first fetch of a provider was refused: %v", err)
	}

	// Control: both releases asked for, one not delivered - the gate holds it.
	err := fetch("lost-"+provider, []string{"r1", "r2"}, []string{"r1"})
	var refusal *vuln.FeedRefusal
	if !errors.As(err, &refusal) || refusal.Reason != vuln.ReasonFeedReleaseMissing {
		t.Fatalf("a feed that dropped a release the fleet needs was not held back: %v", err)
	}

	// The fleet no longer has a host of r2: the fetch asks about r1 alone.
	if err := fetch("retired-"+provider, []string{"r1"}, []string{"r1"}); err != nil {
		t.Fatalf("a fetch for the releases still in the fleet was held back: %v", err)
	}
	active, err := store.ActiveSnapshot(ctx, provider)
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Releases) != 1 || active.Releases[0] != "r1" {
		t.Fatalf("the snapshot in force covers %v after the fleet dropped r2", active.Releases)
	}
}
