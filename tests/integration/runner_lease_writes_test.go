//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/campaigns"
)

// The orchestrator asks for the runner lease of every campaign that is not finished on
// every pass, a few seconds apart, and the lease lasts forty-five seconds and is meant
// to be renewed every fifteen. Writing it on every pass made nine writes a second in a
// laboratory with thirty-five campaigns waiting for an approval, on a table nothing was
// happening to. A lease held with time to spare is read and not written; one that is due is
// written once; one that expired goes to whoever asks.
//
// The version of the row (xmin) tells a write from a read.
func TestARunnerLeaseThatIsNotDueIsNotWrittenAgain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	store := campaigns.NewStore(pool)

	online := ""
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			online = host.ID
			break
		}
	}
	if online == "" {
		absent(t, "the fleet has no connected host of the debian family")
	}
	campaign := h.createCampaign(labCampaign("runner-lease-writes", "cron.service", map[string]any{
		"selector": map[string]any{"host_ids": []string{online}},
	}))
	// Out of the orchestrator's sight: a finished campaign is not claimed by the panel,
	// and the lease is then this test's alone.
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
		map[string]any{"reason": "the lease is tried on a finished campaign"}, nil, 0)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	exec(`update campaigns set runner_id = null, runner_until = null where id = $1::uuid`, campaign.ID)
	version := func() string {
		t.Helper()
		var xmin string
		if err := pool.QueryRow(ctx, `select xmin::text from campaigns where id = $1::uuid`, campaign.ID).Scan(&xmin); err != nil {
			t.Fatal(err)
		}
		return xmin
	}
	first, second := uuid.NewString(), uuid.NewString()

	token, held, err := store.ClaimRunner(ctx, campaign.ID, first)
	if err != nil || !held {
		t.Fatalf("a free lease was not given: held %v, err %v", held, err)
	}
	written := version()

	again, held, err := store.ClaimRunner(ctx, campaign.ID, first)
	if err != nil || !held || again != token {
		t.Fatalf("the holder was refused its own fresh lease: token %d (was %d), held %v, err %v", again, token, held, err)
	}
	if version() != written {
		t.Fatal("a lease renewed a moment ago was written again")
	}

	if _, held, err = store.ClaimRunner(ctx, campaign.ID, second); err != nil || held {
		t.Fatalf("another runner took a lease that is held: held %v, err %v", held, err)
	}

	// Due: a lease with less than the term minus the renewal left is renewed, once.
	exec(`update campaigns set runner_until = now() + interval '20 seconds' where id = $1::uuid`, campaign.ID)
	before := version()
	if _, held, err = store.ClaimRunner(ctx, campaign.ID, first); err != nil || !held {
		t.Fatalf("the holder of a due lease was refused: held %v, err %v", held, err)
	}
	if version() == before {
		t.Fatal("a lease that was due was not renewed")
	}
	var remaining float64
	if err := pool.QueryRow(ctx, `select extract(epoch from runner_until - now()) from campaigns where id = $1::uuid`,
		campaign.ID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining < float64(campaigns.RunnerLeaseTerm.Seconds())-5 {
		t.Fatalf("the renewed lease has %.0f seconds left, want about %.0f", remaining, campaigns.RunnerLeaseTerm.Seconds())
	}

	// Expired: it goes to whoever asks, and the token says the holder changed.
	exec(`update campaigns set runner_until = now() - interval '1 second' where id = $1::uuid`, campaign.ID)
	taken, held, err := store.ClaimRunner(ctx, campaign.ID, second)
	if err != nil || !held || taken != token+1 {
		t.Fatalf("an expired lease was not taken over: token %d (was %d), held %v, err %v", taken, token, held, err)
	}
}
