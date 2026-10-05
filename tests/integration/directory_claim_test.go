//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/identity"
)

// The takeover of a directory change and the result that arrives after it.
//
// A replica claims a change, stops, and its claim lapses; another replica takes
// the change over and finishes it; the first one comes back and writes its
// result. An external reviewer measured on PostgreSQL that the late write
// landed: the successor's Finish clears the holder, so the predecessor
// satisfied "nobody holds it" afterwards and overwrote succeeded with failed.
// A unit test cannot see this - the condition is in SQL and the fault is in the
// order of two transactions - so it is asserted here, through the store's own
// statements.

// probeChange is a change of this test's own: an action no executor knows, so
// a panel that claims the row finishes it without asking the directory
// anything.
const probeChange = "integration.claim-probe"

func TestALateResultDoesNotOverwriteTheRunThatFinishedTheChange(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool := h.database(ctx)
	store := identity.NewStore(pool)

	// The row is born claimed, in one statement: a planned row written here and
	// claimed a moment later is a row the panel's own executor may take in
	// between, and then the scenario is somebody else's.
	id, predecessor := writeClaimedProbeChange(t, ctx, pool)

	// A phase written while the predecessor holds the change is its own.
	recorded := []identity.Phase{
		{Name: "the predecessor started", Status: "succeeded", StartedAt: time.Now().UTC()},
	}
	if err := store.SavePhases(ctx, id, predecessor, recorded); err != nil {
		t.Fatalf("the predecessor could not record its phases: %v", err)
	}

	// The replica stops. All the panel ever sees of that is the claim running
	// out, which is what admits the change to another replica.
	lapseClaim(t, ctx, pool, id)

	successor, taken, err := store.Claim(ctx, id, "integration-successor")
	if err != nil {
		t.Fatalf("the change was not taken over: %v", err)
	}
	if taken {
		// The take says what it took: a running attempt, and the phases that
		// attempt had written. Read anywhere but in the claiming statement,
		// this is the answer from before the claim.
		if !successor.Resumed {
			t.Error("the claim took a running attempt over and reported a first execution")
		}
		// And it says how much of the term it took, measured by the database.
		// A term counted locally from the answer would be the whole of it
		// however long the statement took, which is the overlap that let two
		// replicas believe they held the same change.
		if !successor.Standing.Known() {
			t.Error("the claim reported no term, so the holder has only the constant to go on")
		}
		if successor.Standing.Remaining > identity.ClaimTerm {
			t.Errorf("the claim reported %v of term, which is more than the row holds (%v)",
				successor.Standing.Remaining, identity.ClaimTerm)
		}
		if !strings.Contains(string(successor.Phases), "the predecessor started") {
			t.Errorf("the claim did not carry the phases of the attempt it took over: %s",
				successor.Phases)
		}
		// While the successor holds the change, nothing of the predecessor's
		// lands - neither its phases nor its result.
		if err := store.SavePhases(ctx, id, predecessor, []identity.Phase{
			{Name: "the predecessor kept going", Status: "succeeded"},
		}); err == nil {
			t.Error("the predecessor wrote phases to a change it no longer holds")
		}
		if err := store.Finish(ctx, id, predecessor, identity.StateFailed,
			[]identity.Phase{{Name: "the predecessor failed", Status: "failed"}},
			"the predecessor's result"); err == nil {
			t.Error("the predecessor finished a change it no longer holds")
		}
		if err := store.Finish(ctx, id, successor, identity.StateSucceeded,
			[]identity.Phase{{Name: "the successor carried it out", Status: "succeeded"}},
			"the successor's result"); err != nil {
			t.Fatalf("the successor could not record its result: %v", err)
		}
	} else {
		// The panel's own executor took the change over first; then it is the
		// successor, and the scenario is the same one.
		t.Logf("the change %s was taken over by the panel itself", id)
	}

	stood := awaitTerminal(t, ctx, pool, id)

	// The predecessor comes back and finishes late. The claim is nobody's by
	// now, which is exactly what used to let this write through.
	err = store.Finish(ctx, id, predecessor, identity.StateFailed,
		[]identity.Phase{{Name: "the predecessor came back", Status: "failed"}},
		"the predecessor's late result")
	if err == nil {
		t.Fatal("a late result of an attempt the change had moved on from was recorded")
	}
	if !errors.Is(err, identity.ErrClaimLost) {
		t.Errorf("the refusal does not say the claim is lost: %v", err)
	}
	// And the lapsed claim cannot be renewed back into life either.
	if _, held, err := store.RenewClaim(ctx, id, predecessor); held || err != nil {
		t.Errorf("the lapsed claim was renewed: held=%v err=%v", held, err)
	}

	if now := readChange(t, ctx, pool, id); now != stood {
		t.Fatalf("the terminal result was overwritten:\n%+v\nbecame\n%+v", stood, now)
	}
}

// changeRow is the part of a directory change this scenario reads.
type changeRow struct {
	State    string
	Message  string
	Phases   string
	Finished bool
	Holder   string
	Attempt  string
}

func readChange(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) changeRow {
	t.Helper()
	var row changeRow
	if err := pool.QueryRow(ctx, `
		select state, coalesce(result_message, ''), phases::text, finished_at is not null,
		       coalesce(claimed_by, ''), coalesce(claim_token::text, '')
		  from directory_changes where id = $1::uuid`, id).
		Scan(&row.State, &row.Message, &row.Phases, &row.Finished, &row.Holder, &row.Attempt); err != nil {
		t.Fatalf("the change %s was not read: %v", id, err)
	}
	return row
}

// awaitTerminal waits for the change to reach a state nothing may write over,
// whichever replica got there.
func awaitTerminal(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) changeRow {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		row := readChange(t, ctx, pool, id)
		if identity.State(row.State).Terminal() {
			return row
		}
		if time.Now().After(deadline) {
			t.Fatalf("the change %s stayed in %s, so nothing finished it", id, row.State)
		}
		time.Sleep(time.Second)
	}
}

// writeClaimedProbeChange puts a change of this test's own in the queue and
// claims it for the predecessor in the same statement, so the row is never
// visible to anybody else's Pending: a replica is already carrying it out, and
// its claim has not run out. It is taken out again afterwards.
func writeClaimedProbeChange(t *testing.T, ctx context.Context,
	pool *pgxpool.Pool) (string, identity.Hold) {
	t.Helper()
	id := uuid.NewString()
	hold := identity.Hold{Holder: "integration-predecessor", Attempt: uuid.NewString()}
	payload, err := json.Marshal(map[string]any{"probe": id})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		insert into directory_changes
			(id, action_type, payload, payload_hash, plan, state, requires_approval, created_by,
			 started_at, claimed_by, claim_token, claim_expires_at)
		values ($1::uuid, $2, $3::jsonb, $4, '{}'::jsonb, 'running', false, 'integration-test',
		        now(), $5, $6::uuid, now() + make_interval(secs => $7::double precision))`,
		id, probeChange, payload, []byte(id), hold.Holder, hold.Attempt,
		identity.ClaimTerm.Seconds()); err != nil {
		t.Fatalf("the change was not written: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`delete from directory_changes where id = $1::uuid`, id)
	})
	return id, hold
}

// lapseClaim is the replica that stopped, as the database sees it: the claim
// runs out and nobody renews it.
func lapseClaim(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) {
	t.Helper()
	tag, err := pool.Exec(ctx, `
		update directory_changes set claim_expires_at = now() - make_interval(secs => 1)
		 where id = $1::uuid and state = 'running'`, id)
	if err != nil {
		t.Fatalf("the claim was not run out: %v", err)
	}
	if tag.RowsAffected() == 0 {
		t.Fatalf("the change %s is not running, so there is no claim to run out", id)
	}
}
