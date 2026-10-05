//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/identity"
)

// The panel half of an access cut, as a row that outlives the change.
//
// What cannot be seen without PostgreSQL is the condition that settles it. The
// settlement is one statement whose where clause is the confirmation: every
// subject the cut names is denied or unknown to the panel, and none of them
// holds a live session. A unit test can stub the settlement, and then the thing
// that decides is the thing that was stubbed - so the decision is asserted here.

func TestAnAccessCutIsSettledOnlyWhenTheAccessIsConfirmedGone(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool := h.database(ctx)
	store := identity.NewStore(pool)

	changeID := writeProbeChange(t, ctx, pool)
	subject := "arrears-" + uuid.NewString() + "@ipa.example.test"
	principalID := writeProbePrincipal(t, ctx, pool, subject)
	sessionID := writeProbeSession(t, ctx, pool, principalID)

	owed := []identity.AccessPrincipal{{Subject: subject, PrincipalID: principalID}}
	if err := store.OweLocalAccess(ctx, changeID, "arrears-probe", "the account was preserved",
		owed); err != nil {
		t.Fatalf("the obligation was not recorded: %v", err)
	}
	// Written twice is the same obligation and not a second one.
	if err := store.OweLocalAccess(ctx, changeID, "arrears-probe", "again", owed); err != nil {
		t.Fatalf("recording the obligation a second time failed: %v", err)
	}
	open, err := store.OpenLocalAccess(ctx, 50)
	if err != nil {
		t.Fatalf("the outstanding obligations were not read: %v", err)
	}
	if mine := arrearsOf(open, changeID); len(mine) != 1 {
		t.Fatalf("the change owes %d obligations, expected one", len(mine))
	}

	// A claim takes the row, and a second claim finds nothing: the term has not
	// run out and the row is the first claim's.
	claimed, err := store.ClaimLocalAccess(ctx, "integration-a", 50)
	if err != nil {
		t.Fatalf("the obligation was not claimed: %v", err)
	}
	mine := arrearsOf(claimed, changeID)
	if len(mine) != 1 {
		t.Fatalf("the claim took %d of this change's obligations", len(mine))
	}
	again, err := store.ClaimLocalAccess(ctx, "integration-b", 50)
	if err != nil {
		t.Fatalf("the second claim failed: %v", err)
	}
	if other := arrearsOf(again, changeID); len(other) != 0 {
		t.Error("two replicas claimed the same obligation at once")
	}

	// Nothing has been cut yet, so the settlement's own condition does not hold.
	if err := store.SettleLocalAccess(ctx, mine[0]); !errors.Is(err, identity.ErrAccessNotConfirmed) {
		t.Fatalf("an obligation whose effects are not there was settled: %v", err)
	}

	// The denial alone is not the whole of it: the session is still live.
	if _, err := store.SetLocalDeny(ctx, subject, "the account was preserved", true); err != nil {
		t.Fatalf("the denial was not written: %v", err)
	}
	if err := store.SettleLocalAccess(ctx, mine[0]); !errors.Is(err, identity.ErrAccessNotConfirmed) {
		t.Fatalf("an obligation was settled over a session that is still live: %v", err)
	}

	// Both effects, and now it settles.
	if _, err := pool.Exec(ctx,
		`update web_sessions set revoked_at = now() where id = $1::uuid`, sessionID); err != nil {
		t.Fatalf("the session was not ended: %v", err)
	}
	if err := store.SettleLocalAccess(ctx, mine[0]); err != nil {
		t.Fatalf("an obligation whose effects are confirmed was not settled: %v", err)
	}
	settled, err := store.LocalAccessOf(ctx, changeID)
	if err != nil {
		t.Fatalf("the settled obligation was not read: %v", err)
	}
	if settled.State != "settled" || settled.SettledAt == nil {
		t.Errorf("the obligation reads %+v", settled)
	}
	// And it is no longer outstanding, so the panel stops showing it.
	open, err = store.OpenLocalAccess(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	if left := arrearsOf(open, changeID); len(left) != 0 {
		t.Error("a settled obligation is still read as outstanding")
	}
	// A settlement cannot be written twice: the row is no longer outstanding.
	if err := store.SettleLocalAccess(ctx, mine[0]); !errors.Is(err, identity.ErrAccessNotConfirmed) {
		t.Errorf("a settled obligation was settled again: %v", err)
	}
}

// The claim lapses on its own, so an obligation whose replica stopped is taken
// again rather than staying claimed by nobody - and the arrears it reports are
// measured from when the panel took the obligation on, not from the last
// attempt at it.
func TestAnAccessCutWhoseReplicaStoppedIsTakenAgain(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool := h.database(ctx)
	store := identity.NewStore(pool)

	changeID := writeProbeChange(t, ctx, pool)
	if err := store.OweLocalAccess(ctx, changeID, "arrears-probe", "", nil); err != nil {
		t.Fatalf("the obligation was not recorded: %v", err)
	}
	claimed, err := store.ClaimLocalAccess(ctx, "integration-stopped", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(arrearsOf(claimed, changeID)) != 1 {
		t.Fatalf("the obligation was not claimed")
	}

	// The replica stops. All the panel ever sees of that is the claim running
	// out, and the row standing owed for longer.
	if _, err := pool.Exec(ctx, `
		update local_access_arrears
		   set claim_expires_at = now() - make_interval(secs => 1),
		       created_at = now() - make_interval(secs => 3600)
		 where change_id = $1::uuid`, changeID); err != nil {
		t.Fatal(err)
	}
	retaken, err := store.ClaimLocalAccess(ctx, "integration-successor", 50)
	if err != nil {
		t.Fatal(err)
	}
	mine := arrearsOf(retaken, changeID)
	if len(mine) != 1 {
		t.Fatalf("an obligation whose claim lapsed was taken by nobody")
	}
	if mine[0].Attempts != 2 {
		t.Errorf("the obligation reports %d attempts, expected two", mine[0].Attempts)
	}
	if mine[0].ArrearsSeconds < 3500 {
		t.Errorf("the arrears read as %v seconds, so they are measured from the last attempt",
			mine[0].ArrearsSeconds)
	}

	// Put back with a pause, it is not due again at once.
	if err := store.HoldLocalAccess(ctx, mine[0], time.Hour, "the database does not answer"); err != nil {
		t.Fatalf("the obligation was not put back: %v", err)
	}
	soon, err := store.ClaimLocalAccess(ctx, "integration-eager", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(arrearsOf(soon, changeID)) != 0 {
		t.Error("an obligation waiting out its backoff was claimed anyway")
	}
	held, err := store.LocalAccessOf(ctx, changeID)
	if err != nil {
		t.Fatal(err)
	}
	if held.LastError != "the database does not answer" {
		t.Errorf("the last error reads %q", held.LastError)
	}
}

// arrearsOf narrows a claim or a listing to one change: other rows may be in
// the table, and this test asserts about its own.
func arrearsOf(arrears []identity.LocalAccessArrear, changeID string) []identity.LocalAccessArrear {
	var mine []identity.LocalAccessArrear
	for _, arrear := range arrears {
		if arrear.ChangeID == changeID {
			mine = append(mine, arrear)
		}
	}
	return mine
}

// writeProbeChange puts a finished change of this test's own in the table, so
// the obligation has the change it belongs to. It is terminal, which is the
// whole point: the executor of changes will never look at it again.
func writeProbeChange(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	id := uuid.NewString()
	payload, err := json.Marshal(map[string]any{"probe": id})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		insert into directory_changes
			(id, action_type, payload, payload_hash, plan, state, requires_approval, created_by,
			 started_at, finished_at)
		values ($1::uuid, $2, $3::jsonb, $4, '{}'::jsonb, 'partially_applied', false,
		        'integration-test', now(), now())`,
		id, probeChange, payload, []byte(id)); err != nil {
		t.Fatalf("the change was not written: %v", err)
	}
	t.Cleanup(func() {
		// The obligation goes with the change it belongs to.
		_, _ = pool.Exec(context.Background(),
			`delete from directory_changes where id = $1::uuid`, id)
	})
	return id
}

// writeProbePrincipal gives the panel an identity to deny.
func writeProbePrincipal(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	subject string) string {
	t.Helper()
	id := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		insert into principals (id, subject, display_name)
		values ($1::uuid, $2, 'arrears probe')`, id, subject); err != nil {
		t.Fatalf("the identity was not written: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `delete from principals where id = $1::uuid`, id)
	})
	return id
}

// writeProbeSession gives that identity a live session, so the confirmation has
// something to refuse.
func writeProbeSession(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	principalID string) string {
	t.Helper()
	id := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		insert into web_sessions
			(id, token_hash, principal_id, absolute_expires_at, idle_expires_at)
		values ($1::uuid, $2, $3::uuid, now() + make_interval(secs => 3600),
		        now() + make_interval(secs => 3600))`,
		id, []byte(id), principalID); err != nil {
		t.Fatalf("the session was not written: %v", err)
	}
	return id
}
