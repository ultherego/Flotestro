package identity

import (
	"context"
	"testing"
)

// A write about a running change names the attempt it is the result of. Without
// one it does not land at all, and it never reaches the database to be decided
// there: a replica that cannot say which run it is has nothing to record.
//
// The condition itself - the attempt and the terminal state - is SQL, and the
// scenario that drives it against PostgreSQL is in tests/integration under the
// integration tag, because the predecessor's late write was only ever visible
// against a real row.
func TestAResultThatNamesNoAttemptDoesNotLand(t *testing.T) {
	if (Hold{Holder: "replica-a"}).Held() {
		t.Fatal("a hold without an attempt reads as held")
	}
	if !(Hold{Holder: "replica-a", Attempt: "11111111-1111-1111-1111-111111111111"}).Held() {
		t.Fatal("a hold with an attempt reads as not held")
	}

	// The store has no pool here on purpose: these calls must refuse before
	// they would need one.
	store := &Store{}
	ctx := context.Background()
	if err := store.Finish(ctx, "change-1", Hold{Holder: "replica-a"}, StateSucceeded, nil, ""); err == nil {
		t.Fatal("a result with no attempt was accepted")
	}
	if err := store.SavePhases(ctx, "change-1", Hold{}, nil); err == nil {
		t.Fatal("phases with no attempt were accepted")
	}
	standing, held, err := store.RenewClaim(ctx, "change-1", Hold{Holder: "replica-a"})
	if held || err != nil {
		t.Fatalf("renewing a claim with no attempt answered %v, %v", held, err)
	}
	if standing.Known() {
		t.Fatal("a renewal that did not happen reported a term")
	}
}
