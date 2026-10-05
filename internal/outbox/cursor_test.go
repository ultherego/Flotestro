package outbox

import (
	"strings"
	"testing"
)

// The reader of the trail and its cursor have to stand in one order. The fence
// answers in the order of inserting transactions; a cursor on the event number
// alone stepped in another, and an event committed between the two orders was
// passed and never read again (audit of 6c38561, D2).
//
// Measured on PostgreSQL 16: the transaction 746 took event 2, the transaction
// 747 took event 1 and stayed open, 746 committed first. The identifier-only
// cursor moved to 2 and found nothing readable afterwards; the pair (746, 2)
// left event 1 of 747 ahead of itself, which is where it is.
func TestTheTrailIsReadInTheOrderTheFenceAnswersIn(t *testing.T) {
	key := eventKey("e")
	if !strings.Contains(key, "e.inserted_xid") || !strings.Contains(key, "e.id") {
		t.Fatalf("the order of the trail is not the transaction and the number: %s", key)
	}
	// The fence and the order are the same expression, so one cannot be
	// tightened and the other left behind.
	if !strings.Contains(settledTransaction("e"), thisEpoch("e.inserted_xid")) {
		t.Error("the fence judges a transaction differently from the order")
	}
	if !strings.Contains(settledTransaction("e"), "pg_snapshot_xmin(pg_current_snapshot())") {
		t.Error("the fence does not wait for the oldest running transaction")
	}

	// The cursor advances on the pair, never on the number alone, and never
	// backwards.
	for _, want := range []string{"last_xid", "last_id", "$2::xid8", "$3"} {
		if !strings.Contains(advanceCursor, want) {
			t.Errorf("the cursor advance does not name %s: %s", want, advanceCursor)
		}
	}
	if strings.Contains(advanceCursor, "greatest(last_id") {
		t.Error("the cursor still advances on the event number alone")
	}
	if !strings.Contains(advanceCursor, cursorAt("last_xid", "last_id")) {
		t.Error("the cursor advance does not compare where it stands as a whole")
	}

	// The retention asks the same question of the same pair: an event with a
	// lower number than the cursor may still be ahead of it, and deleting it
	// would lose it as surely as skipping it.
	held := UnpassedBySomeConsumer("e")
	if !strings.Contains(held, "c.last_xid") || !strings.Contains(held, "c.last_id") {
		t.Errorf("the retention reads the cursor as a number alone: %s", held)
	}
	if !strings.Contains(held, "c.active") {
		t.Error("the retention is held back by a consumer that is switched off")
	}

	// A transaction from another cluster - a dump restored here - has nothing
	// left to wait for and nothing to order by but the event number: without
	// this the restored cursor stood above every new event and the trail
	// stopped.
	if !strings.Contains(thisEpoch("x"), "pg_snapshot_xmax(pg_current_snapshot())") {
		t.Error("an identifier from another cluster is taken for one of this one")
	}
	if !strings.Contains(thisEpoch("x"), "'0'::xid8") {
		t.Error("an identifier nothing waits for does not read as the first one")
	}
}
