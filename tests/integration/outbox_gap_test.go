//go:build integration

package integration

import (
	"context"
	"strconv"
	"testing"
	"time"
)

// A sequence number is taken at the insert and becomes visible at the commit,
// and those are two different moments. A transaction that takes one number and
// stays open while another takes the next and commits used to leave the
// consumer's cursor past the open one: it committed afterwards and never
// satisfied "id > cursor" again, so the event reached no webhook and no
// notification, and nothing reported it (audit of 6c38561, D2).
//
// The test builds exactly that order of commits with two transactions of its
// own and asks the read the consumer makes.
func TestAnEventCommittedOutOfOrderIsStillRead(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

	// What the consumer reads: everything above a cursor that no transaction
	// can still insert below.
	const consumerRead = `
		select count(*) from outbox_events
		 where id > $1
		   and (inserted_xid is null
		        or inserted_xid < pg_snapshot_xmin(pg_current_snapshot()))`

	var cursor int64
	if err := pool.QueryRow(ctx,
		`select coalesce(max(id), 0) from outbox_events`).Scan(&cursor); err != nil {
		t.Fatal(err)
	}

	// The slow transaction takes its number first and does not commit.
	slow, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Rollback(ctx)
	var slowID int64
	if err := slow.QueryRow(ctx, `
		insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
		values ('test', gen_random_uuid(), 'test.slow', '{}'::jsonb)
		returning id`).Scan(&slowID); err != nil {
		t.Fatal(err)
	}

	// The quick one takes the next number and commits.
	var quickID int64
	if err := pool.QueryRow(ctx, `
		insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
		values ('test', gen_random_uuid(), 'test.quick', '{}'::jsonb)
		returning id`).Scan(&quickID); err != nil {
		t.Fatal(err)
	}
	if quickID <= slowID {
		t.Fatalf("the quick event took %d and the slow one %d; the order under test did not happen",
			quickID, slowID)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`delete from outbox_events where aggregate_type = 'test' and id in ($1, $2)`,
			slowID, quickID)
	})

	// With the slow transaction still open, the committed one is not readable
	// either: reading it would move the cursor past a number that is still to
	// come. This is the whole of the fix - the wait is deliberate.
	var readable int
	if err := pool.QueryRow(ctx, consumerRead, cursor).Scan(&readable); err != nil {
		t.Fatal(err)
	}
	if readable != 0 {
		t.Fatalf("%d events are readable while a lower number is still open", readable)
	}

	// The slow one commits last.
	if err := slow.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// Both are readable now, in the order of their identifiers. Before the fix
	// the cursor had already moved to the quick one and the slow one was lost.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := pool.QueryRow(ctx, consumerRead, cursor).Scan(&readable); err != nil {
			t.Fatal(err)
		}
		if readable >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of the 2 events are readable after both transactions committed", readable)
		}
		time.Sleep(time.Second)
	}
}

// The fence of 0140 made the reader wait for the transactions; the cursor went
// on stepping in the order of event numbers, and those two orders cross. A
// transaction that takes its identifier at an earlier write, while another with
// a later identifier has already reserved a lower event number and stays open,
// commits first: its event passes the fence although its number is the higher
// one, and a cursor on the number alone moves past the lower one for good
// (audit of 6c38561, D2).
//
// The test builds that order of commits and asks both cursors. Measured on
// PostgreSQL 16 before it was fixed: nothing readable at the end.
func TestTheCursorDoesNotPassAnEventOfAnOlderTransaction(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

	// The key of an event and the key of a cursor, as the panel renders them.
	const eventKey = `(case when e.inserted_xid is null
		                or e.inserted_xid >= pg_snapshot_xmax(pg_current_snapshot())
		           then '0'::xid8 else e.inserted_xid end, e.id)`
	const settled = `case when e.inserted_xid is null
		                or e.inserted_xid >= pg_snapshot_xmax(pg_current_snapshot())
		           then '0'::xid8 else e.inserted_xid end
		         < pg_snapshot_xmin(pg_current_snapshot())`
	// What the consumer reads above a cursor it holds as the pair.
	readAbovePair := `select coalesce(string_agg(e.event_type, ',' order by ` + eventKey + `), '')
		 from outbox_events e where ` + eventKey + ` > ($1::xid8, $2) and ` + settled
	// What it read above a cursor that was the event number alone.
	readAboveID := `select coalesce(string_agg(e.event_type, ',' order by e.id), '')
		 from outbox_events e where e.id > $1 and ` + settled

	// The earlier transaction takes its identifier at a write of its own,
	// before any event exists: that is what a panel transaction does, and it
	// is what puts the two orders out of step.
	early, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer early.Rollback(ctx)
	var earlyXID, lateXID int64
	if err := early.QueryRow(ctx, `select pg_current_xact_id()::text::bigint`).Scan(&earlyXID); err != nil {
		t.Fatal(err)
	}

	// The later transaction takes the lower event number and stays open.
	late, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer late.Rollback(ctx)
	if err := late.QueryRow(ctx, `select pg_current_xact_id()::text::bigint`).Scan(&lateXID); err != nil {
		t.Fatal(err)
	}
	if lateXID <= earlyXID {
		t.Fatalf("the transactions took %d and %d; the order under test did not happen", earlyXID, lateXID)
	}
	var lowID int64
	if err := late.QueryRow(ctx, `
		insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
		values ('test', gen_random_uuid(), 'test.low', '{}'::jsonb)
		returning id`).Scan(&lowID); err != nil {
		t.Fatal(err)
	}

	// The earlier transaction takes the higher number and commits first.
	var highID int64
	if err := early.QueryRow(ctx, `
		insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
		values ('test', gen_random_uuid(), 'test.high', '{}'::jsonb)
		returning id`).Scan(&highID); err != nil {
		t.Fatal(err)
	}
	if highID <= lowID {
		t.Fatalf("the events took %d and %d; the order under test did not happen", highID, lowID)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`delete from outbox_events where aggregate_type = 'test' and id in ($1, $2)`, lowID, highID)
	})
	if err := early.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// With the later transaction still open, its event is not readable and the
	// committed one is: the cursor is about to stand at (earlier, higher).
	var readable string
	if err := pool.QueryRow(ctx, readAbovePair, "0", lowID-1).Scan(&readable); err != nil {
		t.Fatal(err)
	}
	if readable != "test.high" {
		t.Fatalf("the reader sees %q while the later transaction is open, expected only test.high", readable)
	}

	// The later transaction commits last.
	if err := late.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// Above the pair the cursor now holds, the event of the later transaction
	// is still to come - which is where it is. Above the event number alone it
	// was behind the cursor and nothing would ever have read it.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := pool.QueryRow(ctx, readAbovePair, strconv.FormatInt(earlyXID, 10), highID).
			Scan(&readable); err != nil {
			t.Fatal(err)
		}
		if readable == "test.low" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the reader sees %q above the cursor it settled at, expected test.low", readable)
		}
		time.Sleep(time.Second)
	}
	var lost string
	if err := pool.QueryRow(ctx, readAboveID, highID).Scan(&lost); err != nil {
		t.Fatal(err)
	}
	if lost != "" {
		t.Errorf("a cursor on the event number alone sees %q; the test no longer describes the fault", lost)
	}
}
