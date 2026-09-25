//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/ultherego/flotestro/internal/outbox"
)

// The retention of the durable trail keeps every event a consumer has not
// passed. A consumer the installation no longer runs kept its cursor and
// pinned that retention for ever, so an installation that switched its webhook
// off grew outbox_events without end.
func TestARetiredConsumerStopsHoldingTheTrailBack(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	pool := h.database(ctx)

	const name = "integration-retired-consumer"
	if _, err := pool.Exec(ctx, `
		insert into outbox_consumers (name, last_id, active) values ($1, 0, true)
		on conflict (name) do update set last_id = 0, active = true`, name); err != nil {
		t.Fatalf("staging the consumer: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `delete from outbox_consumers where name = $1`, name)
	})

	pinned := func() int64 {
		t.Helper()
		var floor *int64
		if err := pool.QueryRow(ctx,
			`select min(last_id) from outbox_consumers where active`).Scan(&floor); err != nil {
			t.Fatalf("reading the floor: %v", err)
		}
		if floor == nil {
			return -1
		}
		return *floor
	}

	if pinned() != 0 {
		t.Fatalf("a running consumer at the start of the trail does not pin it: %d", pinned())
	}
	if err := outbox.Retire(ctx, pool, name); err != nil {
		t.Fatalf("retiring the consumer: %v", err)
	}
	if pinned() == 0 {
		t.Error("a retired consumer still holds the trail back")
	}

	// Its cursor stays, so switching it on again resumes where it stopped.
	var lastID int64
	var active bool
	if err := pool.QueryRow(ctx,
		`select last_id, active from outbox_consumers where name = $1`, name).Scan(&lastID, &active); err != nil {
		t.Fatal(err)
	}
	if active || lastID != 0 {
		t.Errorf("the retired consumer reads as active=%v cursor=%d", active, lastID)
	}
}
