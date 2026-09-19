package outbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Record writes one event on the trail inside the caller's transaction.
func Record(ctx context.Context, tx pgx.Tx, aggregate, aggregateID, eventType string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding the %s event: %w", eventType, err)
	}
	if _, err := tx.Exec(ctx, `
		insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
		values ($1, $2::uuid, $3, $4::jsonb)`,
		aggregate, aggregateID, eventType, string(body)); err != nil {
		return fmt.Errorf("recording the %s event: %w", eventType, err)
	}
	return nil
}
