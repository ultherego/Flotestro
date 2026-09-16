package jobs

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// CancelQueuedOf takes back the tasks of a campaign that are still in the
// panel: planned, waiting for an approval or queued for a host that has
// not taken them. It returns the identifiers of the tasks it canceled, and
// gives back the budget tokens any of them held, inside the caller's
// transaction - the campaign's own cancel commits the two together, so
// there is no moment at which the campaign is canceled and a task of it
// waits for a host to come online.
//
// A task the agent already holds - leased, dispatched, running - is not
// taken away: the host may be halfway through a package transaction, and
// the campaign records the cancel on the target instead and waits for the
// host to settle. The tasks named in keep are left alone whatever their
// state: the reboot and the verification owed to a host whose change
// landed, which a cancel does not take back either.
func CancelQueuedOf(ctx context.Context, tx pgx.Tx, campaignID, actor, reason string,
	keep []string) ([]string, error) {
	if keep == nil {
		keep = []string{}
	}
	const query = `
		update jobs set state = $2, canceled_by = $3, canceled_at = now(),
		                cancel_reason = $4, wait_reason = '', finished_at = now(), updated_at = now()
		where campaign_id = $1::uuid
		  and state in ('planned', 'awaiting_approval', 'queued')
		  and not (id::text = any($5::text[]))
		returning id`
	canceled, err := collectIDs(tx.Query(ctx, query, campaignID, string(StateCanceled), actor,
		nullable(reason), keep))
	if err != nil {
		return nil, err
	}
	if err := releaseBudgets(ctx, tx, canceled...); err != nil {
		return nil, err
	}
	return canceled, nil
}

// CancelQueuedOf is the store's form of the package function, for callers
// that hold a store rather than a transaction of their own.
func (s *Store) CancelQueuedOf(ctx context.Context, tx pgx.Tx, campaignID, actor, reason string,
	keep []string) ([]string, error) {
	return CancelQueuedOf(ctx, tx, campaignID, actor, reason, keep)
}
