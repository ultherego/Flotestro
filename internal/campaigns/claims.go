package campaigns

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// The claims: which orchestrator drives a campaign, and which one holds
// each of its targets.
//
// Every control-plane instance runs an orchestrator, and nothing but the
// database tells them apart. Without a lease two of them read the same
// target as pending and both dispatch it; with the lease one of them
// drives the campaign, the other waits for the lease to run out. The
// target claims are the second line: a runner that lost the campaign
// still holds targets in its memory, and every write it makes names the
// claim token it read - a token the new runner has moved on.

// openTargetStates are the states of a target that is not settled: what a
// runner claims when it takes a campaign over, and what it keeps claimed
// while it drives it.
const openTargetStates = `('pending', 'planning', 'awaiting_budget', 'queued_offline', 'dispatched',
	'awaiting_lock', 'running', 'rebooting', 'verifying')`

// ClaimRunner takes the runner lease of a campaign for the given runner, or
// renews it when the runner holds it already. It says whether the runner
// holds the lease afterwards and under which token.
//
// A lease is free when nobody holds it or when its holder stopped renewing
// it for the term. The row is taken with skip locked: a runner that finds
// the row locked by another one does not wait for it - the other one is
// either renewing its lease or taking it, and either way this one has no
// business with the campaign on this tick.
func (s *Store) ClaimRunner(ctx context.Context, campaignID, runner string) (int64, bool, error) {
	const query = `
		with candidate as (
			select id from campaigns
			 where id = $1
			   and (runner_id is null or runner_id = $2::uuid or runner_until < now())
			 for update skip locked)
		update campaigns c
		   set runner_id    = $2::uuid,
		       runner_until = now() + make_interval(secs => $3),
		       runner_token = case when c.runner_id is distinct from $2::uuid
		                           then c.runner_token + 1 else c.runner_token end
		  from candidate
		 where c.id = candidate.id
		returning c.runner_token`
	var token int64
	err := s.pool.QueryRow(ctx, query, campaignID, runner, RunnerLeaseTerm.Seconds()).Scan(&token)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return token, true, nil
}

// RenewRunner extends the lease the runner holds. It returns ErrLeaseLost
// when the lease is held by somebody else now - or by this runner under
// another token, which means it lost the lease and took it again since.
func (s *Store) RenewRunner(ctx context.Context, campaign *Campaign) error {
	tag, err := s.pool.Exec(ctx, `
		update campaigns
		   set runner_until = now() + make_interval(secs => $4)
		 where id = $1 and runner_id = $2::uuid and runner_token = $3`,
		campaign.ID, campaign.RunnerID, campaign.RunnerToken, RunnerLeaseTerm.Seconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}

// ReleaseRunner gives the lease back when the orchestrator stops, so the
// next instance takes the campaign at once rather than after the term.
// Only the holder under its own token releases anything.
func (s *Store) ReleaseRunner(ctx context.Context, campaign *Campaign) error {
	_, err := s.pool.Exec(ctx, `
		update campaigns set runner_id = null, runner_until = null
		 where id = $1 and runner_id = $2::uuid and runner_token = $3`,
		campaign.ID, campaign.RunnerID, campaign.RunnerToken)
	return err
}

// AdoptTargets puts every open target of the campaign under the runner's
// claim and renews the claims it holds already.
//
// A target held by another runner gets a new claim token, and the budget
// lease it holds is re-fenced with that token in the same transaction: from
// this moment the old runner's writes to the row and its renewals of the
// lease touch nothing, while the new runner renews and releases under the
// token it reads back with the target. Adoption happens on every tick of
// the runner that holds the campaign, so a target left behind by a dead
// runner is taken over within one tick of the lease changing hands.
func (s *Store) AdoptTargets(ctx context.Context, campaignID, runner string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		with adopted as (
			update campaign_targets t
			   set claimed_by  = $2::uuid,
			       claim_token = t.claim_token + 1,
			       claim_until = now() + make_interval(secs => $3),
			       revision    = t.revision + 1
			 where t.campaign_id = $1 and t.claimed_by is distinct from $2::uuid
			   and t.state in `+openTargetStates+`
			returning t.id, t.claim_token)
		update budget_leases l
		   set fencing_token = a.claim_token
		  from adopted a
		 where l.owner = a.id::text`,
		campaignID, runner, RunnerLeaseTerm.Seconds()); err != nil {
		return fmt.Errorf("adopting the targets of the campaign: %w", err)
	}
	// The claims renewed are those of the hosts carrying a task: a few
	// rows per campaign. A host in the queue is claimed when it is
	// launched and holds no live claim before that, so a campaign of a
	// thousand waiting hosts is not rewritten on every tick.
	if _, err := tx.Exec(ctx, `
		update campaign_targets
		   set claim_until = now() + make_interval(secs => $3)
		 where campaign_id = $1 and claimed_by = $2::uuid
		   and state in ('planning', 'dispatched', 'awaiting_lock', 'running', 'rebooting', 'verifying')`,
		campaignID, runner, RunnerLeaseTerm.Seconds()); err != nil {
		return fmt.Errorf("renewing the claims of the campaign: %w", err)
	}
	return tx.Commit(ctx)
}

// claimedTarget is a target the runner has just claimed for a launch: its
// identifier and the revision and token the row carries now.
type claimedTarget struct {
	ID         string
	Revision   int64
	ClaimToken int64
}

// ClaimWaveTargets claims up to limit waiting targets of one wave for the
// runner, in rollout order, and returns them with the revision and the
// token the rows carry now.
//
// The candidates are the hosts in the queue whose claim is free - never
// claimed, claimed by this runner, or claimed by one that stopped renewing
// - and they are taken with skip locked, so two runners that reach the
// same wave at once take different hosts rather than the same one. The
// state does not change with the claim: the claim says who may start the
// host, the state says where the host stands, and a host claimed and not
// started stays in the queue for the next pass.
func (s *Store) ClaimWaveTargets(ctx context.Context, campaignID string, wave int,
	runner string, limit int) ([]claimedTarget, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		with candidate as (
			select id from campaign_targets
			 where campaign_id = $1 and wave = $2 and state in ('pending', 'awaiting_budget')
			   and (claimed_by = $3::uuid or claim_until is null or claim_until < now())
			 order by position
			 for update skip locked
			 limit $4)
		update campaign_targets t
		   set claimed_by  = $3::uuid,
		       claim_token = t.claim_token + 1,
		       claim_until = now() + make_interval(secs => $5),
		       revision    = t.revision + 1
		  from candidate c
		 where t.id = c.id
		returning t.id, t.revision, t.claim_token`,
		campaignID, wave, runner, limit, RunnerLeaseTerm.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	claimed := []claimedTarget{}
	for rows.Next() {
		var c claimedTarget
		if err := rows.Scan(&c.ID, &c.Revision, &c.ClaimToken); err != nil {
			return nil, err
		}
		claimed = append(claimed, c)
	}
	return claimed, rows.Err()
}

// LockForLaunch locks the campaign row inside the caller's transaction and
// checks that the campaign may start a host now, under the lease the
// runner holds.
//
// The lock is what makes a pause exact: a pause is an update of the same
// row, so it either committed before this lock - and the state read here
// says pausing, and no task is created - or it waits for this transaction
// to commit, and then finds the host dispatched and counts it among the
// hosts it waits for. There is no third case in which the task exists and
// nobody follows it.
func (s *Store) LockForLaunch(ctx context.Context, tx pgx.Tx, campaign *Campaign) error {
	var state, runner string
	var token int64
	err := tx.QueryRow(ctx, `
		select state, coalesce(runner_id::text, ''), runner_token
		  from campaigns where id = $1 for share`, campaign.ID).Scan(&state, &runner, &token)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if runner != campaign.RunnerID || token != campaign.RunnerToken {
		return ErrLeaseLost
	}
	if !State(state).Launching() {
		return fmt.Errorf("%w: the campaign is %s now and starts no host", ErrConcurrentTransition, state)
	}
	return nil
}
