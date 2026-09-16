-- Revisions, claims and fencing for the campaigns.
--
-- Until now every write to a campaign or to one of its targets was an
-- unconditional update: two control-plane instances each ran an
-- orchestrator, both read the same target as pending, and both could
-- dispatch it; a pause committed between the read and the write changed
-- nothing about the write. From here on every row carries a revision, and a
-- state is written only against the revision the writer read. A write that
-- lost the race fails, and the writer reads the row again instead of
-- repeating a decision made on a stale picture.
alter table campaigns
    add column if not exists revision bigint not null default 1,
    -- The runner lease: one orchestrator drives a campaign at a time. The
    -- holder renews the lease while it works; a dead holder loses it after
    -- the term, and the next one takes over with a new token, so a write
    -- from the old holder that arrives late fails on the token.
    add column if not exists runner_id uuid,
    add column if not exists runner_token bigint not null default 0,
    add column if not exists runner_until timestamptz;

alter table campaign_targets
    add column if not exists revision bigint not null default 1,
    -- The claim: which runner holds the target and under which token. The
    -- token also fences the target's budget lease, so a runner that lost
    -- the target cannot renew or release the tokens of the runner that
    -- holds it now.
    add column if not exists claimed_by uuid,
    add column if not exists claim_token bigint not null default 0,
    add column if not exists claim_until timestamptz,
    -- A cancel ordered while the host was carrying its task: the task is
    -- not taken away from the host, but the moment the operator asked is
    -- recorded, and the acknowledgement of the agent will settle it.
    add column if not exists cancel_requested_at timestamptz,
    -- When the target reached a terminal state. finished_at says the same
    -- for the host's work; settled_at is the moment the campaign stopped
    -- waiting for it, which a late result is judged against.
    add column if not exists settled_at timestamptz;

-- The claim looks for targets of one wave that are not settled and whose
-- claim ran out; the settled rows are the bulk of a finished campaign and
-- are left out of the index.
create index if not exists campaign_targets_claimable
    on campaign_targets (campaign_id, wave, state, claim_until)
    where state in ('pending', 'awaiting_budget', 'planning', 'dispatched', 'awaiting_lock',
                    'running', 'rebooting', 'verifying');

-- pausing: an operator or a threshold stopped the campaign while hosts
-- were still carrying their tasks. Nothing new starts; the hosts under way
-- settle, their leases are renewed meanwhile, and the campaign is paused
-- once none is in flight. Until now the campaign said "paused" at once
-- and the orchestrator stopped looking at it: the leases of the running
-- hosts expired, and their results were not read until the resume.
alter table campaigns drop constraint if exists campaigns_state_check;
alter table campaigns add constraint campaigns_state_check
    check (state in ('planning', 'planned', 'awaiting_approval', 'canary', 'manual_gate',
                     'running', 'pausing', 'paused', 'canceling',
                     'completed', 'completed_with_issues', 'failed', 'plan_failed',
                     'expired', 'canceled'));

-- The fencing token of a budget lease. A campaign target takes its tokens
-- under the claim token it holds; a renewal or a release from a runner
-- that no longer holds the claim carries the old token and touches
-- nothing. A single job takes its tokens without a token and keeps its
-- path: the scheduler is the one owner of a job's lease.
alter table budget_leases
    add column if not exists fencing_token bigint not null default 0;
