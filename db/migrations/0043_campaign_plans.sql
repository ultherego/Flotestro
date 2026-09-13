-- Per-host plans for campaigns.
--
-- Two hosts picked by the same order almost never have the same diff: a
-- different package set, different versions, different dependencies. A
-- campaign that approves one payload therefore approves a change nobody saw.
-- The plan is made separately for every host, and the consent concerns the whole set.
create table if not exists campaign_plans (
    campaign_id uuid        not null references campaigns(id) on delete cascade,
    host_id     uuid        not null references hosts(id) on delete cascade,
    plan_hash   text        not null,
    plan        jsonb       not null default '{}'::jsonb,
    computed_at timestamptz not null default now(),
    primary key (campaign_id, host_id)
);

comment on table campaign_plans is
    'A plan computed on one host. The fingerprint binds the consent to exactly this diff.';

-- The fingerprint of the whole plan set. It enters the approval fingerprint,
-- so a plan recomputed on a different host state invalidates the consent.
alter table campaigns
    add column if not exists plan_set_hash text not null default '';

-- The host's planning job. A separate column, because the plan and the change
-- are two different operations of the same target.
alter table campaign_targets
    add column if not exists plan_job_id uuid references jobs(id);

-- New states: the campaign and the host compute the plan before anything changes.
alter table campaigns drop constraint if exists campaigns_state_check;
alter table campaigns add constraint campaigns_state_check
    check (state in ('planning', 'planned', 'awaiting_approval', 'canary', 'running',
                     'paused', 'completed', 'failed', 'canceled'));

alter table campaign_targets drop constraint if exists campaign_targets_state_check;
alter table campaign_targets add constraint campaign_targets_state_check
    check (state in ('pending', 'planning', 'running', 'rebooting', 'verifying',
                     'succeeded', 'failed', 'skipped', 'canceled'));
