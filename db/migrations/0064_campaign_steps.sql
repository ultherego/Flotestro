-- The executable steps of a campaign target, one row each.
--
-- A target so far carried its tasks as columns: the plan, the change, the
-- reboot and the health check. Four columns answer "which task" but not
-- "how did this step go, when, on which attempt and why did it not run" -
-- and a composite remediation or a compensation has no column at all. The
-- step row is the durable record of one executable step of one host: what
-- it depended on, which plan it ran under, which task carried it, how many
-- times it was ordered and how it ended. The target columns keep working;
-- the steps are written next to them, in the same transaction as the
-- target's transition, so a step cannot be started without the target
-- knowing and a target cannot be settled with its step left open.
create table if not exists campaign_steps (
    id          uuid        primary key default gen_random_uuid(),
    campaign_id uuid        not null references campaigns (id) on delete cascade,
    target_id   uuid        not null references campaign_targets (id) on delete cascade,
    host_id     uuid        not null references hosts (id) on delete cascade,
    -- The kinds of step the engine has. A plan computes the diff, execute
    -- carries the change, reboot and verify follow it when the policy asks,
    -- compensate is the approved way back after a failure.
    step_key    text        not null
                    check (step_key in ('plan', 'execute', 'reboot', 'verify', 'compensate')),
    -- The step this one waited for; null for the first step of the host.
    depends_on  text
                    check (depends_on is null
                           or depends_on in ('plan', 'execute', 'reboot', 'verify', 'compensate')),
    -- The digest of the plan the step ran under. The plan step has none:
    -- it is the step that computes the digest. A campaign without a planner
    -- has none either. An empty string would be a digest of nothing.
    plan_hash   text        check (plan_hash is null or plan_hash <> ''),
    state       text        not null default 'pending'
                    check (state in ('pending', 'running', 'succeeded', 'failed', 'skipped', 'canceled')),
    -- The task that carried the latest attempt; null for a step settled
    -- without a task and for a remediation, which runs its own plan.
    job_id      uuid        references jobs (id) on delete set null,
    attempts    integer     not null default 0 check (attempts >= 0),
    -- Why the step ended the way it did. A step that did not run has to say
    -- why; a step passed over in silence looks like a forgotten step.
    reason      text,
    created_at  timestamptz not null default now(),
    started_at  timestamptz,
    finished_at timestamptz,
    updated_at  timestamptz not null default now(),
    constraint campaign_steps_reason_present
        check (state not in ('failed', 'skipped', 'canceled') or coalesce(reason, '') <> '')
);

comment on table campaign_steps is
    'One executable step of one campaign target: its dependency, plan, task, attempts and outcome. Written with the target transition.';
comment on column campaign_steps.plan_hash is
    'The digest of the plan the step ran under; null for the plan step itself and for a campaign without a planner.';
comment on column campaign_steps.attempts is
    'How many times the step was ordered; a step ordered again after a reconnect is the same step on its next attempt.';

-- One step of one kind per target and plan. A step ordered a second time
-- for the same plan is another attempt of the same row, never a second
-- row. Nulls count as equal here on purpose: a campaign without a planner
-- has exactly one execute step per host, not one per insert.
create unique index if not exists campaign_step_once
    on campaign_steps (target_id, step_key, plan_hash) nulls not distinct;

create index if not exists campaign_steps_campaign_state_idx
    on campaign_steps (campaign_id, state);
create index if not exists campaign_steps_target_idx
    on campaign_steps (target_id);
