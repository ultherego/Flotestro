-- The remediation plan as a durable entity.
--
-- A multi-step remediation does not fit in one job: the steps must go one
-- after another, each with its own approval, and what was done before the
-- error must be visible. Without a table the panel would not know after a
-- restart which steps already went, and the operator would see a handful of unrelated jobs.
create table if not exists remediation_plans (
    id                uuid        primary key default gen_random_uuid(),
    host_id           uuid        not null references hosts(id) on delete cascade,
    -- The fingerprint binds the plan to the host state the operator looked at,
    -- and the canonicalisation version says by which rules it was computed.
    plan_hash         text        not null,
    plan_hash_version int         not null,
    reason            text        not null,
    created_by        text        not null,
    -- Stopping after a failure is the default: the next steps assume the
    -- previous ones succeeded.
    stop_on_failure   boolean     not null default true,
    state             text        not null
                                  check (state in ('running', 'succeeded', 'failed', 'stopped')),
    created_at        timestamptz not null default now(),
    finished_at       timestamptz
);

create table if not exists remediation_steps (
    id              uuid        primary key default gen_random_uuid(),
    plan_id         uuid        not null references remediation_plans(id) on delete cascade,
    -- The position is a dependency: a step starts only once the previous one succeeded.
    position        int         not null,
    check_id        text        not null,
    check_version   int         not null,
    action_type     text        not null,
    payload         jsonb       not null,
    -- The host resource lock class. Two steps of the same class cannot go in
    -- parallel - and they do not, because the plan runs one step at a time.
    lock_class      text        not null default '',
    -- The step that ends the plan: after a reboot the host state has to be assessed anew.
    requires_reboot boolean     not null default false,
    job_id          uuid        references jobs(id) on delete set null,
    state           text        not null
                                check (state in ('pending', 'running', 'succeeded', 'failed', 'skipped')),
    reason          text,
    started_at      timestamptz,
    finished_at     timestamptz,
    unique (plan_id, position)
);

create index if not exists remediation_plans_host_idx
    on remediation_plans (host_id, created_at desc);
-- The runner asks for plans in progress at every cycle.
create index if not exists remediation_plans_running_idx
    on remediation_plans (state) where state = 'running';
