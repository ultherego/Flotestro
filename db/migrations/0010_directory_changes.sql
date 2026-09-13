-- A directory change is one Flotestro business transaction, but may consist
-- of several FreeIPA operations. Every phase has its own result, because a
-- partial success must not be presented as a completed success.

create table directory_changes (
    id                uuid        primary key,
    action_type       text        not null,
    payload           jsonb       not null,
    -- The hash of the plan approved by a human. A content swap after
    -- approval is detectable.
    payload_hash      bytea       not null,
    -- The impact preview: what the change will do before anything happens.
    plan              jsonb       not null default '{}'::jsonb,

    state             text        not null
                          check (state in ('planned', 'awaiting_approval', 'running',
                                           'succeeded', 'partially_applied', 'failed',
                                           'canceled')),
    requires_approval boolean     not null default true,
    approved_by       text,
    approved_at       timestamptz,
    canceled_by       text,
    canceled_at       timestamptz,

    -- The result of every phase separately. Without it there is no telling what
    -- managed to change before the error.
    phases            jsonb       not null default '[]'::jsonb,
    result_message    text,

    created_by        text        not null,
    request_id        text,
    started_at        timestamptz,
    finished_at       timestamptz,
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now()
);

create index directory_changes_state_idx on directory_changes (state, created_at desc);
create index directory_changes_actor_idx on directory_changes (created_by, created_at desc);

-- The local denial marker. Set before the lock in the directory, so that
-- revoking access works at once, before the change manages to propagate.
alter table principals add column denied_at timestamptz;
alter table principals add column denied_reason text;

create index principals_denied_idx on principals (denied_at) where denied_at is not null;
