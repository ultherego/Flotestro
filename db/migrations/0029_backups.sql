-- Backups: definitions and run history.
--
-- Backup data does not flow through the panel and is not in this database.
-- Only metadata is here: what is backed up, where to, how long it is kept and
-- when the last copy succeeded. A panel through which the copies of a hundred
-- hosts flowed would be a bottleneck and the most interesting target in the whole installation.
--
-- Credentials are secret names, not values: the repository password and the
-- tool's environment variables live in the store and only there.
create table if not exists backup_definitions (
    id             uuid        primary key default gen_random_uuid(),
    host_id        uuid        not null references hosts(id) on delete cascade,
    name           text        not null,
    tool           text        not null,
    repository     text        not null default '',
    paths          text[]      not null default '{}',
    excludes       text[]      not null default '{}',
    tags           text[]      not null default '{}',
    keep_last      int         not null default 0,
    keep_daily     int         not null default 0,
    keep_weekly    int         not null default 0,
    keep_monthly   int         not null default 0,
    prune          boolean     not null default false,
    runbook        text        not null default '',
    -- Consent to initialise the repository at the first copy. Without it the
    -- host creates nothing: a repository created by a typo in the address
    -- looks like a backup that works.
    initialize     boolean     not null default false,
    -- The name of the secret with the repository password and the mapping of
    -- environment variables to secrets. Names, not values.
    password_secret text       not null default '',
    env_secrets    jsonb       not null default '{}'::jsonb,
    note           text        not null default '',
    created_by     text        not null,
    created_at     timestamptz not null default now(),
    updated_by     text        not null,
    updated_at     timestamptz not null default now(),
    unique (host_id, name)
);

create index if not exists backup_definitions_host_idx on backup_definitions (host_id);

-- The run history. A definition may disappear and the history stays: that a
-- copy was made and when it last succeeded is a fact that deleting the
-- definition does not undo.
create table if not exists backup_runs (
    id               uuid        primary key default gen_random_uuid(),
    host_id          uuid        not null references hosts(id) on delete cascade,
    definition       text        not null,
    -- The kind: plan, run, verify or restore.
    kind             text        not null,
    job_id           uuid        references jobs(id) on delete set null,
    outcome          text        not null,
    snapshot_id      text        not null default '',
    bytes_added      bigint,
    total_bytes      bigint,
    files_new        bigint,
    duration_seconds double precision,
    -- Fields from the plan: how many copies are in the repository, how much
    -- they take and when the newest was made.
    snapshots        int,
    repository_size  bigint,
    last_success_at  timestamptz,
    message          text        not null default '',
    started_by       text        not null default '',
    recorded_at      timestamptz not null default now()
);

create index if not exists backup_runs_host_idx
    on backup_runs (host_id, definition, recorded_at desc);
