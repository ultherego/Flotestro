-- The secret store.
--
-- A secret value must not appear in a job, in the audit log or in the
-- inventory. The job carries only a reference; the host fetches the content
-- only when it starts the operation, and only on the basis of a short lease
-- issued for that one job.
--
-- The content lies encrypted with a key that is not in the database: without
-- the key file a database copy is not enough to read anything.
create table if not exists secrets (
    id              uuid        primary key default gen_random_uuid(),
    name            text        not null unique,
    description     text,
    -- The current version; a reference without a version points at it.
    current_version int         not null default 0,
    created_by      text        not null,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    -- A retired secret stays in the table together with its history, but can
    -- no longer be issued: the trace that it existed is part of the audit.
    retired_at      timestamptz
);

create table if not exists secret_versions (
    secret_id  uuid        not null references secrets(id) on delete cascade,
    version    int         not null,
    -- The nonce and the ciphertext are the only place where the value exists.
    nonce      bytea       not null,
    ciphertext bytea       not null,
    -- The plain size serves to show the operator that the version is not empty,
    -- without decrypting anything.
    size_bytes int         not null,
    created_by text        not null,
    created_at timestamptz not null default now(),
    -- A destroyed version loses its ciphertext, not its row: the history is to
    -- show that the version existed and when it stopped.
    destroyed_at timestamptz,
    primary key (secret_id, version)
);

-- A lease is short, single-use and bound to a job and a host.
create table if not exists secret_leases (
    id          uuid        primary key default gen_random_uuid(),
    secret_id   uuid        not null references secrets(id) on delete cascade,
    version     int         not null,
    job_id      uuid        not null references jobs(id) on delete cascade,
    host_id     uuid        not null references hosts(id) on delete cascade,
    issued_at   timestamptz not null default now(),
    expires_at  timestamptz not null,
    redeemed_at timestamptz,
    revoked_at  timestamptz
);

create index if not exists secret_leases_job_idx on secret_leases (job_id);
create index if not exists secret_leases_expiry_idx on secret_leases (expires_at)
    where redeemed_at is null and revoked_at is null;
