-- Local accounts seen on the host. The table mirrors the host state and is
-- not the source of truth about the accounts: the truth is /etc/passwd on the
-- host, and the panel only remembers the last observation so it can be browsed and filtered.
--
-- The module is meant for installations without a directory. Where FreeIPA or
-- another directory runs, people's accounts come from the directory and the
-- panel does not duplicate them; the source column tells these two worlds apart.
create table host_local_accounts (
    host_id            uuid        not null references hosts (id) on delete cascade,
    name               text        not null,
    uid                bigint      not null,
    gid                bigint      not null,
    home               text,
    shell              text,
    gecos              text,
    -- local | directory | system
    source             text        not null,
    groups             text[]      not null default '{}',
    -- NULL means an undetermined state: the helper may be unavailable, and then
    -- "unlocked" would be a made-up fact.
    locked             boolean,
    ssh_keys           jsonb       not null default '[]'::jsonb,
    unavailable_reason text,
    observed_at        timestamptz not null default now(),
    primary key (host_id, name)
);

create index host_local_accounts_source_idx on host_local_accounts (source, name);
-- Accounts without an SSH key and without a lock are reachable by password only
-- or not at all; that is the first thing an audit looks for in an installation without a directory.
create index host_local_accounts_keyless_idx on host_local_accounts (host_id)
    where source = 'local' and ssh_keys = '[]'::jsonb;
