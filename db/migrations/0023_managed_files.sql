-- Configuration files managed by the panel.
--
-- The desired state is kept in the panel, not only on the host: without it
-- there is no telling whether the file on the host was changed outside the
-- panel, nor going back to the content from before the change. Content is
-- addressed by digest, so the same configuration on a hundred hosts takes space once.
create table if not exists file_versions (
    sha256     text        primary key,
    content    bytea       not null,
    size_bytes bigint      not null,
    created_at timestamptz not null default now()
);

create table if not exists managed_files (
    host_id        uuid        not null references hosts(id) on delete cascade,
    path           text        not null,
    desired_sha256 text        not null references file_versions(sha256),
    mode           text,
    owner_name     text,
    group_name     text,
    validator      text,
    updated_by     text        not null,
    updated_at     timestamptz not null default now(),
    primary key (host_id, path)
);

-- The change history of a file. A rollback is a return to a specific version,
-- not "undo the last change": the operator picks the content they saw.
create table if not exists managed_file_history (
    id         uuid        primary key default gen_random_uuid(),
    host_id    uuid        not null references hosts(id) on delete cascade,
    path       text        not null,
    sha256     text        not null references file_versions(sha256),
    job_id     uuid        references jobs(id) on delete set null,
    applied_by text        not null,
    applied_at timestamptz not null default now()
);

create index if not exists managed_file_history_path_idx
    on managed_file_history(host_id, path, applied_at desc);
