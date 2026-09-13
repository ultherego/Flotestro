-- The full list of a host's installed packages.
--
-- The panel keeps it, because without it the vulnerability question cannot
-- be answered: the distribution security tracker speaks of a source package
-- and a version, not of a host. The list is fetched on demand - the inventory
-- carries only the digest, so the panel knows when its copy stopped describing the host.
--
-- There are no rows for a host not asked yet. That is the state "unknown",
-- not "clean host" - and it must be shown that way.
create table if not exists host_packages (
    host_id       uuid        not null references hosts(id) on delete cascade,
    name          text        not null,
    architecture  text        not null default '',
    -- An empty epoch means a package without an epoch; zero and no epoch mean
    -- the same for comparison, but differ in the record.
    epoch         text        not null default '',
    version       text        not null,
    release       text        not null default '',
    -- The source package: Debian tracks security by exactly that, and one
    -- source gives a dozen binaries.
    source_name    text       not null default '',
    source_version text       not null default '',
    source_rpm     text       not null default '',
    vendor         text       not null default '',
    repository_id  text       not null default '',
    module_stream  text       not null default '',
    primary key (host_id, name, architecture, version, release)
);

create index if not exists host_packages_source_idx on host_packages (source_name);
create index if not exists host_packages_name_idx on host_packages (name);

-- The list state: the digest of what the panel holds and what the host last
-- reported. A mismatch between them means the copy is stale - and then the
-- vulnerability assessment of this host is incomplete, not empty.
create table if not exists host_package_state (
    host_id            uuid        primary key references hosts(id) on delete cascade,
    digest             text        not null default '',
    package_count      int         not null default 0,
    collected_at       timestamptz,
    job_id             uuid        references jobs(id) on delete set null,
    unavailable_reason text        not null default ''
);
