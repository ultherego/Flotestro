-- Vendor advisories known to the host from the metadata of its own repositories.
--
-- For Fedora this is the deciding source: it speaks of versions from the same
-- repositories the host takes packages from. The panel does not guess whether
-- a fix is reachable - the host sees it or not.
--
-- Only security advisories about packages this host really has are kept: the
-- full release list is thousands of items, most of which concern things the
-- host does not have.
create table if not exists host_advisories (
    host_id      uuid   not null references hosts(id) on delete cascade,
    advisory_id  text   not null,
    package_name text   not null,
    architecture text   not null default '',
    -- The version that closes the advisory, in the vendor's EVR form.
    fixed_evr    text   not null default '',
    cve_ids      text[] not null default '{}',
    severity     text   not null default '',
    title        text   not null default '',
    issued_at    timestamptz,
    collected_at timestamptz not null default now(),
    primary key (host_id, advisory_id, package_name, architecture)
);

create index if not exists host_advisories_package_idx
    on host_advisories (host_id, package_name);
