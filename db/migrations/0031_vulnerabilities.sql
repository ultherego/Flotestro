-- The vulnerability correlator.
--
-- The distribution vendor's security tracker decides, not the upstream feed:
-- backported fixes have version numbers no NVD range covers, so comparing
-- against it gives false alarms one way and misses the other.
--
-- A feed snapshot is immutable and has a digest: an assessment that cannot be
-- tied to specific data can be neither repeated nor defended.
create table if not exists vuln_snapshots (
    id                 uuid        primary key default gen_random_uuid(),
    provider           text        not null,
    digest             text        not null,
    -- Releases lists the releases the snapshot covers. That is where the
    -- answer "the feed does not cover this release" comes from - different from "no vulnerabilities".
    releases           text[]      not null default '{}',
    advisory_count     int         not null default 0,
    fetched_at         timestamptz not null default now(),
    source_modified_at timestamptz,
    etag               text        not null default '',
    -- There is one active snapshot per provider. A failed import does not
    -- replace the previous one: better to assess with older data and say it
    -- is older than not assess at all.
    active  boolean not null default false,
    error   text    not null default '',
    unique (provider, digest)
);

create unique index if not exists vuln_snapshots_active_idx
    on vuln_snapshots (provider) where active;

create table if not exists vuln_advisories (
    snapshot_id    uuid   not null references vuln_snapshots(id) on delete cascade,
    provider       text   not null,
    advisory_id    text   not null,
    cve_ids        text[] not null default '{}',
    distribution   text   not null,
    release        text   not null,
    -- The correlation key: the tracker speaks of the source package, the host has binaries.
    source_package text   not null,
    binary_package text   not null default '',
    -- An empty fixed version means a vulnerability without a fix: the package
    -- is vulnerable and there is nothing to fix it with.
    fixed_version  text   not null default '',
    status         text   not null,
    vendor_severity text  not null default '',
    title          text   not null default '',
    url            text   not null default '',
    published_at   timestamptz,
    primary key (snapshot_id, advisory_id, release, source_package, binary_package)
);

create index if not exists vuln_advisories_lookup_idx
    on vuln_advisories (snapshot_id, distribution, release, source_package);

-- The findings for hosts. Each carries the snapshot digest and the package list
-- digest that decided it: without them there is no knowing what the answer concerns.
create table if not exists vuln_findings (
    host_id           uuid   not null references hosts(id) on delete cascade,
    provider          text   not null,
    advisory_id       text   not null,
    cve_ids           text[] not null default '{}',
    distribution      text   not null default '',
    release           text   not null default '',
    source_package    text   not null default '',
    binary_package    text   not null default '',
    architecture      text   not null default '',
    installed_version text   not null default '',
    fixed_version     text   not null default '',
    -- Three states, not two: "unknown" is an answer, not the absence of one,
    -- and always has a reason code.
    state             text   not null,
    reason_code       text   not null default '',
    remediation       text   not null default 'unknown',
    vendor_severity   text   not null default '',
    snapshot_digest   text   not null default '',
    inventory_digest  text   not null default '',
    comparator_version text  not null default '',
    evaluated_at      timestamptz not null default now(),
    primary key (host_id, provider, advisory_id, binary_package, architecture)
);

create index if not exists vuln_findings_state_idx on vuln_findings (state, vendor_severity);
create index if not exists vuln_findings_host_idx on vuln_findings (host_id, state);

-- The host assessment state: what it was decided with, when and how well covered.
--
-- Coverage is as important here as the number of findings. A host without
-- findings and a host the feed does not cover look the same on the counter -
-- and only this table tells them apart.
create table if not exists vuln_host_state (
    host_id          uuid        primary key references hosts(id) on delete cascade,
    distribution     text        not null default '',
    release          text        not null default '',
    provider         text        not null default '',
    snapshot_digest  text        not null default '',
    inventory_digest text        not null default '',
    packages_total   int         not null default 0,
    packages_covered int         not null default 0,
    affected         int         not null default 0,
    -- A vulnerability with a fix and one without lead to entirely different
    -- decisions: the first is to be installed today, the second is a risk
    -- assessment. Glued into one number they give a wall nobody will
    -- read.
    affected_fixable int         not null default 0,
    affected_no_fix  int         not null default 0,
    unknown          int         not null default 0,
    coverage_reason  text        not null default '',
    evaluated_at     timestamptz
);
