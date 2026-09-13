-- Enriching the findings with upstream data: CVSS and the vulnerability description.
--
-- A separate table, not columns on the finding, because it is data of another
-- kind and another source. The distribution vendor decides whether a package
-- is vulnerable and which version closes that; NVD has nothing to say about
-- it - its version ranges do not cover backported fixes. It can say instead
-- how dangerous the vulnerability itself is, and that is the only thing the panel takes from it.
create table if not exists vuln_cve_details (
    cve           text primary key,
    source        text not null,
    cvss_score    double precision,
    cvss_severity text not null default '',
    cvss_vector   text not null default '',
    cvss_version  text not null default '',
    summary       text not null default '',
    published_at  timestamptz,
    modified_at   timestamptz,
    fetched_at    timestamptz not null default now()
);

-- The synchronisation state: since when to ask for changes. Without it every
-- panel start would fetch the whole set anew - and that is nearly four hundred
-- thousand entries and two hundred requests to a service that watches for it.
create table if not exists vuln_enrichment_state (
    source        text primary key,
    last_modified timestamptz,
    entries       integer not null default 0,
    updated_at    timestamptz not null default now(),
    error         text not null default ''
);
