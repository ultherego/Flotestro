-- Three remediation axes instead of one word, the package origin and a
-- separate cycle of vendor advisories.
--
-- One word "fix" promised more than the panel checked: "available" meant
-- only that the vendor released a newer version somewhere. Whether that
-- version lies in this host's repository and whether the transaction passes
-- are two other questions - and something else answers them.
alter table vuln_findings drop column if exists remediation;

alter table vuln_findings
    -- What the vendor released. The advisory answers.
    add column if not exists vendor_fix           text not null default 'unknown',
    -- Whether that version is visible in the host repositories. The repository
    -- metadata answers - and only for the hosts it is available for.
    add column if not exists repository_candidate text not null default 'unknown',
    -- Whether it can be installed now. Only the package plan answers: it alone
    -- sees holds, exclusions and module conflicts.
    add column if not exists transaction_state    text not null default 'unknown',
    -- The version really compared with the advisory and where it comes from.
    -- Debian tracks security by source package, and the binary version may
    -- differ: a rebuild appends a suffix and comes out higher than the source
    -- with the same code.
    add column if not exists comparison_version   text not null default '',
    add column if not exists comparison_basis     text not null default '',
    -- Whose package it is. Without this a package from a foreign repository
    -- would count as covered by the distribution vendor's advisories.
    add column if not exists package_origin       text not null default '',
    -- The digest of the advisory set that decided. The set changes also when
    -- not a single package changed on the host.
    add column if not exists advisory_digest      text not null default '';

do $$
begin
    if exists (select 1 from information_schema.columns
               where table_name = 'vuln_host_state' and column_name = 'affected_fixable') then
        alter table vuln_host_state rename column affected_fixable to affected_with_vendor_fix;
    end if;
end $$;

alter table vuln_host_state
    add column if not exists advisory_digest text not null default '',
    -- Four counters instead of one: one vulnerability touches several
    -- packages, one advisory carries several CVEs, and "1354 findings" does
    -- not say how many really different matters there are to close.
    add column if not exists unique_cves       int not null default 0,
    add column if not exists unique_advisories int not null default 0,
    add column if not exists affected_packages int not null default 0,
    -- The reason there are no vendor advisories. A metadata read error must
    -- not look like a host without advisories.
    add column if not exists advisories_reason text not null default '';

-- The package origin: APT does not record the vendor with the package, so it
-- is taken from the repository the installed version came from.
alter table host_packages
    add column if not exists origin       text not null default '',
    add column if not exists origin_class text not null default '';

-- The state of the vendor advisories known to the host.
--
-- Separate from the package list state, because it is a separate source and
-- a separate cycle: the vendor releases fixes also when not a single package
-- changed on the host. Without this the panel would refresh the advisories
-- only at a list change - that is sometimes never.
create table if not exists host_advisory_state (
    host_id            uuid        primary key references hosts(id) on delete cascade,
    digest             text        not null default '',
    advisory_count     int         not null default 0,
    collected_at       timestamptz,
    job_id             uuid        references jobs(id) on delete set null,
    unavailable_reason text        not null default ''
);
