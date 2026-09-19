-- The pass that could not run is written down on the host it concerns.
--
-- Until now a read that failed - the package list, the host's own findings,
-- the findings of the feed - made the scheduler skip the host and leave the
-- previous verdict standing. That is the right thing to do: an assessment
-- made with nothing would say the host is clean. But nothing recorded that it
-- had happened, so a host whose assessment could not be refreshed for days
-- looked exactly like one judged a minute ago.

alter table vuln_host_state
    add column if not exists evaluation_failed_reason text not null default '',
    add column if not exists evaluation_failed_source text not null default '',
    add column if not exists evaluation_failed_at timestamptz,
    add column if not exists last_successful_at timestamptz;

comment on column vuln_host_state.evaluation_failed_reason is
    'The typed code of the last pass that could not be computed; empty when the last pass succeeded.';
comment on column vuln_host_state.evaluation_failed_source is
    'Which read failed: package_list_state, package_list, host_advisory_state, host_advisories, feed_advisories or save.';
comment on column vuln_host_state.evaluation_failed_at is
    'When that pass was attempted.';
comment on column vuln_host_state.last_successful_at is
    'When the verdict in this row was last computed in full; null for a verdict written before this migration.';

-- A verdict that exists was computed at some point, and that point is
-- evaluated_at. Saying "never" for every host already assessed would raise a
-- fleet-wide alarm for a column that was simply not kept before.
update vuln_host_state
set last_successful_at = evaluated_at
where last_successful_at is null and evaluated_at is not null;

-- The fleet screen asks "which hosts could not be assessed": that is a scan
-- over the few rows that carry a reason.
create index if not exists vuln_host_state_evaluation_failed_idx
    on vuln_host_state (evaluation_failed_at desc)
    where evaluation_failed_reason <> '';
