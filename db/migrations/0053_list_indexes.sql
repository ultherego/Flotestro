-- The indexes behind the fleet lists.
--
-- The lists are filtered and paged in the database, because the panel never
-- pulls the whole fleet into the browser to filter it. That promise holds
-- only while the database answers "the failed jobs of this campaign since
-- Monday" from an index rather than a scan of every job ever ordered.

-- Keyset paging of the task list goes by (created_at, id); the state and
-- host indexes from the first migration do not cover that order.
create index if not exists jobs_created_idx on jobs (created_at desc, id desc);
create index if not exists jobs_action_idx on jobs (action_type, created_at desc, id desc);
create index if not exists jobs_actor_idx on jobs (created_by, created_at desc, id desc);
create index if not exists jobs_campaign_idx on jobs (campaign_id, created_at desc, id desc)
    where campaign_id is not null;
create index if not exists jobs_error_idx on jobs (result_error_code, created_at desc, id desc)
    where result_error_code is not null;

-- The audit trail: the time index exists, the key of the page also needs the
-- identifier, and "what did this action do" and "the denials" are the two
-- questions the trail is read for.
create index if not exists audit_events_key_idx on audit_events (occurred_at desc, id desc);
create index if not exists audit_events_action_idx on audit_events (action, occurred_at desc, id desc);
create index if not exists audit_events_outcome_idx on audit_events (outcome, occurred_at desc, id desc)
    where outcome <> 'success';

-- The host list: the page key, the owner filter and the lifecycle filter. The
-- lifecycle index from migration 0037 leaves out the active hosts, which is
-- what the filter asks for most often.
create index if not exists hosts_page_idx on hosts (hostname, id);
create index if not exists hosts_owner_idx on hosts (owner) where owner is not null;
create index if not exists hosts_lifecycle_state_idx on hosts (lifecycle_state);

-- The dashboard counts the hosts whose agent certificate is about to run out.
create index if not exists agent_certificates_live_idx on agent_certificates (host_id, not_after desc)
    where revoked_at is null;

-- The free-text search looks for a fragment anywhere in the hostname, the
-- address, the machine identifier or the owner. A btree cannot serve
-- "contains"; a trigram index can, but it needs the pg_trgm extension, and
-- creating one takes a right the panel's database role may not have. The
-- search works without the index - it only scans - so a missing extension
-- is a notice in the log, not a panel that refuses to start.
do $$
begin
    create extension if not exists pg_trgm;
    create index if not exists hosts_hostname_trgm_idx
        on hosts using gin (hostname gin_trgm_ops);
    create index if not exists hosts_management_address_trgm_idx
        on hosts using gin (management_address gin_trgm_ops);
    create index if not exists hosts_machine_id_trgm_idx
        on hosts using gin (machine_id gin_trgm_ops);
    create index if not exists hosts_owner_trgm_idx
        on hosts using gin (owner gin_trgm_ops);
exception when others then
    raise notice 'the host search runs without trigram indexes (pg_trgm unavailable): %', sqlerrm;
end $$;
