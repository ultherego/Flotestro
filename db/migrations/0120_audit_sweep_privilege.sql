-- The audit trail is append-only through a trigger, and the retention sweep is
-- the one exception: the trigger lets a delete through when the transaction
-- carries a marker the sweep sets. The marker is an ordinary setting, though,
-- so any session holding the connection string could set it for itself and
-- delete the trail. The trigger asked whether the marker was there, never who
-- had set it.
--
-- Two things change. The sweep becomes the only way to set that marker from
-- outside: it runs as its owner with a fixed search path and is callable only
-- by whoever is granted it, so an installation that separates its migrator,
-- owner and runtime logins can take DELETE on audit_events away from the
-- runtime and still have the sweep work. An installation running everything as
-- one owner keeps what it had - an owner can always delete its own rows, and no
-- migration can change that; what it gains is the guard below.
--
-- And the sweep refuses a retention that is not a positive interval. A negative
-- one turned the predicate into "older than a month from now" and took the
-- whole table.
create or replace function audit_events_expire(retention interval)
    returns bigint
    language plpgsql
    security definer
    set search_path = pg_catalog, public
as $$
declare
    deleted bigint;
begin
    if retention is null or retention <= interval '0' then
        raise exception 'the audit retention has to be a positive interval, got %', retention;
    end if;
    perform set_config('flotestro.audit_sweep', 'on', true);
    delete from audit_events where occurred_at < now() - retention;
    get diagnostics deleted = row_count;
    perform set_config('flotestro.audit_sweep', 'off', true);
    return deleted;
end;
$$;

revoke all on function audit_events_expire(interval) from public;

comment on function audit_events_expire(interval) is
    'Deletes the audit events older than the retention and returns how many went. The only path that may delete from audit_events. Runs as its owner, so an installation may take DELETE on the table away from its runtime login and still sweep.';
