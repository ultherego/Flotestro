-- The audit trail stays append-only for every ordinary path: nothing in the
-- panel updates or deletes an event. The one exception is the retention
-- sweep, and it goes through this function alone: the trigger lets a delete
-- through only inside a transaction the function has marked, so a stray
-- delete elsewhere is still refused.

create or replace function audit_events_immutable() returns trigger as $$
begin
    if tg_op = 'DELETE' and current_setting('flotestro.audit_sweep', true) = 'on' then
        return old;
    end if;
    raise exception 'audit_events is append-only: % is not allowed', tg_op;
end;
$$ language plpgsql;

-- audit_events_expire deletes the events older than the retention and
-- returns how many went. The marker is local to the transaction, so it
-- ends with the function whatever happens inside it.
create or replace function audit_events_expire(retention interval) returns bigint as $$
declare
    deleted bigint;
begin
    perform set_config('flotestro.audit_sweep', 'on', true);
    delete from audit_events where occurred_at < now() - retention;
    get diagnostics deleted = row_count;
    perform set_config('flotestro.audit_sweep', 'off', true);
    return deleted;
end;
$$ language plpgsql;
