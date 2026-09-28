-- Two holes in the write-ahead trail of a trust change, both about the same
-- thing: the trail is the record, so what the record depends on has to last as
-- long as the record does and may not be written twice.
--
-- The outcome of a change is one row. The panel writes it when the change
-- finishes, and the reconciler writes it at a later start when nothing did. Two
-- replicas reconciling at once would each write one, and a reader would see the
-- same change answered twice. The index makes the second write fail instead;
-- the caller reads that as "somebody already closed this" and goes on.
create unique index audit_events_intent_outcome_unique
    on audit_events (action, (detail->>'intent_key'))
    where outcome <> 'started' and detail ? 'intent_key';

comment on index audit_events_intent_outcome_unique is
    'One outcome per idempotency key: the panel and the reconciler cannot both close the same change.';

-- The beginning of a change is what says who began what, and the key in it is
-- what keeps a repeated request from making the change a second time. The
-- retention sweep used to take both away with everything else of that age. A
-- beginning nothing answered is kept: it is the only record that the change may
-- have happened, and the reconciler still has it to close.
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
    delete from audit_events e
     where e.occurred_at < now() - retention
       and not (
           e.outcome = 'started'
           and e.detail ? 'intent_key'
           and not exists (
               select 1 from audit_events answer
                where answer.action = e.action
                  and answer.detail->>'intent_key' = e.detail->>'intent_key'
                  and answer.outcome <> 'started'));
    get diagnostics deleted = row_count;
    perform set_config('flotestro.audit_sweep', 'off', true);
    return deleted;
end;
$$;

revoke all on function audit_events_expire(interval) from public;

comment on function audit_events_expire(interval) is
    'Deletes the audit events older than the retention and returns how many went. The only path that may delete from audit_events. Keeps the beginning of a change nothing answered: that row is the record that the change may have happened, and the key in it is what stops a repeat.';
