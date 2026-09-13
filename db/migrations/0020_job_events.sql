-- Notifications about operation state changes.
--
-- The panel showed progress only after a page refresh. An operator running a
-- campaign must see what happens at the moment it happens - otherwise they
-- have no control over it, only a report after the fact.
--
-- The notification comes out of the database, not of the code that happens to
-- write the state. The operation state changes in several places: approval,
-- dispatch, the agent result, cancellation, expiry and the campaign. The
-- trigger covers them all and cannot be skipped when adding another one.
create or replace function flotestro_powiadom_o_zadaniu() returns trigger
language plpgsql as $$
begin
    -- The content is short on purpose: the notification says what changed, not
    -- what the new state looks like. The recipient reads it from the database,
    -- so it cannot see a state other than the recorded one.
    perform pg_notify('flotestro_zadania',
        new.id::text || ' ' || new.state || ' ' || coalesce(new.campaign_id::text, ''));
    return null;
end;
$$;

create trigger jobs_powiadomienie
    after insert or update of state, result_status on jobs
    for each row execute function flotestro_powiadom_o_zadaniu();
