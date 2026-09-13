-- Notifications about campaign target state changes.
--
-- Jobs had their trigger, campaign targets did not. An operator looking at a
-- campaign saw "pending" for its whole duration and then the finished
-- result - and that is a report after the fact, not control over the rollout.
--
-- A campaign target is not a job: it goes through its own states (running,
-- rebooting, verifying), which no operation reflects. That is why it has its
-- own notification, not an addition to an existing one.
create or replace function flotestro_powiadom_o_celu() returns trigger
language plpgsql as $$
begin
    perform pg_notify('flotestro_kampanie',
        new.campaign_id::text || ' ' || new.state);
    return null;
end;
$$;

create trigger campaign_targets_powiadomienie
    after insert or update of state on campaign_targets
    for each row execute function flotestro_powiadom_o_celu();
