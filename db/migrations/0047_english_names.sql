-- English names for the notification channels, the trigger functions and
-- the remaining schema objects that still carried Polish names.
--
-- The channel names are a contract between the database and the panel, so
-- they change in one step together with the panel code that listens on
-- them: the old trigger functions are dropped and the triggers are
-- re-created against functions carrying the new names. The payloads stay
-- the same. The outbox functions and the indexes are only renamed.
drop trigger if exists jobs_powiadomienie on jobs;
drop trigger if exists jobs_notification on jobs;
drop function if exists flotestro_powiadom_o_zadaniu();

create or replace function flotestro_notify_job() returns trigger
language plpgsql as $$
begin
    perform pg_notify('flotestro_jobs',
        new.id::text || ' ' || new.state || ' ' || coalesce(new.campaign_id::text, ''));
    return null;
end;
$$;

create trigger jobs_notification
    after insert or update of state, result_status on jobs
    for each row execute function flotestro_notify_job();

drop trigger if exists campaign_targets_powiadomienie on campaign_targets;
drop trigger if exists campaign_targets_notification on campaign_targets;
drop function if exists flotestro_powiadom_o_celu();

create or replace function flotestro_notify_target() returns trigger
language plpgsql as $$
begin
    perform pg_notify('flotestro_campaigns',
        new.campaign_id::text || ' ' || new.state);
    return null;
end;
$$;

create trigger campaign_targets_notification
    after insert or update of state on campaign_targets
    for each row execute function flotestro_notify_target();

-- The outbox trigger functions keep their bodies; a rename keeps the
-- triggers bound to them.
do $$
begin
    if to_regproc('flotestro_zdarzenie_celu') is not null then
        alter function flotestro_zdarzenie_celu() rename to flotestro_target_event;
    end if;
    if to_regproc('flotestro_zdarzenie_kampanii') is not null then
        alter function flotestro_zdarzenie_kampanii() rename to flotestro_campaign_event;
    end if;
    if exists (select 1 from pg_trigger where tgname = 'campaign_targets_zdarzenie') then
        alter trigger campaign_targets_zdarzenie on campaign_targets rename to campaign_targets_event;
    end if;
    if exists (select 1 from pg_trigger where tgname = 'campaigns_zdarzenie') then
        alter trigger campaigns_zdarzenie on campaigns rename to campaigns_event;
    end if;
end;
$$;

alter index if exists managed_file_history_plik_idx rename to managed_file_history_path_idx;
alter index if exists outbox_events_agregat rename to outbox_events_aggregate_idx;
alter index if exists outbox_events_nieopublikowane rename to outbox_events_unpublished_idx;
