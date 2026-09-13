-- The durable trace of campaign and target events.
--
-- LISTEN/NOTIFY notifications wake open screens, but are not a durable
-- queue: an event sent at the moment the panel was restarting no longer
-- exists anywhere. The final state can be read from the tables, but the
-- course - what happened and when - vanished. A campaign without a timeline
-- is a report after the fact, not control over the rollout.
--
-- The event is created in a trigger, not in the panel code. Thanks to that
-- it is recorded in the same transaction as the state change, and the state
-- cannot be changed without recording the event - also when the change is
-- made by another panel instance or a manual fix in the database.
create table if not exists outbox_events (
    id             bigserial   primary key,
    aggregate_type text        not null,
    aggregate_id   uuid        not null,
    event_type     text        not null,
    payload        jsonb       not null default '{}'::jsonb,
    occurred_at    timestamptz not null default now(),
    -- published_at waits for the first consumer outside the panel. Today the
    -- only recipient is this panel and it reads the table directly, so the
    -- column stays empty. It is here so that moving publication to a broker
    -- requires no change to the shape of the events or their identifiers.
    published_at   timestamptz
);

comment on table outbox_events is
    'The durable trace of state changes. Recorded in the same transaction as the change it describes.';

create index if not exists outbox_events_aggregate_idx
    on outbox_events (aggregate_type, aggregate_id, id);
create index if not exists outbox_events_unpublished_idx
    on outbox_events (id) where published_at is null;

-- Campaign target events. The reason and the message are part of the event,
-- because without them "host failed" says nothing beyond something going wrong.
create or replace function flotestro_target_event() returns trigger
language plpgsql as $$
begin
    if tg_op = 'UPDATE' and old.state = new.state then
        return null;
    end if;
    insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
    values ('campaign_target', new.campaign_id, 'target.' || new.state,
            jsonb_build_object(
                'target_id',  new.id,
                'host_id',    new.host_id,
                'wave',       new.wave,
                'error_code', coalesce(new.error_code, ''),
                'message',    coalesce(new.message, ''),
                'job_id',     new.job_id));
    return null;
end;
$$;

drop trigger if exists campaign_targets_event on campaign_targets;
create trigger campaign_targets_event
    after insert or update of state on campaign_targets
    for each row execute function flotestro_target_event();

-- Events of the campaign itself: entering a phase, pausing, closing.
create or replace function flotestro_campaign_event() returns trigger
language plpgsql as $$
begin
    if tg_op = 'UPDATE' and old.state = new.state then
        return null;
    end if;
    insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
    values ('campaign', new.id, 'campaign.' || new.state,
            jsonb_build_object(
                'name',         new.name,
                'action_type',  new.action_type,
                'pause_reason', coalesce(new.pause_reason, ''),
                'approved_by',  coalesce(new.approved_by, '')));
    return null;
end;
$$;

drop trigger if exists campaigns_event on campaigns;
create trigger campaigns_event
    after insert or update of state on campaigns
    for each row execute function flotestro_campaign_event();
