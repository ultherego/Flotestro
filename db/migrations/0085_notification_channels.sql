-- Notification channels.
--
-- A channel is an address the fleet reports to when nobody is looking at
-- the panel: a webhook of the installation's own, a mailbox, a chat
-- room. It names the events it carries and, for a fleet of many sites, a
-- filter on which part of the fleet it speaks for. The channel is
-- configuration of the installation, so it is written with a reason and
-- an author, like a rule or a schedule.
--
-- The configuration holds the address and, for a webhook, the secret the
-- deliveries are signed with. A mail password never lies in the row: the
-- configuration names a secret of the secret store, and the sender reads
-- it at the moment of sending. A copy of this table gives away no
-- mailbox.
create table if not exists notification_channels (
    id          uuid        primary key,
    name        text        not null unique,
    kind        text        not null check (kind in ('webhook', 'email', 'slack_webhook')),
    config      jsonb       not null default '{}'::jsonb,
    events      text[]      not null default '{}'::text[],
    filter      jsonb       not null default '{}'::jsonb,
    enabled     boolean     not null default true,
    created_by  text        not null,
    reason      text        not null,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

comment on table notification_channels is
    'Where the fleet reports to: an address, the events it carries and the part of the fleet it speaks for.';
comment on column notification_channels.config is
    'The address of the channel. A mail password is never here: the configuration names a secret of the store.';
comment on column notification_channels.events is
    'The subjects the channel carries, e.g. alert.fired; a channel with none carries nothing.';
comment on column notification_channels.filter is
    'What narrows the events: the least severity of an alert, a site, an environment.';

-- The router is a consumer of the durable trail with a cursor of its own,
-- beside the legacy webhook. The cursor starts at the end of the trail
-- rather than at its beginning: an installation that upgrades is not to
-- have its first channel told everything that ever happened.
insert into outbox_consumers (name, last_id)
select 'notifications', coalesce(max(id), 0) from outbox_events
on conflict (name) do nothing;

-- The subjects a channel can carry that the trail did not record yet. A
-- task waiting for its approval, a host that completed its enrollment, a
-- host that stopped answering, a policy that found a drift: each is a
-- moment somebody may want to be told about without watching the panel.
-- The triggers follow the ones of the campaigns: the event is written in
-- the transaction of the change, so the change cannot happen without it.

-- A task that waits for a person. The order and the host are in the
-- payload, so the message can say what waits and where.
create or replace function flotestro_job_approval_event() returns trigger
language plpgsql as $$
declare
    host_name text;
begin
    if new.state <> 'awaiting_approval' then
        return null;
    end if;
    if tg_op = 'UPDATE' and old.state = new.state then
        return null;
    end if;
    select hostname into host_name from hosts where id = new.host_id;
    insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
    values ('job', new.id, 'job.awaiting_approval',
            jsonb_build_object(
                'host_id',     new.host_id,
                'hostname',    coalesce(host_name, ''),
                'action_type', new.action_type,
                'campaign_id', new.campaign_id,
                'created_by',  new.created_by,
                'expires_at',  new.expires_at));
    return null;
end;
$$;

drop trigger if exists jobs_approval_event on jobs;
create trigger jobs_approval_event
    after insert or update of state on jobs
    for each row execute function flotestro_job_approval_event();

-- A host that completed its enrollment is a new row of the hosts table:
-- the panel writes it once the handshake has been accepted. A host that
-- stopped answering is one that was online and is not any more - stale
-- when its heartbeats stopped, offline when its session closed. The
-- other transitions, a host coming back among them, are not announced:
-- a channel that carried every flap would be muted within a day.
create or replace function flotestro_host_event() returns trigger
language plpgsql as $$
begin
    if tg_op = 'INSERT' then
        insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
        values ('host', new.id, 'enrollment.completed',
                jsonb_build_object(
                    'hostname',    new.hostname,
                    'site',        new.site,
                    'environment', new.environment,
                    'os_family',   coalesce(new.os_family, ''),
                    'enrolled_at', new.enrolled_at));
        return null;
    end if;
    if old.connection_state = 'online' and new.connection_state in ('offline', 'stale') then
        insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
        values ('host', new.id, 'host.offline',
                jsonb_build_object(
                    'hostname',         new.hostname,
                    'site',             new.site,
                    'environment',      new.environment,
                    'connection_state', new.connection_state,
                    'last_seen_at',     new.last_seen_at));
    end if;
    return null;
end;
$$;

drop trigger if exists hosts_event on hosts;
create trigger hosts_event
    after insert or update of connection_state on hosts
    for each row execute function flotestro_host_event();

-- A rule of a policy that turned to drift on a host. One event per
-- verdict that changes into drift; a drift that stays is not news again
-- on every evaluation.
create or replace function flotestro_policy_drift_event() returns trigger
language plpgsql as $$
declare
    policy_name text;
    host_name   text;
begin
    if new.verdict <> 'drift' then
        return null;
    end if;
    if tg_op = 'UPDATE' and old.verdict = 'drift' then
        return null;
    end if;
    select name into policy_name from policies where id = new.policy_id;
    select hostname into host_name from hosts where id = new.host_id;
    insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
    values ('policy', new.policy_id, 'policy.drift',
            jsonb_build_object(
                'policy_name', coalesce(policy_name, ''),
                'version',     new.version,
                'host_id',     new.host_id,
                'hostname',    coalesce(host_name, ''),
                'rule_index',  new.rule_index,
                'reason',      new.reason));
    return null;
end;
$$;

drop trigger if exists policy_results_drift_event on policy_results;
create trigger policy_results_drift_event
    after insert or update of verdict on policy_results
    for each row execute function flotestro_policy_drift_event();
