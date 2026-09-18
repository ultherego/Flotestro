-- The history of what a relay's spool holds.
--
-- Until now the panel kept exactly one heartbeat per relay, in memory. That
-- answers "how full is the buffer right now" and nothing else: an operator
-- could not see that a site was cut off for two hours last night, that the
-- spool has been filling for a week, or that the relay restarted and lost
-- the counters it had been reporting. A site is the one thing in the fleet
-- that fails as a whole, so its buffer needs a history like a host's
-- resource samples have one.
--
-- These are plain tables with a time index and a delete sweep, not daily
-- partitions like host_metrics.
--
-- The raw resource samples are partitioned because their retention deletes
-- a whole day of a fleet at a time: ten thousand hosts sampling every
-- minute are fourteen million rows a day, and deleting them row by row
-- writes as much WAL as the insert did and holds the oldest transaction in
-- the database while it runs. The relays are three orders of magnitude
-- smaller. A hundred relays reporting once a minute are a hundred and
-- forty thousand rows a day; a week of them is a million, and the sweep
-- deletes one day of that in a fraction of a second. The partition
-- machinery would buy nothing here and would be a second copy of code that
-- is bound to the shape of host_metrics, which is exactly the kind of
-- duplication that goes wrong at the next upgrade.

-- The raw samples: one row per relay per heartbeat, kept for seven days.
create table if not exists relay_buffer_samples (
    relay_id        uuid        not null references relays (id) on delete cascade,
    reported_at     timestamptz not null,
    -- InstanceID names the process of the relay: a fresh identifier at
    -- every start. A change of it between two samples is a restart, and a
    -- restart is what explains dropped_total falling back to zero. Empty
    -- for a relay from before the spool, which did not report one.
    instance_id     text        not null default '',
    bytes_used      bigint      not null,
    bytes_limit     bigint      not null,
    item_count      integer     not null,
    -- DroppedTotal counts since the relay process started, so it is read as
    -- a delta between samples of the same instance and never across a
    -- restart.
    dropped_total   bigint      not null,
    active_sessions integer     not null,
    -- UpstreamState is connected, buffering or reconnecting, as the relay
    -- saw its link at the moment of the report. Empty means a relay that
    -- did not say; unknown is not "connected".
    upstream_state  text        not null default '',
    version         text        not null default '',
    primary key (relay_id, reported_at)
);

comment on table relay_buffer_samples is
    'The raw buffer reports of the relays, as the heartbeat carried them; kept for seven days.';
comment on column relay_buffer_samples.instance_id is
    'The process of the relay; a change between two samples means the relay restarted.';
comment on column relay_buffer_samples.dropped_total is
    'Results dropped since the relay process started; read as a delta within one instance.';

-- The retention sweep deletes by time across every relay.
create index if not exists relay_buffer_samples_at_idx on relay_buffer_samples (reported_at);

-- The quarter-hour rollups, kept for ninety days. The means draw the long
-- chart; the maxima say whether a quiet mean hid a spike. dropped_total is
-- cumulative, so the quarter keeps its last value rather than a mean of
-- counters, and restarts counts how many times the instance changed inside
-- the quarter - one look says "the relay was flapping" without reading the
-- raw samples that are already gone.
create table if not exists relay_buffer_samples_15m (
    relay_id         uuid        not null references relays (id) on delete cascade,
    at               timestamptz not null,
    instance_id      text        not null default '',
    bytes_used       bigint      not null,
    bytes_used_max   bigint      not null,
    bytes_limit      bigint      not null,
    item_count       integer     not null,
    item_count_max   integer     not null,
    dropped_total    bigint      not null,
    active_sessions  integer     not null,
    upstream_state   text        not null default '',
    -- DisconnectedSamples counts the samples of the quarter whose link was
    -- not connected. A quarter with one such sample and a quarter that was
    -- cut off throughout are different incidents, and an averaged state
    -- would tell them apart for nobody.
    disconnected_samples integer not null default 0,
    restarts         integer     not null default 0,
    version          text        not null default '',
    samples          integer     not null,
    primary key (relay_id, at)
);

comment on table relay_buffer_samples_15m is
    'The quarter-hour rollups of the relay buffer reports; kept for ninety days.';

create index if not exists relay_buffer_samples_15m_at_idx on relay_buffer_samples_15m (at);

-- The alert rules over the buffer of a relay.
--
-- They are a table of their own rather than rows of alert_rules, because
-- alert_rules and alerts are bound to a host: a rule carries a host
-- selector and an alert carries a host_id that cannot be null. A relay is
-- not a host and has no host to hang the episode on. The shape is the one
-- the host rules have - metric, operator, threshold, a holding window,
-- severity, an enabled flag and an author - so a reader of one reads the
-- other, and the built-ins are seeded here the same way: only where no
-- rule watches the metric yet, so an installation that changed or removed
-- them keeps its decision.
create table if not exists relay_buffer_alert_rules (
    id          uuid        primary key,
    name        text        not null,
    metric      text        not null check (metric in (
                    'relay_buffer_used_percent', 'relay_buffer_dropped_increase')),
    operator    text        not null check (operator in ('gt', 'lt', 'gte', 'lte')),
    threshold   double precision not null,
    for_minutes integer     not null default 0 check (for_minutes >= 0),
    severity    text        not null check (severity in ('critical', 'warning', 'info')),
    enabled     boolean     not null default true,
    created_by  text        not null,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

comment on table relay_buffer_alert_rules is
    'The alert rules the panel evaluates over the buffer reports of the relays.';

-- The episodes. One row per rule and relay from the moment the condition
-- is first seen: pending while the holding window fills, firing once it
-- held for the whole window, resolved when the condition ends. The rule's
-- name, metric and severity are copied onto the episode, because an
-- episode is history and history has to keep saying what fired after the
-- rule was renamed.
create table if not exists relay_buffer_alerts (
    id          uuid        primary key,
    rule_id     uuid        references relay_buffer_alert_rules (id) on delete set null,
    rule_name   text        not null,
    metric      text        not null,
    severity    text        not null,
    relay_id    uuid        not null references relays (id) on delete cascade,
    state       text        not null check (state in ('pending', 'firing', 'resolved')),
    value       double precision not null,
    detail      text        not null default '',
    started_at  timestamptz not null default now(),
    fired_at    timestamptz,
    resolved_at timestamptz
);

comment on table relay_buffer_alerts is
    'The alerts raised on the buffer of a relay: pending, firing or resolved, one row per episode.';

create unique index if not exists relay_buffer_alerts_open_idx
    on relay_buffer_alerts (rule_id, relay_id) where state <> 'resolved';
create index if not exists relay_buffer_alerts_relay_idx
    on relay_buffer_alerts (relay_id, started_at desc);

-- The durable trail, in the shape the notification router already reads:
-- firing and resolving are news, a pending episode is not yet. The
-- payload names the relay under 'hostname' so the message says which
-- relay it is about without the router learning a new kind of subject,
-- and it carries relay_id and site as well, for a channel filtered by
-- site and for a panel link.
create or replace function flotestro_relay_buffer_alert_event() returns trigger
language plpgsql as $$
declare
    relay_name text;
    relay_site text;
begin
    if new.state = 'pending' then
        return null;
    end if;
    if tg_op = 'UPDATE' and old.state = new.state then
        return null;
    end if;
    -- An episode resolved straight from pending never fired, so there is
    -- nothing to announce the end of.
    if new.state = 'resolved' and (tg_op <> 'UPDATE' or old.state <> 'firing') then
        return null;
    end if;
    select name, site into relay_name, relay_site from relays where id = new.relay_id;
    insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
    values ('alert', new.id,
            case new.state when 'firing' then 'alert.fired' else 'alert.resolved' end,
            jsonb_build_object(
                'rule_id',     new.rule_id,
                'rule_name',   new.rule_name,
                'metric',      new.metric,
                'severity',    new.severity,
                'relay_id',    new.relay_id,
                'hostname',    coalesce(relay_name, ''),
                'site',        coalesce(relay_site, ''),
                'value',       new.value,
                'detail',      new.detail,
                'started_at',  new.started_at,
                'fired_at',    new.fired_at,
                'resolved_at', new.resolved_at));
    return null;
end;
$$;

drop trigger if exists relay_buffer_alerts_event on relay_buffer_alerts;
create trigger relay_buffer_alerts_event
    after insert or update of state on relay_buffer_alerts
    for each row execute function flotestro_relay_buffer_alert_event();

-- The built-in rules. Three steps on the fill, because they are three
-- different decisions: at 70 % there is time to look at the link, at 85 %
-- the site is going to start losing results, at 95 % the spool is about to
-- refuse new sessions. The holding windows shorten as the fill grows - a
-- quarter of an hour at 70 % so a single slow flush does not alarm, none
-- at 95 % because by then waiting costs results. A drop is its own rule
-- with no window at all: a relay that dropped even one result lost
-- something the fleet will not get back.
insert into relay_buffer_alert_rules (id, name, metric, operator, threshold, for_minutes, severity, created_by)
select gen_random_uuid(), r.name, r.metric, r.operator, r.threshold, r.for_minutes, r.severity, 'system'
from (values
    ('Relay buffer filling',      'relay_buffer_used_percent',      'gt', 70::double precision, 15, 'warning'),
    ('Relay buffer nearly full',  'relay_buffer_used_percent',      'gt', 85::double precision,  5, 'warning'),
    ('Relay buffer critical',     'relay_buffer_used_percent',      'gt', 95::double precision,  0, 'critical'),
    ('Relay is dropping results', 'relay_buffer_dropped_increase',  'gt',  0::double precision,  0, 'critical')
) as r(name, metric, operator, threshold, for_minutes, severity)
where not exists (
    select 1 from relay_buffer_alert_rules existing
    where existing.metric = r.metric and existing.threshold = r.threshold);
