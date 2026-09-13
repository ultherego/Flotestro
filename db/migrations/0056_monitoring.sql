-- Built-in monitoring: the resource samples of the hosts, their rollups,
-- the alert rules, the alerts and the silences.
--
-- Until now the panel read somebody else's metrics and somebody else's
-- alerts. The agent already sits on every host and reads the kernel
-- counters for the heartbeat, so the panel keeps the samples itself: the
-- charts, the rules and the alerts then work on every installation, not
-- only on one that stood a metrics system next to the panel and mapped
-- its labels onto the fleet.

-- The raw samples: one row per host per interval, kept for two days. The
-- filesystems and the interfaces are lists that change shape from host to
-- host, so they stay as JSON rather than as a table of their own that
-- every chart would have to join.
create table if not exists host_metrics (
    host_id          uuid        not null references hosts (id) on delete cascade,
    at               timestamptz not null,
    cpu_percent      real        not null,
    load1            real        not null,
    load5            real        not null,
    load15           real        not null,
    memory_total     bigint      not null,
    memory_used      bigint      not null,
    memory_available bigint      not null,
    swap_total       bigint      not null,
    swap_used        bigint      not null,
    uptime_seconds   bigint      not null,
    filesystems      jsonb       not null default '[]'::jsonb,
    interfaces       jsonb       not null default '[]'::jsonb,
    primary key (host_id, at)
);

comment on table host_metrics is
    'The raw resource samples of the hosts, as the agent sent them; kept for two days.';

-- The retention sweep deletes by time across every host.
create index if not exists host_metrics_at_idx on host_metrics (at);

-- The quarter-hour rollups, kept for a month. The averages draw the long
-- charts; the maxima say whether a quiet average hid a spike. The network
-- counters are cumulative, so the rollup keeps the last values of the
-- quarter and the reader computes rates between consecutive rows.
create table if not exists host_metrics_15m (
    host_id              uuid        not null references hosts (id) on delete cascade,
    at                   timestamptz not null,
    cpu_percent          real        not null,
    cpu_percent_max      real        not null,
    load1                real        not null,
    load5                real        not null,
    load15               real        not null,
    memory_total         bigint      not null,
    memory_used          bigint      not null,
    memory_used_max      bigint      not null,
    memory_available     bigint      not null,
    swap_total           bigint      not null,
    swap_used            bigint      not null,
    uptime_seconds       bigint      not null,
    filesystems          jsonb       not null default '[]'::jsonb,
    interfaces           jsonb       not null default '[]'::jsonb,
    samples              integer     not null,
    primary key (host_id, at)
);

comment on table host_metrics_15m is
    'The quarter-hour rollups of the resource samples; kept for a month.';

create index if not exists host_metrics_15m_at_idx on host_metrics_15m (at);

-- The moment of the last sample lives on the host row: the fleet view asks
-- "who is reporting" across every host, and must not scan the samples to
-- answer.
alter table hosts add column if not exists last_metrics_at timestamptz;

comment on column hosts.last_metrics_at is
    'When the host last sent a resource sample; empty for a host that never did.';

-- The alert rules. A rule names a metric, a condition, how long it has to
-- hold and which hosts it covers. The selector has the shape of a campaign
-- selector: site, environment, OS family and an explicit host list.
create table if not exists alert_rules (
    id          uuid        primary key,
    name        text        not null,
    metric      text        not null check (metric in (
                    'cpu_percent', 'load1_per_core', 'memory_used_percent',
                    'swap_used_percent', 'filesystem_used_percent',
                    'inodes_used_percent', 'host_offline', 'uptime_seconds')),
    operator    text        not null check (operator in ('gt', 'lt', 'gte', 'lte')),
    threshold   double precision not null,
    for_minutes integer     not null default 0 check (for_minutes >= 0),
    severity    text        not null check (severity in ('critical', 'warning', 'info')),
    selector    jsonb       not null default '{}'::jsonb,
    enabled     boolean     not null default true,
    created_by  text        not null,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

comment on table alert_rules is
    'The alert rules the panel evaluates over the resource samples of the matching hosts.';

-- The alerts. One row per rule and host from the moment the condition is
-- first seen: pending while the window fills, firing once it held for the
-- whole window, resolved when the condition ends. A resolved alert stays
-- as history; a pending one that never fired is removed, because a
-- condition that lasted one sample is not an alert.
--
-- The rule's name, metric and severity are copied onto the alert: an alert
-- is history, and history has to keep saying what fired after the rule was
-- renamed or removed. A removed rule leaves its alerts resolved and
-- without a rule.
create table if not exists alerts (
    id          uuid        primary key,
    rule_id     uuid        references alert_rules (id) on delete set null,
    rule_name   text        not null,
    metric      text        not null,
    severity    text        not null,
    host_id     uuid        not null references hosts (id) on delete cascade,
    state       text        not null check (state in ('pending', 'firing', 'resolved')),
    value       real        not null,
    detail      text        not null default '',
    started_at  timestamptz not null default now(),
    fired_at    timestamptz,
    resolved_at timestamptz
);

comment on table alerts is
    'The alerts raised by the rules: pending, firing or resolved, one row per episode.';

-- At most one open episode per rule and host; the evaluator finds it by
-- this index and the fleet view lists the open ones.
create unique index if not exists alerts_open_idx
    on alerts (rule_id, host_id) where state <> 'resolved';
create index if not exists alerts_host_idx on alerts (host_id, started_at desc);
create index if not exists alerts_started_idx on alerts (started_at desc);

-- The silences. A silence keeps a firing alert out of the on-call view for
-- a bounded time and with a reason; it changes nothing about the alert
-- itself, so the history keeps saying what fired.
create table if not exists silences (
    id          uuid        primary key,
    host_id     uuid        references hosts (id) on delete cascade,
    rule_id     uuid        references alert_rules (id) on delete cascade,
    until       timestamptz not null,
    reason      text        not null,
    created_by  text        not null,
    created_at  timestamptz not null default now(),
    expired_at  timestamptz
);

comment on table silences is
    'The silences of the alerts: bounded in time, with a reason and an author; ended early by expired_at.';

create index if not exists silences_active_idx on silences (until) where expired_at is null;

-- The durable trail of the alerts. Firing and resolving are the events the
-- webhook delivers; a pending alert is not yet news. The trigger writes
-- the event in the same transaction as the state change, like the
-- campaign events.
create or replace function flotestro_alert_event() returns trigger
language plpgsql as $$
declare
    host_name text;
begin
    if new.state = 'pending' then
        return null;
    end if;
    if tg_op = 'UPDATE' and old.state = new.state then
        return null;
    end if;
    -- An alert resolved straight from pending never fired, so there is
    -- nothing to announce the end of.
    if new.state = 'resolved' and (tg_op <> 'UPDATE' or old.state <> 'firing') then
        return null;
    end if;
    select hostname into host_name from hosts where id = new.host_id;
    insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
    values ('alert', new.id,
            case new.state when 'firing' then 'alert.fired' else 'alert.resolved' end,
            jsonb_build_object(
                'rule_id',   new.rule_id,
                'rule_name', new.rule_name,
                'metric',    new.metric,
                'severity',  new.severity,
                'host_id',   new.host_id,
                'hostname',  coalesce(host_name, ''),
                'value',     new.value,
                'detail',    new.detail,
                'started_at', new.started_at,
                'fired_at',  new.fired_at,
                'resolved_at', new.resolved_at));
    return null;
end;
$$;

drop trigger if exists alerts_event on alerts;
create trigger alerts_event
    after insert or update of state on alerts
    for each row execute function flotestro_alert_event();

-- The default rules: the thresholds an installation without any rules
-- would be missing first. Seeded only into an empty table, so an
-- installation that changed or removed them keeps its decision.
insert into alert_rules (id, name, metric, operator, threshold, for_minutes, severity, selector, created_by)
select gen_random_uuid(), r.name, r.metric, r.operator, r.threshold, r.for_minutes, r.severity, '{}'::jsonb, 'system'
from (values
    ('High CPU load',            'cpu_percent',             'gt', 90::double precision, 15, 'warning'),
    ('Filesystem almost full',   'filesystem_used_percent', 'gt', 90::double precision, 10, 'warning'),
    ('Filesystem full',          'filesystem_used_percent', 'gt', 97::double precision,  0, 'critical'),
    ('Memory almost exhausted',  'memory_used_percent',     'gt', 95::double precision, 10, 'warning'),
    ('Host not reporting',       'host_offline',            'gt', 10::double precision,  0, 'critical')
) as r(name, metric, operator, threshold, for_minutes, severity)
where not exists (select 1 from alert_rules);
