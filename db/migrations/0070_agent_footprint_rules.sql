-- The agent's own footprint in the resource sample.
--
-- The release gate of the agent asks what it costs a host in memory and
-- CPU, and until now nothing on the fleet answered: the agent sampled the
-- host and said nothing about itself. It now reads /proc/self along with
-- the host counters, and the sample carries the numbers. Every column is
-- nullable and null means the agent did not report the value - an agent
-- from before this change, or a procfs it could not read. Null is never
-- coalesced to zero: a zero would let the gate pass on a host it never
-- measured, and a "less than" rule would fire on it.
alter table host_metrics
    add column if not exists agent_rss_bytes   bigint,
    add column if not exists agent_cpu_percent real,
    add column if not exists agent_goroutines  integer,
    add column if not exists agent_open_fds    integer,
    add column if not exists helper_rss_bytes  bigint;

comment on column host_metrics.agent_rss_bytes is
    'Resident memory of the agent process at the sample; null when the agent did not report it.';
comment on column host_metrics.agent_cpu_percent is
    'Busy time of the agent process over the interval since the previous sample, as a share of one core; null when not reported.';
comment on column host_metrics.agent_goroutines is
    'Goroutines of the agent at the sample; null when not reported.';
comment on column host_metrics.agent_open_fds is
    'Open file descriptors of the agent at the sample; null when not reported.';
comment on column host_metrics.helper_rss_bytes is
    'Resident memory of the root helper while it runs; null while it sleeps between orders or when not reported.';

-- The rollups keep the mean and, for memory and CPU, the peak of the
-- quarter: a leak shows as a mean that climbs, a burst as a peak the mean
-- hides. The averages skip the null samples, so a quarter with one
-- reading keeps that reading.
alter table host_metrics_15m
    add column if not exists agent_rss_bytes       bigint,
    add column if not exists agent_rss_bytes_max   bigint,
    add column if not exists agent_cpu_percent     real,
    add column if not exists agent_cpu_percent_max real,
    add column if not exists agent_goroutines      integer,
    add column if not exists agent_open_fds        integer,
    add column if not exists helper_rss_bytes      bigint;

-- Two rules may watch the footprint: the agent's memory and its CPU
-- share. The metric list of alert_rules is a check constraint, so it is
-- rewritten with the two names.
alter table alert_rules drop constraint if exists alert_rules_metric_check;
alter table alert_rules add constraint alert_rules_metric_check check (metric in (
    'cpu_percent', 'load1_per_core', 'memory_used_percent',
    'swap_used_percent', 'filesystem_used_percent',
    'inodes_used_percent', 'host_offline', 'uptime_seconds',
    'agent_rss_bytes', 'agent_cpu_percent'));

-- The default rules for the footprint: twice the budget of the release
-- gate (128 MiB, 10 %), held for a quarter of an hour so a package
-- transaction or an inventory run does not alarm. Seeded where no rule
-- watches the metric yet, so an installation that wrote its own keeps
-- its decision; the first five defaults were seeded into an empty table
-- and an installation with rules would otherwise never get these.
insert into alert_rules (id, name, metric, operator, threshold, for_minutes, severity, selector, created_by)
select gen_random_uuid(), r.name, r.metric, r.operator, r.threshold, r.for_minutes, r.severity, '{}'::jsonb, 'system'
from (values
    ('Agent memory over budget', 'agent_rss_bytes',   'gt', 268435456::double precision, 15, 'warning'),
    ('Agent CPU over budget',    'agent_cpu_percent', 'gt', 25::double precision,        15, 'warning')
) as r(name, metric, operator, threshold, for_minutes, severity)
where not exists (select 1 from alert_rules a where a.metric = r.metric);
