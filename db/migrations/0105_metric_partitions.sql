-- The raw resource samples move into a table partitioned by day, so that
-- the retention drops a partition instead of deleting rows.
--
-- Ten thousand hosts at one sample a minute are 14.4 million rows a day.
-- The retention so far was a plain "delete from host_metrics where at <
-- ...", which on a fleet that size deletes a day's worth every sweep: it
-- writes as much WAL as the insert did, leaves the space to the vacuum,
-- and holds a transaction long enough to be the oldest one in the
-- database - which stops the vacuum everywhere else. Dropping a partition
-- writes one catalogue row and frees the files.
--
-- Daily rather than weekly. The retention is a number of days, and a
-- partition can only be dropped once its whole range is past it: with
-- weekly partitions a seven-day retention would keep up to fourteen days
-- of samples, twice the storage the operator asked for, and the
-- difference is 100 million rows on a fleet of ten thousand. A day of
-- samples is also small enough that the scan behind a chart of one host
-- stays an index scan per partition. A week of daily partitions is seven
-- children plus the ones created ahead, far below the point where the
-- planner's per-partition cost is worth thinking about.
--
-- WHAT THIS COSTS ON A FLEET'S DATABASE. The existing table is not
-- copied: it is renamed and attached as the partition that holds
-- everything up to the cutover, which moves no rows and writes no WAL for
-- the data. What it does cost is two passes over that table inside the
-- migration's transaction - the check constraint that lets the attach
-- skip its own scan, and the foreign key the new parent declares - plus
-- the catalogue work. At the retention this code shipped with, 48 hours,
-- the table holds at most two days of samples: about 29 million rows and
-- ten to fifteen gigabytes on a fleet of ten thousand hosts, so seconds on
-- local NVMe and a few minutes on slower storage. An installation that
-- had raised the raw retention should expect that time to grow in
-- proportion and run the upgrade in a window.
--
-- WHAT IT LOCKS. ACCESS EXCLUSIVE on host_metrics for that time: no
-- sample is written and no chart is read while it runs. Nothing is lost -
-- the agents hold unacknowledged samples in their own spools and send
-- them again, and a relay holds what it has not seen acknowledged - but
-- the host pages show no new points until it finishes. Nothing else in
-- the panel touches this table, so tasks, campaigns and the fleet view
-- carry on.

do $$
declare
    -- The cutover is the start of tomorrow in UTC. Everything the panel
    -- already holds is older than that by definition, so the existing
    -- table can become one partition covering everything up to it, and the
    -- daily partitions start there.
    boundary  timestamptz;
    legacy    text;
    child     text;
    day       timestamptz;
    step      integer;
    pk_name   text;
    fk_name   text;
begin
    -- A database that already has the partitioned table has been here.
    if exists (
        select 1 from pg_partitioned_table
         where partrelid = to_regclass('host_metrics')
    ) then
        return;
    end if;

    boundary := (date_trunc('day', now() at time zone 'UTC') at time zone 'UTC') + interval '1 day';
    -- A partition is named after the day its range begins, and the
    -- retention reads that name to know what the range ends at. The
    -- partition that holds the history begins before every day there is,
    -- but it ends at the cutover, so it takes the name of the day before
    -- it - and the retention drops it exactly when the day it names is
    -- past the retention, by which time every row in it is older still.
    legacy := 'host_metrics_p' || to_char((boundary - interval '1 day') at time zone 'UTC', 'YYYYMMDD');

    -- The constraints of the existing table carry the names the new parent
    -- wants for its own. They are renamed rather than dropped: the
    -- primary key index behind them is what lets the attach reuse the
    -- index instead of building one.
    select conname into pk_name from pg_constraint
     where conrelid = 'host_metrics'::regclass and contype = 'p';
    select conname into fk_name from pg_constraint
     where conrelid = 'host_metrics'::regclass and contype = 'f';

    if pk_name is not null then
        execute format('alter table host_metrics rename constraint %I to %I', pk_name, legacy || '_pkey');
    end if;
    -- The parent declares the reference to hosts, and the attach puts it
    -- on this partition with the others. The old one would then sit next
    -- to it and run the same check twice on every deleted host.
    if fk_name is not null then
        execute format('alter table host_metrics drop constraint %I', fk_name);
    end if;
    if to_regclass('host_metrics_at_idx') is not null then
        execute format('alter index host_metrics_at_idx rename to %I', legacy || '_at_idx');
    end if;
    execute format('alter table host_metrics rename to %I', legacy);

    -- The check is what the attach reads: with it the range is already
    -- proved and the attach does not scan the table a second time.
    execute format('alter table %I add constraint %I check (at < %L)',
                   legacy, legacy || '_range_check', boundary);

    create table host_metrics (
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
        agent_rss_bytes   bigint,
        agent_cpu_percent real,
        agent_goroutines  integer,
        agent_open_fds    integer,
        helper_rss_bytes  bigint,
        received_at       timestamptz not null default now(),
        primary key (host_id, at)
    ) partition by range (at);

    -- The index on time is declared on the parent before the attach and
    -- not after it. Declaring it on a partitioned table creates it on
    -- every partition, and on a partition that already holds the history
    -- that is a build over every row; an attach, by contrast, looks for an
    -- index that already matches and takes it. The renamed index of the
    -- old table is exactly that match, so this costs nothing here and the
    -- partitions created later still get their index for free.
    create index host_metrics_at_idx on host_metrics (at);

    execute format('alter table host_metrics attach partition %I for values from (minvalue) to (%L)',
                   legacy, boundary);

    -- Today's cutover and the days the maintenance loop would create
    -- anyway. They exist before the first sample of tomorrow arrives: an
    -- insert into a range no partition covers is an error, and the loop
    -- must never be the only thing standing between a fleet and that.
    for step in 0..3 loop
        day := boundary + (step || ' days')::interval;
        child := 'host_metrics_p' || to_char(day at time zone 'UTC', 'YYYYMMDD');
        execute format('create table if not exists %I partition of host_metrics for values from (%L) to (%L)',
                       child, day, day + interval '1 day');
    end loop;
end;
$$;

comment on table host_metrics is
    'The raw resource samples of the hosts, as the agents sent them; partitioned by day, kept for the raw retention and dropped a partition at a time.';
