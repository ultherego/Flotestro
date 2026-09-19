-- The monitoring retentions as a setting of the installation rather than of
-- the process.
--
-- The raw retention, the rollup retention, the lateness budget, the raw query
-- window, the clock skew limit and the margin of partitions were flags read
-- once at start. Changing a number therefore meant restarting the control
-- plane, and on an installation with two replicas a rolling restart - a
-- deployment operation to answer "keep the raw samples for a fortnight". The
-- values belong to the installation, so the installation holds them.
--
-- One row. There is exactly one monitoring in a panel, and a key-value table
-- would let two rows disagree about the same setting with nothing to say
-- which is in force.
--
-- A NULL is not zero: it means this installation never set that field, and
-- the environment of the process still decides it. That is what keeps
-- FLOTESTRO_METRICS_* meaningful as the initial value of a new installation
-- and lets one field be taken over without freezing the other five.
--
-- N-1: a replica on the previous release never reads this table and goes on
-- running the values from its own environment. Nothing here changes an
-- existing table, so a downgrade needs no undo.
create table if not exists monitoring_settings (
    singleton                boolean     primary key default true check (singleton),
    -- Seconds rather than intervals: the panel compares them with Go
    -- durations, and an interval carrying months has no fixed length.
    raw_retention_seconds    bigint      check (raw_retention_seconds is null or raw_retention_seconds > 0),
    rollup_retention_seconds bigint      check (rollup_retention_seconds is null or rollup_retention_seconds > 0),
    max_lateness_seconds     bigint      check (max_lateness_seconds is null or max_lateness_seconds > 0),
    raw_query_window_seconds bigint      check (raw_query_window_seconds is null or raw_query_window_seconds > 0),
    clock_skew_limit_seconds bigint      check (clock_skew_limit_seconds is null or clock_skew_limit_seconds > 0),
    partitions_ahead         integer     check (partitions_ahead is null or (partitions_ahead > 0 and partitions_ahead <= 60)),
    updated_at               timestamptz not null default now(),
    -- Who stored it. A retention that shrinks throws readings away for good,
    -- so the row names the operator as well as the audit trail does.
    updated_by               text        not null default '',
    revision                 bigint      not null default 1
);

comment on table monitoring_settings is
    'The monitoring retentions and windows of this installation, one row; a NULL field is one the installation never set and the environment of the control plane still decides.';
comment on column monitoring_settings.raw_retention_seconds is
    'How long the raw samples are kept. The panel refuses a value shorter than the raw query window plus the maximum lateness (metrics_retention_too_short), on the write as well as at start.';
comment on column monitoring_settings.updated_by is
    'The identity that stored these values, as the audit trail names it.';
