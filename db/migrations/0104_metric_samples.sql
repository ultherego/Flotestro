-- The identity of a resource sample, the per-host rollup watermark with its
-- queue of buckets to recompute, and the lease of the alert evaluator.
--
-- Until now a sample was identified by the host and the moment the host
-- said it took it. A clock is a poor identity. NTP steps it, a virtual
-- machine resumes from a snapshot with the clock of the moment it was
-- taken, an operator sets it by hand - and every one of those turns a
-- resent sample into a second row, or makes a new sample land on top of an
-- older reading of the same host. Since the relay keeps a message until
-- the panel acknowledges it, and the agent now keeps its own unacknowledged
-- samples too, a resend is no longer the exception: it is the normal way a
-- sample survives a broken link, and it has to be a no-op.
--
-- The identity is the boot the agent runs on and a sequence that grows by
-- one within that boot. It comes from the host but says nothing about the
-- host's time, so a clock that jumps changes which chart point a sample
-- draws and never which sample it is.

-- The identities of the samples the panel holds. A table of its own rather
-- than a unique index on host_metrics: host_metrics becomes partitioned by
-- time in the next migration, and a unique index on a partitioned table has
-- to contain the partition key - which would put the host's clock back into
-- the identity and defeat the whole point. This table stays unpartitioned
-- and small: five columns per sample against the thirty of a reading.
create table if not exists metric_samples (
    host_id     uuid        not null references hosts (id) on delete cascade,
    boot_id     text        not null,
    sequence    bigint      not null check (sequence > 0),
    -- The moment the host says it took the sample, and the moment the panel
    -- received it. Both are kept: freshness is judged by the panel's clock,
    -- because a host whose clock runs ahead must not look fresher than it
    -- is, while the chart point belongs at the moment of the observation.
    at          timestamptz not null,
    received_at timestamptz not null default now(),
    primary key (host_id, boot_id, sequence)
);

comment on table metric_samples is
    'The identity of every raw sample the panel holds: the host, the boot and the sequence within that boot. A second delivery of the same identity is a duplicate and writes nothing.';
comment on column metric_samples.at is
    'The moment the host says it took the sample; the chart point.';
comment on column metric_samples.received_at is
    'The moment the panel received it; freshness and lateness are measured against this.';

-- The retention of the raw samples drops whole partitions of host_metrics;
-- the identities are swept by time in the same pass and need the index.
create index if not exists metric_samples_at_idx on metric_samples (at);

-- The raw readings carry the moment they arrived as well, so a late sample
-- from a relay's spool can be told from a fresh one on the host page
-- without joining the identities.
alter table host_metrics add column if not exists received_at timestamptz not null default now();

comment on column host_metrics.received_at is
    'When the panel received the reading; later than "at" by the time the sample spent in a spool.';

-- How far the rollup has finished, per host.
--
-- One global watermark - the newest quarter in host_metrics_15m - was the
-- previous answer, and it loses data the moment a fleet has more than one
-- kind of link. A host behind a relay that was down for an hour delivers
-- its samples after every directly connected host has already moved the
-- global mark past that hour, and its readings are then never rolled up:
-- they sit in host_metrics until the retention drops them, and the long
-- charts of that one host have a hole nobody can explain. A mark per host
-- cannot be moved by another host's clock.
create table if not exists metric_rollup_watermarks (
    host_id          uuid        not null primary key references hosts (id) on delete cascade,
    -- Every quarter-hour bucket that ended before this has been rolled up.
    complete_through timestamptz not null,
    updated_at       timestamptz not null default now()
);

comment on table metric_rollup_watermarks is
    'How far the quarter-hour rollup has finished for each host; a late sample for an older bucket is queued in metric_rollup_dirty rather than hidden by another host''s progress.';

-- The buckets that have to be recomputed.
--
-- A sample is written and its bucket is marked in one transaction, so a
-- reading the panel holds is always either in a bucket the rollup has not
-- reached yet or in a bucket the queue names. The worker takes rows with
-- "for update skip locked", recomputes them and deletes them in the same
-- transaction; a sample that arrives while the bucket is being recomputed
-- waits on that row and marks it again after the commit, so the reading is
-- never lost between the two.
--
-- The document keys the queue by host and series. Here a sample is one row
-- per host per interval covering every metric of that host at once, so
-- there is no series to separate: the bucket of a host is the unit that is
-- recomputed.
create table if not exists metric_rollup_dirty (
    host_id   uuid        not null references hosts (id) on delete cascade,
    bucket_at timestamptz not null,
    dirty_at  timestamptz not null default clock_timestamp(),
    primary key (host_id, bucket_at)
);

comment on table metric_rollup_dirty is
    'The quarter-hour buckets whose rollup is out of date because a sample landed in them. Marked in the transaction that stored the sample; cleared in the transaction that recomputed the bucket.';

-- The queue is drained oldest first, and the retention asks it whether a
-- partition still owes a recomputation before it drops it.
create index if not exists metric_rollup_dirty_order_idx on metric_rollup_dirty (dirty_at);
create index if not exists metric_rollup_dirty_bucket_idx on metric_rollup_dirty (bucket_at);

-- The leases of the background work of the monitoring.
--
-- Every control-plane instance runs the alert evaluator, and until now all
-- of them evaluated every rule on every tick. The unique index over the
-- open episodes hid it: the second instance's insert lost the race and was
-- swallowed by "on conflict do nothing", so the duplicate fire never became
-- a duplicate row. It did become duplicate work on every host of the fleet,
-- and the rest of an episode - firing, refreshing, resolving - is a plain
-- update that no index guards: two instances a second apart can resolve an
-- episode the other has just refreshed. One holder at a time, named by the
-- lease, settles it; an instance that loses the lease stops rather than
-- finishing its pass on a fleet somebody else is now judging.
create table if not exists monitoring_leases (
    name        text        not null primary key,
    holder      uuid,
    -- The token grows every time the lease changes hands, so a holder can
    -- tell "I still have it" from "I had it, lost it and took it again".
    token       bigint      not null default 0,
    lease_until timestamptz,
    updated_at  timestamptz not null default now()
);

comment on table monitoring_leases is
    'The leases of the monitoring background work; one row per kind of work, held by at most one control-plane instance at a time.';

insert into monitoring_leases (name) values ('alert_evaluator')
on conflict (name) do nothing;
