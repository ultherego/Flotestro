-- Diagnostic read fan-outs.
--
-- A fan-out is the same read the operator orders on one host, ordered on a
-- handful at once: a process snapshot, a journal read, a security scan. It
-- is not a campaign - it changes nothing, needs no approval and has no
-- waves - so it does not take the campaign tables. It is a row that groups
-- ordinary jobs: one job per host, each with its own attempt and result,
-- and the fan-out is the projection over them. The row keeps what was
-- asked (the operation and its payload), by whom and why, and how many
-- hosts got a job; the state of every host is read from its job.
create table if not exists read_fanouts (
    id         uuid        primary key,
    action     text        not null,
    payload    jsonb       not null default '{}'::jsonb,
    created_by text        not null,
    reason     text        not null default '',
    created_at timestamptz not null default now(),
    host_count int         not null check (host_count > 0)
);

comment on table read_fanouts is
    'A diagnostic read ordered on many hosts at once; one ordinary job per host carries the result.';

create index if not exists read_fanouts_creator on read_fanouts (created_by, created_at desc);

-- A job ordered by a fan-out knows its fan-out, the way a job ordered by a
-- campaign knows its campaign: the fan-out page lists its jobs by this
-- column, and the job list filters on it.
alter table jobs add column if not exists fanout_id uuid references read_fanouts (id) on delete set null;

create index if not exists jobs_fanout on jobs (fanout_id) where fanout_id is not null;

comment on column jobs.fanout_id is
    'The read fan-out that ordered the job; null for a job ordered by hand or by a campaign.';
