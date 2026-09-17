-- The cancel protocol: a request, an acknowledgement, a settlement.
--
-- Until now a cancel of a delivered task wrote "canceled" on the job at
-- once and gave its budget tokens back in the same statement, while the
-- host went on with the operation: the panel said stopped, the host ran a
-- transaction to its end, and the capacity the host was still using was
-- handed to the next task. From here on a cancel of a task the host holds
-- is a request. The job stands in cancel_requested with its tokens until
-- the agent answers what the request found - not started, interrupted,
-- not interruptible, already done - or until the operation's own timeout
-- passes with no answer, at which point the outcome on the host is
-- unknown and the job says so.
alter table jobs
    -- When the cancel was asked for a task the host held. Null for a job
    -- canceled while it was still in the panel's queue: nothing was asked
    -- of any host.
    add column if not exists cancel_requested_at timestamptz,
    -- When the agent answered, and with what: not_started, interrupted,
    -- not_interruptible or already_done, and the phase the host was in.
    add column if not exists cancel_ack_at timestamptz,
    add column if not exists cancel_outcome text,
    add column if not exists cancel_phase text;

comment on column jobs.cancel_requested_at is
    'When a cancel was asked of the host holding the task; null when the task never left the panel.';
comment on column jobs.cancel_ack_at is
    'When the agent acknowledged the cancel; null until then.';
comment on column jobs.cancel_outcome is
    'What the cancel found on the host: not_started, interrupted, not_interruptible or already_done.';
comment on column jobs.cancel_phase is
    'What the host was doing when the cancel arrived, as the agent named it.';

-- cancel_requested: the request went to the host and the answer is
-- awaited. The job is neither running nor canceled - it is a question in
-- flight - and it never goes back to the queue: a lease that runs out
-- under it is not a reason to deliver the task again.
alter table jobs drop constraint if exists jobs_state_check;
alter table jobs add constraint jobs_state_check
    check (state in ('planned', 'awaiting_approval', 'queued', 'leased',
                     'dispatched', 'running', 'cancel_requested',
                     'succeeded', 'failed', 'timed_out', 'canceled', 'expired'));

-- The relay that sends the request to the host and the sweep that settles
-- an unanswered one both read the open requests; a settled campaign of ten
-- thousand jobs must not be scanned for them.
create index if not exists jobs_cancel_requested_idx
    on jobs (host_id, cancel_requested_at)
    where state = 'cancel_requested';
