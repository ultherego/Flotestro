-- The acknowledgement of a task.
--
-- Until now the panel learned of a delivered task only from its result:
-- between the hand-over and the result an attempt was silent, its lease
-- was the five-minute execution lease from the start, and an envelope sent
-- into a stream that had just died was noticed only when that lease ran
-- out. The agent now answers every task in stages (TaskProgress.stage in
-- agent.proto): "accepted" once it holds the task, "awaiting_lock" while
-- it waits for a resource of the host, "started" once the operation is
-- starting. The two moments that last are recorded on the attempt.
--
-- started_at was dropped in 0014 because nobody filled it in: a column
-- that is always empty reads as "never started". It comes back with the
-- agent's report behind it, and stays null for an attempt the agent was
-- never heard from - which is not the same as one that started at the
-- dispatch.
alter table job_attempts
    add column if not exists accepted_at timestamptz,
    add column if not exists started_at  timestamptz;

comment on column job_attempts.accepted_at is
    'When the agent said it holds the task; null until then. The dispatch lease waits for it.';
comment on column job_attempts.started_at is
    'When the agent said the operation is starting on the host; null until then.';

-- A campaign host shows why it has not started. The text is the blocker
-- the agent named for the job of the host - "units held by task <id>
-- (schedule.run_now)" - copied from the wait reason of the job while it
-- waits, and cleared with it. Empty means the host waits on no lock the
-- panel knows of.
alter table campaign_targets
    add column if not exists blocker text not null default '';

comment on column campaign_targets.blocker is
    'The resource lock the host''s task waits on, as the agent named it; empty when it waits on none.';
