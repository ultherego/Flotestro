-- A job attempt has no execution start time: the agent does not report it,
-- so the column was empty from the start. A column nobody fills in reads as
-- "never started" and misleads anybody who bases a measurement on it - that
-- is exactly how the delay metric bug came about.
--
-- Observable are the time the job was handed to the agent (dispatched_at) and
-- the finish time (finished_at), and the metrics rest on those.
alter table job_attempts drop column started_at;

-- The delivery delay metric reads fresh attempts by the dispatch time.
create index job_attempts_dispatched_idx on job_attempts (dispatched_at)
    where dispatched_at is not null;
