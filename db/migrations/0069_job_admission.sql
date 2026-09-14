-- Admission of single-host jobs.
--
-- Until now the budgets governed campaigns alone: an operator ordering
-- restarts host by host walked past every capacity the fleet had decided
-- on, and fifty such orders were fifty mutations nobody admitted. A queued
-- job now asks the same budgets a campaign target asks, and one that gets
-- no tokens stays in the queue. Standing in the queue for no visible reason
-- looks like a forgotten job, so the reason is a column the job list shows:
-- 'awaiting_budget:<key>' names the budget that had no room. Empty means the
-- job is not waiting on anything the panel knows of - not that the reason
-- is unknown.
alter table jobs
    add column if not exists wait_reason text not null default '';

comment on column jobs.wait_reason is
    'Why a queued job has not been taken yet, e.g. awaiting_budget:global:mutations. Empty when nothing holds it.';

-- The class with which the job asks for capacity. An operator may mark an
-- order as an incident response - locking an account, stopping a service
-- that misbehaves - and it then waits the shortest. Empty means the class
-- was not stated and is derived from the operation and its author at
-- dispatch time.
alter table jobs
    add column if not exists budget_class text not null default ''
        check (budget_class in ('', 'incident', 'interactive', 'maintenance', 'background'));

comment on column jobs.budget_class is
    'The budget class the job asks for capacity with; empty means derived from the operation and its author.';

-- The waiting jobs are read by budget key for the operator's screen and
-- for the metrics; the queue is small, but the scan must not walk the
-- whole history of finished jobs.
create index if not exists jobs_waiting_on_budget on jobs (wait_reason)
    where state = 'queued' and wait_reason <> '';
