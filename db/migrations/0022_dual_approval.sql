-- Data-destroying operations require two people's consent.
--
-- The second-person rule already in place says only that the requester does
-- not approve themselves. For formatting a disk that is too little: a mistake
-- by one person who happens to have the right to approve costs data nobody
-- will restore. That is why the number of required approvals is a property
-- of the job, not of the environment - and every approval is recorded separately, with the person and the time.
alter table jobs
    add column if not exists required_approvals smallint not null default 1
        check (required_approvals between 1 and 3);

create table if not exists job_approvals (
    job_id      uuid        not null references jobs(id) on delete cascade,
    approver    text        not null,
    reason      text,
    approved_at timestamptz not null default now(),
    -- The same person does not approve twice: two approvals are to mean two
    -- people, not two clicks.
    primary key (job_id, approver)
);

create index if not exists job_approvals_job_idx on job_approvals(job_id);
