-- A cancel that the host answers with "not interruptible" puts the job back to
-- running, and leaves cancel_ack_at set. The relay that carries cancel requests
-- to the hosts sends only the jobs whose cancel_ack_at is null, so a second
-- cancel of the same job - perfectly legal, the job is running again - was
-- recorded, never delivered, and failed on its own timeout as an outcome nobody
-- knows. The operator pressed cancel and the panel waited out the operation's
-- timeout without ever asking the host.
--
-- The revision counts the requests. A new request raises it and clears the
-- answer to the previous one, so the job is pending again; the acknowledgement
-- carries the revision it answers, so an answer to a request the panel has
-- already replaced is recorded and changes nothing.
alter table jobs
    add column cancel_revision bigint not null default 0;

comment on column jobs.cancel_revision is
    'How many times a cancel was requested for this job. The acknowledgement names the revision it answers, so a late answer cannot settle a newer request.';
