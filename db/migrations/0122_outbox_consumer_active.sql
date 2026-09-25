-- The retention of the durable trail keeps every event a consumer has not
-- passed yet: min(last_id) over outbox_consumers pins it. A consumer that was
-- switched off keeps its row with its old cursor, so turning the webhook off
-- stopped the trail from ever being swept, and outbox_events grew without end
-- on an installation that is not using it.
--
-- A consumer says whether it is running. One that is not holds nothing back.
alter table outbox_consumers
    add column active boolean not null default true;

comment on column outbox_consumers.active is
    'False for a consumer this installation no longer runs. Its cursor stays, so switching it on again resumes where it stopped, but it no longer pins the retention of the trail.';
