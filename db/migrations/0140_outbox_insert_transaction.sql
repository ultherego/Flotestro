-- An event is readable when no earlier event can still appear.
--
-- outbox_events.id comes from a sequence: the number is taken at the insert and
-- becomes visible at the commit, and those are two different moments. A
-- transaction that takes 100 and stays open while another takes 101 and commits
-- leaves the consumer reading 101 and moving its cursor there; 100 commits
-- afterwards and never satisfies "id > 101" again. The event stays in the table
-- and reaches no durable consumer - no webhook, no notification - and nothing
-- reports it, because from the cursor's side nothing happened.
--
-- The identifier of the inserting transaction is recorded beside the event, so
-- a consumer can ask the only question that settles this: is every transaction
-- that could still insert a lower number already finished. Postgres answers it
-- with pg_snapshot_xmin(pg_current_snapshot()) - the oldest transaction still
-- running - and xid8 does not wrap, unlike the 32-bit xmin of a row.
--
-- The column is left null on the rows that are already there: they were
-- inserted by transactions that ended before this release, so there is nothing
-- to wait for, and a null is read as settled rather than backfilled with a
-- value that would be a guess.
alter table outbox_events
    add column if not exists inserted_xid xid8;

alter table outbox_events
    alter column inserted_xid set default pg_current_xact_id();

comment on column outbox_events.inserted_xid is
    'The transaction that inserted the event. A consumer reads an event only once no transaction that could insert a lower identifier is still running; null means inserted before this column existed.';
