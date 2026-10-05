-- Where a consumer of the trail stands, in the order the fence answers in.
--
-- 0140 added the inserting transaction beside each event and made the reader
-- wait until no transaction that could still insert a lower event number is
-- running. The fence answers in the order of transactions; the cursor advanced
-- in the order of event numbers, and those two orders cross. A transaction that
-- took its identifier at an earlier write - say 100 - while another with a later
-- one, 101, had already reserved a lower event number and stayed open: the
-- transaction of 100 commits, the oldest running transaction is then 101, its
-- event passes the fence although its event number is the higher one, and the
-- cursor moves there. The event of 101 commits afterwards, carries a lower
-- number, and never satisfies "id > cursor" again: no webhook, no
-- notification, and nothing reports it, because from the cursor's side nothing
-- happened. The fence closed the window the reader looks through and left the
-- one the cursor steps through open.
--
-- The cursor becomes the pair the fence orders by: the inserting transaction,
-- then the event number within it. The set of events whose transaction is older
-- than every running one is complete and can never grow, so an event that
-- arrives later always carries a key above the cursor.
--
-- '0' is where every existing consumer starts, which is also how a row from
-- before 0140 reads: those rows have no transaction to wait for and are ordered
-- by their event numbers alone, below everything this cluster inserted. A
-- consumer keeps its last_id, so nothing is delivered twice and nothing is
-- skipped.
alter table outbox_consumers
    add column if not exists last_xid xid8 not null default '0'::xid8;

comment on column outbox_consumers.last_xid is
    'The inserting transaction of the last event delivered. The cursor is (last_xid, last_id): an event is read in the order its transaction settled, because the event number is taken before the commit and the two orders cross.';

comment on column outbox_consumers.last_id is
    'The event number of the last event delivered, within last_xid. Not a cursor on its own: an event with a lower number may still be ahead of the cursor.';
