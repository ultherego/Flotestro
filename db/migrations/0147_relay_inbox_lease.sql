-- A relayed message whose number is spent and whose work is not done is a
-- retry, and the retry had no owner. Two gateways serving one host's spool -
-- the relay reconnects to another replica while the first is still applying -
-- both read "received, never applied" and both did the work: two task results
-- recorded, two inventory revisions, one sample counted twice.
--
-- The number alone cannot settle it, because the number is deliberately spent
-- before the work. What settles it is a lease on the row: one delivery holds
-- it while it applies the message, the others are told the message is in
-- flight and keep it in the relay's spool. A gateway that dies mid-apply lets
-- the lease expire, so the work is never stranded.
alter table relay_inbox add column if not exists claimed_by text not null default '';
alter table relay_inbox add column if not exists claimed_at timestamptz;

comment on column relay_inbox.claimed_by is
    'The gateway instance applying this message right now; empty when nobody holds it.';
comment on column relay_inbox.claimed_at is
    'When that instance took it; a lease older than the inbox lease is free to take.';
