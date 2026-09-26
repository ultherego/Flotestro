-- A relayed message's sequence was spent in a transaction of its own, before
-- the message was applied. A failure between the two - a database hiccup, this
-- gateway going down, anything - left the number spent and the work undone, and
-- the relay's redelivery then looked exactly like a duplicate: the panel
-- acknowledged it and dropped it. A job result, an inventory or a task
-- acknowledgement disappeared without a word, which is the one thing the
-- envelope and its sequence exist to prevent.
--
-- The sequence still moves the session's watermark, because two gateways
-- serving one host's spool must not both accept the same number. What became of
-- the message is recorded beside it, so a redelivery of something never applied
-- is applied rather than discarded.
create table if not exists relay_inbox (
    host_id     uuid        not null references hosts(id) on delete cascade,
    session_id  uuid        not null,
    sequence    bigint      not null,
    -- received: the number is spent and the work is not done yet.
    -- applied:  the panel has it; a redelivery is a repeat and is dropped.
    -- dead:     refused often enough that the relay is told to stop carrying it.
    state       text        not null default 'received'
        check (state in ('received', 'applied', 'dead')),
    attempts    integer     not null default 0,
    last_error  text        not null default '',
    received_at timestamptz not null default now(),
    applied_at  timestamptz,
    primary key (host_id, session_id, sequence)
);

comment on table relay_inbox is
    'What became of each relayed message of a session: received but not applied, applied, or set aside.';

-- The only question asked of it in bulk: what is still owed on this session.
create index if not exists relay_inbox_unfinished
    on relay_inbox (host_id, session_id) where state = 'received';
