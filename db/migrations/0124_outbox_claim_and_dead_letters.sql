-- The webhook round used to be claimed with a row lock that stayed open across
-- the delivery: a receiver taking its full fifteen seconds held a transaction
-- open for fifteen seconds, and the oldest such transaction is what keeps the
-- database from cleaning up after every other one. The round is now claimed in
-- one short transaction, delivered outside any transaction, and settled in a
-- second short one; the claim is a lease so that two panels still do not send
-- the same events twice.
alter table outbox_consumers
    add column if not exists claimed_by    uuid,
    add column if not exists claimed_until timestamptz;

comment on column outbox_consumers.claimed_until is
    'While this stands in the future the round belongs to claimed_by; it expires on its own when that instance disappears.';

-- An event the receiver will never accept - a payload it rejects, a signature
-- it will not take - used to stop the trail at its own identifier for ever,
-- because the cursor only ever moved on success. After a bounded number of
-- attempts the event is set aside here and the cursor moves past it, so the
-- rest of the trail keeps flowing and what was set aside is still readable.
create table if not exists outbox_dead_letters (
    consumer     text        not null,
    event_id     bigint      not null,
    aggregate    text        not null default '',
    aggregate_id text        not null default '',
    event_type   text        not null default '',
    payload      jsonb       not null default '{}'::jsonb,
    failures     integer     not null,
    last_error   text        not null,
    set_aside_at timestamptz not null default now(),
    primary key (consumer, event_id)
);

comment on table outbox_dead_letters is
    'Events a consumer refused often enough that the trail was let past them; kept whole, because the event itself is pruned on its own schedule.';
