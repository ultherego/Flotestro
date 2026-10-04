-- The moment a schedule was claimed for, before anything is ordered.
--
-- Claiming a schedule commits next_run_at and last_run_at, and only then is the
-- campaign ordered. Between those two there was nothing durable that said "this
-- moment was taken and the campaign does not exist yet", so a process that
-- stopped there - or a transient refusal of the ordering - lost the whole
-- occurrence. For a one-shot schedule next_run_at is null afterwards, so the
-- moment was lost for good and nothing in the panel said a campaign had been
-- due.
--
-- The occurrence becomes a row first, in the same transaction as the claim, and
-- the loop finishes the pending ones. Ordering again is safe: the idempotency
-- key of the order is "schedule:<id>:<moment>", which is written for exactly
-- this - a repeated tick places one campaign and not two.
create table if not exists schedule_occurrences (
    schedule_id uuid        not null references campaign_schedules (id) on delete cascade,
    -- The moment the schedule was due, which is what the idempotency key of
    -- the order is built from.
    due_at      timestamptz not null,
    state       text        not null check (state in ('pending', 'placed', 'refused')),
    campaign_id uuid        references campaigns (id) on delete set null,
    -- The refusal, in the words the operator will read.
    error       text,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now(),
    primary key (schedule_id, due_at)
);

comment on table schedule_occurrences is
    'One row per moment a schedule was claimed for. Written before the campaign is ordered, so an occurrence is work to recover rather than a moment that is simply gone.';

create index if not exists schedule_occurrences_pending_idx
    on schedule_occurrences (created_at) where state = 'pending';
