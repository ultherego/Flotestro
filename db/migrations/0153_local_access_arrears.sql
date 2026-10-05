-- The outstanding local half of an access cut.
--
-- A change that cuts a principal's access has two halves: the directory side,
-- and the panel's own - the local denial in principals, the live sessions, and
-- the tokens the denial marker turns away. When the directory half succeeded
-- and the local half did not, the change ended terminal partially_applied and
-- nothing retried the half that was left. The record said so honestly, and
-- then said it for ever: a terminal change is never claimed again, so the
-- preserved account kept its panel sessions and tokens until somebody read the
-- phases and acted by hand. The obligation inside the change's phases survives
-- a replica stopping; it does not survive the change reaching a terminal state.
--
-- This is that obligation as a row of its own, with its own claim, its own
-- term and its own backoff, so it outlives the change that created it and is
-- carried out without a person. It retries the local half alone: it never
-- re-touches the directory, and it never repeats the preserve.
--
-- The account's identifiers are kept here rather than read again when the
-- retry runs. By then the directory account may be gone - that is what the
-- change did to it - and a retry that had to resolve the panel identities from
-- a live directory read would have nothing to resolve them from.
create table if not exists local_access_arrears (
    id              uuid        primary key default gen_random_uuid(),
    -- change_id is the directory change that owes it. One row per change: the
    -- obligation is written before the mutating call, and an attempt that
    -- writes it a second time means the same obligation, not a second one.
    change_id       uuid        not null references directory_changes (id) on delete cascade,
    -- directory_uid is the account as the directory knew it, for the trail.
    -- Nothing here is resolved from it again.
    directory_uid   text        not null,
    -- principals are the panel identities the cut names, each with the subject
    -- to deny and the identifier whose sessions end: resolved once, before the
    -- directory was touched, and kept.
    principals      jsonb       not null default '[]'::jsonb,
    reason          text        not null default '',
    state           text        not null default 'outstanding'
                        check (state in ('outstanding', 'settled')),
    attempts        integer     not null default 0 check (attempts >= 0),
    next_attempt_at timestamptz not null default now(),
    claimed_by      text,
    claim_token     uuid,
    claim_expires_at timestamptz,
    -- last_error is the sentence of the last attempt that did not confirm the
    -- effects, for the operator to read beside the arrears.
    last_error      text        not null default '',
    settled_at      timestamptz,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    unique (change_id)
);

comment on table local_access_arrears is
    'The panel half of an access cut that is still owed: retried on its own claim until the denial and the revocation are confirmed, never given up on.';
comment on column local_access_arrears.principals is
    'The panel identities resolved before the directory was touched: [{"subject": "...", "principal_id": "..."}]. The retry uses these and reads no directory.';
comment on column local_access_arrears.state is
    'outstanding: the access may still be open; settled: the denial and the revocation were read back and confirmed. There is no state for giving up - the arrears grow instead, where the panel shows them.';
comment on column local_access_arrears.claim_expires_at is
    'When the claim on this row lapses. It is the row''s own claim and not the directory change''s: the change is terminal by the time this is retried.';

-- The claim reads the due rows oldest first, so the longest arrears go first.
create index if not exists local_access_arrears_due_idx
    on local_access_arrears (next_attempt_at, created_at)
    where state = 'outstanding';
-- The panel reads what is outstanding and how long it has been.
create index if not exists local_access_arrears_outstanding_idx
    on local_access_arrears (created_at)
    where state = 'outstanding';
