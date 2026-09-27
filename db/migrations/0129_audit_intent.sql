-- A change to what the fleet trusts leaves a trail before it happens.
--
-- Preparing a CA, handing signing over to it and retiring one all happen on
-- disk: once done, nothing can undo them, and an entry written afterwards can
-- still be lost. So the entry comes first. The panel writes what it is about to
-- do, commits that, and only then does it - and if the second entry, the one
-- with the outcome, is never written, the first one still says who began what
-- and when. A reconciler reads the trust store at the next start and appends
-- what it found.
--
-- The table is append-only, so an outcome is a second row rather than an update
-- of the first.
alter table audit_events drop constraint audit_events_outcome_check;
alter table audit_events add constraint audit_events_outcome_check
    check (outcome in ('success', 'failure', 'denied', 'started'));

-- The key a caller repeats a request with, so that a retry cannot begin the
-- same change twice. It is unique among the entries that begin something, and
-- those rows are never removed, so a key is spent for good: the second attempt
-- under it is refused and the operator is sent to read the state instead.
create unique index audit_events_intent_unique
    on audit_events (action, (detail->>'intent_key'))
    where outcome = 'started' and detail ? 'intent_key';

comment on index audit_events_intent_unique is
    'One beginning per idempotency key: a retry of a trust change is refused, not performed again.';
