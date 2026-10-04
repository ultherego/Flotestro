-- Who took a directory change for execution, and until when.
--
-- Claim moved a change from planned to running and recorded nothing else: no
-- holder, no term. Pending reads the changes in planned, so a row left in
-- running - because the replica that claimed it stopped between the claim and
-- the finish - was seen by nobody afterwards. There was no way back to it and
-- no view that showed it as overdue; the operator saw a change that had been
-- approved and then simply stayed.
--
-- With a holder and a term the row comes back: a claim whose term has run out
-- may be taken again, and the panel can say which replica held it. The term is
-- generous, because a directory change can be slow, and it is not a guarantee
-- that the previous holder has stopped - what it bounds is how long a change
-- stays invisible.
alter table directory_changes
    add column if not exists claimed_by text,
    add column if not exists claim_expires_at timestamptz;

comment on column directory_changes.claimed_by is
    'The instance that took the change for execution; null when nobody holds it.';
comment on column directory_changes.claim_expires_at is
    'When the claim lapses. A running change past this moment may be taken again.';

create index if not exists directory_changes_claim_idx
    on directory_changes (state, claim_expires_at);
