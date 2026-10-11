-- The operator's ruling on an operation whose outcome nobody could confirm.
--
-- Two outcomes leave a host in a state the panel cannot vouch for, and they
-- are not the same thing:
--
--   outcome_unknown      the agent came back from a restart to find an
--                        operation it had started and did not live to see
--                        the end of. Whether the change happened is not
--                        known to anybody.
--   applied_unverified   the change was made and the verifier could not
--                        confirm it afterwards - it read nothing, or it
--                        read something other than what was promised.
--
-- The first asks "did it happen?", the second "did it hold?". Summing them
-- into one number would hide which question is open, so they are counted
-- apart everywhere.
--
-- Until now neither could be closed. The counters of the dashboard cover the
-- last 24 hours, so an unresolved operation left the screen by the clock
-- rather than by anybody deciding anything - which is the opposite of what
-- "unknown is not zero" means. A pilot cannot be judged against "no
-- unexplained unknown outcome" when the evidence ages out.
--
-- A ruling is therefore a row of its own, and it does not touch the attempt.
-- The job keeps the outcome it had: an operator saying "I looked, the change
-- is there" is a second fact about the same attempt, not a correction of the
-- first. Reading the history of a job has to show both, and a screen that
-- rewrote the outcome would make the record of what the fleet reported
-- unreliable for everything else that reads it.
create table if not exists unresolved_operation_rulings (
    attempt_id   uuid        primary key
                 references job_attempts (id) on delete cascade,
    -- Which question was answered, because the two are asked separately and
    -- a ruling on one says nothing about the other.
    kind         text        not null
                 check (kind in ('outcome_unknown', 'applied_unverified')),
    -- What the operator concluded. Deliberately not "ok/not ok": the useful
    -- distinction is whether the uncertainty is over, and how it ended.
    ruling       text        not null
                 check (ruling in ('confirmed_applied', 'confirmed_not_applied', 'accepted_unknown')),
    -- On what basis, in the operator's own words. A ruling with no basis is
    -- somebody clearing a screen, which is the thing this exists to prevent.
    basis        text        not null check (length(trim(basis)) > 0),
    ruled_by     text        not null,
    ruled_at     timestamptz not null default now()
);

comment on table unresolved_operation_rulings is
    'One row per attempt whose uncertain outcome an operator has ruled on. It does not change the attempt: the job keeps what the fleet reported, and the ruling is a second fact beside it.';
comment on column unresolved_operation_rulings.kind is
    'outcome_unknown (did it happen?) or applied_unverified (did it hold?); counted apart because they are different questions.';
comment on column unresolved_operation_rulings.ruling is
    'confirmed_applied, confirmed_not_applied or accepted_unknown - the last is a decision to stop asking, which is still a decision somebody made and signed.';
comment on column unresolved_operation_rulings.basis is
    'Why the operator concluded it: what they read, where they looked. Required, because a ruling without one is a screen being cleared.';

-- The list reads the attempts that have no ruling, so the join goes the other
-- way: by attempt.
create index if not exists unresolved_operation_rulings_at_idx
    on unresolved_operation_rulings (ruled_at desc);
