-- The fencing token of the evaluator lease, carried onto the alert state.
--
-- The lease decides who may judge the fleet, and its renewal is already fenced
-- by the token. Nothing the evaluator wrote said which lease wrote it, so the
-- lease guarded the right to start a pass and nothing else. A pass over ten
-- thousand hosts takes time: an instance that loses the lease halfway through a
-- rule went on writing verdicts for the rest of that rule, straight over the new
-- leader's. The unique index over the open episodes stops a second row being
-- inserted; it stops no second resolve, no second refresh and no second delete,
-- because those are plain updates on a row that already exists.
--
-- From here every write of the evaluator stamps the row with the token of the
-- lease it was made under, and refuses to move a row a newer lease has touched.
alter table alerts add column if not exists fencing_token bigint;

comment on column alerts.fencing_token is
    'The token of the evaluator lease that last wrote this row; null for a row nothing fenced - a panel of the previous release, or an operator acknowledging.';

-- A token is minted from zero the first time the lease changes hands, so zero
-- is "no lease" and never belongs on a row: an instance without a lease writes
-- nothing rather than writing unfenced.
alter table alerts drop constraint if exists alerts_fencing_token_positive;
alter table alerts add constraint alerts_fencing_token_positive
    check (fencing_token is null or fencing_token > 0);
