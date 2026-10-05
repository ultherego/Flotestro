-- Which run of a directory change a result belongs to.
--
-- The claim recorded the holder and a term, and Finish wrote where the holder
-- matched or where nobody held the row. Both halves of that condition were
-- wrong in the same way. A successor finishing the change clears the holder, so
-- the predecessor - whose claim had lapsed, whose work the successor redid -
-- satisfied "nobody holds it" afterwards and wrote its own result over a
-- finished one: measured on PostgreSQL, succeeded overwritten with failed.
--
-- The claim now carries an attempt identifier. Every take of the row mints a
-- new one, a write names the attempt it is the result of, and a row that is no
-- longer running belongs to nobody: a terminal state is terminal.
alter table directory_changes
    add column if not exists claim_token uuid;

comment on column directory_changes.claim_token is
    'The attempt the claim belongs to. A renewal and a result must name it, so a replica whose claim lapsed cannot write the result of a run that is no longer its own.';
