-- A feed snapshot has two dates, because they are two different facts.
--
-- "Fetched" says how old the data is. "Checked" says when the panel last
-- made sure nothing changed. A feed that changes once a day was without this
-- considered stale after six hours - although the panel asked about it every
-- half hour and got "no changes" every time.
alter table vuln_snapshots
    add column if not exists checked_at timestamptz;

update vuln_snapshots set checked_at = fetched_at where checked_at is null;
