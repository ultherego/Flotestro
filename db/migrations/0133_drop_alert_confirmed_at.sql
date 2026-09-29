-- alerts.confirmed_at was added with a comment describing how the "for" window
-- is restarted after a gap in the samples, and no code ever wrote or read it.
-- The evaluator restarts the window differently and has to: a pass judges only
-- the newest reading of a host, while several readings may have arrived since
-- the previous pass. One of those may be a reading the rule did not hold for,
-- and a column touched once per pass cannot see it - so the evaluator walks the
-- readings of the episode instead and starts the window after the last hole or
-- the last reading that broke the condition.
--
-- Keeping the column would leave the schema describing a mechanism that does
-- not exist, and the next reader would trust the comment over the code.
alter table alerts
    drop column if exists confirmed_at;
