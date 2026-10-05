-- What ordered a task, recorded rather than read off the author's name.
--
-- The panel writes its own work under names like "campaign:<name>",
-- "directory-change:<id>", "flotestro/vuln" and "system". A dispatcher that
-- decided by prefix carried three prefixes nobody writes and missed two that
-- are - and a name is something an identity could be given, which a column is
-- not.
--
-- Null is every row written before this column, and it is not a licence: the
-- dispatcher reads an unrecorded kind as a person, which is the narrow side, so
-- such a row waits for a decision rather than passing as the panel's own.
alter table jobs add column if not exists created_by_kind text;

comment on column jobs.created_by_kind is
    'person | machinery; null for rows from before the column, read as person';
