-- The groups from the identity token are remembered in the session. The role
-- mapping is computed on every request, so a policy change works without the
-- user logging in again, and a membership change in the directory at the next login.
alter table web_sessions add column groups text[] not null default '{}';
