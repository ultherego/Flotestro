-- Teams: the third way to draw the boundary of what somebody may touch.
--
-- Until now a role binding named a site and an environment, and that is
-- the whole vocabulary of authorisation. It does not describe how fleets
-- are actually divided: the database machines of two sites belong to the
-- same people, and the two sites hold other people's machines as well. The
-- operators of those machines were therefore given the whole site, or the
-- work was done by somebody who has everything.
--
-- The security document decides the shape (chapter 8.3). A tag cannot be
-- the boundary: an operator edits tags, so an operator could widen their
-- own authority. An owner written as a name cannot be either: it is a
-- label, it is spelt differently by different people and nothing stops two
-- of them meaning one group. A team is a row with an identifier: a host
-- points at it, a role binding points at it, and moving a host between
-- teams is a change of its own, with its own permission and its own line
-- in the audit trail. A tag stays what it is good at - choosing hosts
-- inside what somebody may already touch.
--
-- A binding is scoped one way or the other, never both: a binding that
-- names a team says nothing about sites, and the check below is what keeps
-- the two vocabularies from being mixed into a third nobody can read.

create table teams (
    id          uuid        primary key,
    -- The name is what people say to each other, so it is unique and it is
    -- not the identifier: a team renamed keeps every binding it had.
    name        text        not null unique,
    description text        not null default '',
    created_by  text        not null default 'system',
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

comment on table teams is
    'A stable group of hosts that belong to the same people. A role binding may name a team instead of a site, and a host belongs to at most one.';

-- A host belongs to at most one team. Null is not "no owner" but "nobody
-- has said yet", and the panel shows it as such: an unassigned host is
-- reachable only through a site binding, which is how every host is
-- reachable today.
alter table hosts add column team_id uuid references teams (id) on delete set null;
create index hosts_team_idx on hosts (team_id) where team_id is not null;

alter table role_bindings add column team_id uuid references teams (id) on delete cascade;

-- One vocabulary per binding. A team binding leaves the site and the
-- environment at the wildcard they default to, because they mean nothing
-- there; a site binding has no team. Anything else would be a scope whose
-- meaning depends on which check reads it first.
alter table role_bindings add constraint role_bindings_one_scope check (
    team_id is null or (site = '*' and environment = '*')
);

-- The same role for the same team twice is the same grant. The existing
-- unique key covers the site bindings; this one covers the team bindings,
-- which all carry the same wildcard site and environment.
create unique index role_bindings_team_unique
    on role_bindings (principal_id, role, team_id) where team_id is not null;

create index role_bindings_team_idx on role_bindings (team_id) where team_id is not null;
