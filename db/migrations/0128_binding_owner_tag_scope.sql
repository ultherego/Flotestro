-- A role binding now narrows by five categories, not two: site and environment
-- and team and owner and tag. Within a list the values are alternatives; across
-- the categories every one has to hold.
--
-- The two new columns default to the wildcard, because that is what every
-- existing row means: a binding written before this migration narrowed by
-- nothing beyond its site and environment, and saying so out loud is how an
-- empty list stays free to mean "nothing" instead of "everything".
alter table role_bindings add column if not exists owners text[] not null default array['*'];
alter table role_bindings add column if not exists tags   text[] not null default array['*'];

-- The team is a foreign key and has no value that means "any", so the binding
-- carries a separate word for it. No default: code that forgets the field must
-- fail rather than quietly grant more, which is the whole reason this is a
-- column and not a convention about null.
alter table role_bindings add column if not exists team_any boolean;
update role_bindings set team_any = (team_id is null) where team_any is null;
alter table role_bindings alter column team_any set not null;

alter table role_bindings drop constraint if exists role_bindings_team_scope_check;
alter table role_bindings add constraint role_bindings_team_scope_check
    check ((team_any and team_id is null) or (not team_any and team_id is not null));

comment on column role_bindings.owners is
    'The owners this binding reaches; a single * is every owner, and an empty list reaches none.';
comment on column role_bindings.tags is
    'The tags this binding reaches, any one of them; a single * is every tag, and an empty list reaches none.';
comment on column role_bindings.team_any is
    'Whether the binding is narrowed by team at all. Exclusive with team_id, which the check constraint holds to.';
