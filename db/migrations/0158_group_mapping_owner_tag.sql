-- A group from the identity provider may now grant a role narrowed by owner
-- and by tag, as a binding made by hand already could.
--
-- The decision of 15.10 approved those two dimensions for RBAC, and the
-- mapping was the half that could not express them: it carried site and
-- environment and nothing else, so an operator who narrowed a binding to an
-- owner had no way to say the same thing about a group. Every role that
-- arrives through SSO was therefore wider than one granted locally, which is
-- the opposite of what a directory is for.
--
-- The default is a single '*', the same spelling role_bindings uses, and it
-- means every owner. An EMPTY list reaches none - that distinction is the
-- product's rule about unknown and nothing, and it is why the default here is
-- a wildcard rather than an empty array.
alter table group_role_mappings
    add column if not exists owners text[] not null default array['*'],
    add column if not exists tags   text[] not null default array['*'];

comment on column group_role_mappings.owners is
    'The owners this mapping reaches; a single * is every owner, and an empty list reaches none.';
comment on column group_role_mappings.tags is
    'The tags this mapping reaches; a single * is every tag, and an empty list reaches none.';

-- The uniqueness of a mapping now includes the two new dimensions: two rules
-- for one group and role that differ only by owner are two rules, and the old
-- constraint would have collapsed them into one.
do $$
declare existing text;
begin
    select conname into existing
      from pg_constraint
     where conrelid = 'group_role_mappings'::regclass
       and contype = 'u'
       and pg_get_constraintdef(oid) like '%site, environment)';
    if existing is not null then
        execute format('alter table group_role_mappings drop constraint %I', existing);
    end if;
end $$;

create unique index if not exists group_role_mappings_rule_idx
    on group_role_mappings (issuer, group_name, role, site, environment, owners, tags);
