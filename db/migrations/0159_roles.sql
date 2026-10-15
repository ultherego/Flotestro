-- A role is a row now, so an installation can define one of its own.
--
-- Until here the name of a role was a check constraint in three places
-- (0004_authz.sql, and twice in 0007_oidc.sql), so the six roles the product
-- ships with were the only roles there could ever be. The decision of 14.10
-- approved roles of the installation's own; a value added to a check
-- constraint is not that - it is the same six, spelled longer.
--
-- The split this table makes, and the reason for it: a BUILT-IN role keeps
-- its permissions in the code, where they are read in review and cannot be
-- edited by anybody holding a password. Only a role somebody here defined
-- keeps its permissions in role_permissions. So the two can never disagree
-- about a built-in role, because only one of them ever says anything about
-- one.
--
-- THIS MIGRATION CANNOT BE UNDONE BY A LATER ONE. Going back means dropping
-- every role an installation defined, and with it every binding and every
-- group mapping that names one - which is somebody's access, deleted to
-- satisfy a schema. The step down does not exist on purpose.

create table roles (
    name        text        primary key,
    -- A built-in role is one the product defines. The column is what refuses
    -- an edit, and it is here rather than in the code because the refusal has
    -- to hold for a row that arrived some other way.
    built_in    boolean     not null default false,
    description text        not null default '',
    created_by  text        not null default 'system',
    created_at  timestamptz not null default now(),
    -- The name is what a binding, a mapping and an audit line carry, so it is
    -- held to the spelling those can be read back from.
    constraint roles_name_shape check (name ~ '^[a-z][a-z0-9_]{1,62}$')
);

comment on table roles is
    'The roles of this installation. A built-in role keeps its permissions in the code; a role defined here keeps them in role_permissions.';

insert into roles (name, built_in, description) values
    ('viewer',         true, 'Reads the fleet and the results of what others ordered.'),
    ('auditor',        true, 'Reads the trail, the metrics and the state of the protections.'),
    ('operator',       true, 'Orders the work on the hosts.'),
    ('approver',       true, 'Approves what somebody else ordered.'),
    ('identity_admin', true, 'Administers the directory objects: sudo, HBAC and the accounts.'),
    ('platform_admin', true, 'Administers the panel itself.');

-- The permissions of a role defined here. A built-in role has no row in this
-- table and may not be given one: its permissions are compiled in, and a row
-- here that disagreed with the code would be a second answer to one question.
create table role_permissions (
    role       text not null references roles (name) on delete cascade,
    permission text not null,
    primary key (role, permission)
);

create or replace function role_permissions_not_for_built_in() returns trigger as $$
begin
    if (select built_in from roles where name = new.role) then
        raise exception 'the permissions of the built-in role % are in the code, not in this table', new.role
            using errcode = 'check_violation';
    end if;
    return new;
end;
$$ language plpgsql;

create trigger role_permissions_built_in_guard
    before insert or update on role_permissions
    for each row execute function role_permissions_not_for_built_in();

-- The three check constraints the name used to stand on, replaced by the one
-- thing that can answer for a name nobody wrote in advance: the table.
--
-- The references are the default ON DELETE, which is RESTRICT. That is the
-- behaviour wanted: a role somebody is bound to cannot be deleted out from
-- under them, and the database refuses it whichever path asks - the API, a
-- script, or a hand at psql.
alter table role_bindings drop constraint role_bindings_role_check;
alter table role_bindings add constraint role_bindings_role_fkey
    foreign key (role) references roles (name);

alter table group_role_mappings drop constraint group_role_mappings_role_check;
alter table group_role_mappings add constraint group_role_mappings_role_fkey
    foreign key (role) references roles (name);
