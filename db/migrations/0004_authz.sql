-- The authorisation model: a permission is a pair of operation + scope. Roles
-- are not based on one broad admin=true, because reading logs, restarting a
-- service and approving changes are different levels of trust.

create table principals (
    id           uuid        primary key,
    subject      text        not null unique,
    display_name text        not null default '',
    kind         text        not null default 'user'
                     check (kind in ('user', 'service')),
    disabled_at  timestamptz,
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now()
);

-- An API token is a temporary authentication until OIDC is enabled.
-- Only the digest is kept in the database, just like for enrollment tokens.
create table api_tokens (
    id           uuid        primary key,
    principal_id uuid        not null references principals (id) on delete cascade,
    token_hash   bytea       not null unique,
    description  text,
    expires_at   timestamptz,
    revoked_at   timestamptz,
    last_used_at timestamptz,
    created_by   text        not null default 'system',
    created_at   timestamptz not null default now()
);

create index api_tokens_principal_idx on api_tokens (principal_id) where revoked_at is null;

-- A role is always assigned within a specific scope. An asterisk means any
-- value, so an operator may have rights only on staging in one site.
create table role_bindings (
    id           uuid        primary key,
    principal_id uuid        not null references principals (id) on delete cascade,
    role         text        not null
                     check (role in ('viewer', 'auditor', 'operator', 'approver', 'platform_admin')),
    site         text        not null default '*',
    environment  text        not null default '*',
    created_by   text        not null default 'system',
    created_at   timestamptz not null default now(),
    unique (principal_id, role, site, environment)
);

create index role_bindings_principal_idx on role_bindings (principal_id);
