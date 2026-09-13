-- Operator authentication through Keycloak in the backend-for-frontend layout.
-- The refresh token stays on the server side; the browser gets only a session
-- reference in an HttpOnly cookie.

-- The identity_admin role manages the FreeIPA directory objects. It is separate
-- from platform_admin, because the right to change sudo and HBAC is a different
-- level of trust than the right to restart a service.
alter table role_bindings drop constraint role_bindings_role_check;
alter table role_bindings add constraint role_bindings_role_check
    check (role in ('viewer', 'auditor', 'operator', 'approver', 'identity_admin', 'platform_admin'));

-- An external identity binds a Keycloak account to a Flotestro principal.
alter table principals add column issuer  text;
alter table principals add column subject_id text;
alter table principals add column email text;
alter table principals add column last_login_at timestamptz;

-- The issuer + subject_id pair is the only reliable identifier of an external
-- account. The username may change, the subject does not.
create unique index principals_external_idx on principals (issuer, subject_id)
    where issuer is not null and subject_id is not null;

create table web_sessions (
    id                 uuid        primary key,
    -- Only the digest of the cookie value is kept in the database. A leaked
    -- database copy therefore gives no ready sessions.
    token_hash         bytea       not null unique,
    principal_id       uuid        not null references principals (id) on delete cascade,
    -- The refresh token does not leave the server; the browser does not see it.
    refresh_token      text,
    id_token           text,
    access_expires_at  timestamptz,
    absolute_expires_at timestamptz not null,
    idle_expires_at    timestamptz not null,
    user_agent         text,
    remote_addr        text,
    revoked_at         timestamptz,
    revocation_reason  text,
    created_at         timestamptz not null default now(),
    last_seen_at       timestamptz not null default now()
);

create index web_sessions_principal_idx on web_sessions (principal_id) where revoked_at is null;
create index web_sessions_expiry_idx on web_sessions (absolute_expires_at) where revoked_at is null;

-- The state of a login in progress: the PKCE verifier and the redirect target.
-- The record lives briefly and is deleted at the code exchange.
create table auth_flows (
    state          text        primary key,
    code_verifier  text        not null,
    nonce          text        not null,
    redirect_after text,
    created_at     timestamptz not null default now(),
    expires_at     timestamptz not null
);

create index auth_flows_expiry_idx on auth_flows (expires_at);

-- The mapping of external groups to roles. A group grants only a candidate role;
-- the target scope and the approval requirements remain Flotestro policy.
create table group_role_mappings (
    id          uuid        primary key,
    issuer      text        not null,
    group_name  text        not null,
    role        text        not null
                    check (role in ('viewer', 'auditor', 'operator', 'approver',
                                    'identity_admin', 'platform_admin')),
    site        text        not null default '*',
    environment text        not null default '*',
    created_by  text        not null default 'system',
    created_at  timestamptz not null default now(),
    unique (issuer, group_name, role, site, environment)
);

create index group_role_mappings_lookup_idx on group_role_mappings (issuer, group_name);
