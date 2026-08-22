-- Uwierzytelnianie operatorow przez Keycloak w ukladzie backend-for-frontend.
-- Refresh token pozostaje po stronie serwera; przegladarka dostaje wylacznie
-- referencje do sesji w ciasteczku HttpOnly.

-- Rola identity_admin zarzadza obiektami katalogu FreeIPA. Jest osobna od
-- platform_admin, bo prawo do zmiany sudo i HBAC to inny poziom zaufania niz
-- prawo do restartu uslugi.
alter table role_bindings drop constraint role_bindings_role_check;
alter table role_bindings add constraint role_bindings_role_check
    check (role in ('viewer', 'auditor', 'operator', 'approver', 'identity_admin', 'platform_admin'));

-- Tozsamosc zewnetrzna wiaze konto Keycloak z principalem Flotestro.
alter table principals add column issuer  text;
alter table principals add column subject_id text;
alter table principals add column email text;
alter table principals add column last_login_at timestamptz;

-- Para issuer + subject_id jest jedynym pewnym identyfikatorem konta
-- zewnetrznego. Nazwa uzytkownika moze sie zmienic, subject nie.
create unique index principals_external_idx on principals (issuer, subject_id)
    where issuer is not null and subject_id is not null;

create table web_sessions (
    id                 uuid        primary key,
    -- W bazie trzymamy wylacznie skrot wartosci ciasteczka. Wyciek kopii bazy
    -- nie daje wiec gotowych sesji.
    token_hash         bytea       not null unique,
    principal_id       uuid        not null references principals (id) on delete cascade,
    -- Refresh token nie opuszcza serwera; przegladarka go nie widzi.
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

-- Stan trwajacego logowania: weryfikator PKCE i cel przekierowania. Rekord
-- zyje krotko i jest kasowany przy wymianie kodu.
create table auth_flows (
    state          text        primary key,
    code_verifier  text        not null,
    nonce          text        not null,
    redirect_after text,
    created_at     timestamptz not null default now(),
    expires_at     timestamptz not null
);

create index auth_flows_expiry_idx on auth_flows (expires_at);

-- Mapowanie grup zewnetrznych na role. Grupa nadaje wylacznie kandydacka role;
-- docelowy zakres i wymagania approval pozostaja polityka Flotestro.
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
