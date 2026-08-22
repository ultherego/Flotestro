-- Model autoryzacji: uprawnienie to para operacja + zakres. Role nie opieraja
-- sie na jednym szerokim admin=true, bo odczyt logow, restart uslugi
-- i zatwierdzanie zmian to rozne poziomy zaufania.

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

-- Token API jest tymczasowym uwierzytelnieniem do czasu wlaczenia OIDC.
-- W bazie trzymamy wylacznie skrot, tak samo jak dla tokenow enrollmentu.
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

-- Rola jest zawsze przypisana w konkretnym zakresie. Gwiazdka oznacza dowolna
-- wartosc, wiec operator moze miec prawa tylko na staging w jednej lokalizacji.
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
