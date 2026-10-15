-- A person can sign in to this panel without an identity provider.
--
-- Until here the panel had RBAC, roles, scopes and tokens, and no way for a
-- human to get in without Keycloak: /auth/login answers 501 oidc_disabled
-- when none is configured, and the only other door was the bootstrap token,
-- which the product itself describes as being for the first group mapping.
-- An installation of a product sold as "download and run" could therefore
-- give a person no access at all. The owner asked the question on 16.10 -
-- *"a co jeśli ktoś nie ma freeipa / sso? To skąd ma mieć dostępy"* - and
-- chose local accounts with passwords, as Zabbix and Grafana have.
--
-- A credential is a row of its own rather than columns on the principal: an
-- identity with no row has no password, which is a different thing from an
-- identity whose password is empty, and the difference is the one this
-- product keeps everywhere.
create table local_credentials (
    principal_id uuid primary key references principals (id) on delete cascade,
    -- The encoded argon2id hash, parameters included, so a future change of
    -- cost does not strand the rows written under the old one.
    password_hash text not null,
    set_at     timestamptz not null default now(),
    set_by     text        not null,
    -- A password somebody else chose is a password its owner has to replace.
    must_change boolean not null default true,
    -- What a brute force costs: the attempts since the last success, and the
    -- moment the account starts answering again.
    failed_attempts int not null default 0,
    locked_until    timestamptz,
    last_used_at    timestamptz
);

comment on table local_credentials is
    'The password of an identity that signs in without an identity provider. No row means no password: that identity signs in through the provider or not at all.';
