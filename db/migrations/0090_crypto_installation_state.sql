-- The cryptographic identity of the installation.
--
-- The panel used to make itself a new secret store key or a new fleet CA
-- whenever a file was missing. Next to an existing database that is the
-- worst possible reaction: the secrets become unreadable and the hosts
-- lose the issuer they trust, and nothing says so until the first fetch
-- or the first renewal fails. This row is what the panel checks at start
-- instead. Once it exists, a missing key or CA stops the start with a
-- named state, and creating anything anew is refused.
--
-- The sentinel columns hold a value sealed under the active key the same
-- way the secrets are. Opening it at start proves that the key on disk is
-- the key of this installation and not merely a file of the right size.
create table crypto_installation_state (
    singleton               boolean     primary key default true check (singleton),
    installation_id         uuid        not null,
    -- The provider that holds the key encryption keys ("local-sealed" for
    -- the files of the state directory).
    secrets_key_provider    text        not null,
    active_secrets_key_id   text        not null,
    -- The issuer of new agent certificates: the identifier and the
    -- fingerprint of the CA certificate the files on disk must match.
    active_agent_ca_id      uuid        not null,
    active_agent_ca_fingerprint text    not null,
    sentinel_key_id         text        not null,
    sentinel_wrapped_dek    bytea       not null,
    sentinel_nonce          bytea       not null,
    sentinel_ciphertext     bytea       not null,
    initialized_at          timestamptz not null default now(),
    updated_at              timestamptz not null default now(),
    revision                bigint      not null default 1
);

-- Every version of a secret names the key it is wrapped with. A row from
-- before the envelope carries version 1 and no key: it is sealed directly
-- under the installation's original key, which the panel registers as
-- "legacy" and rewraps in the background.
alter table secret_versions add column envelope_version int not null default 1;
alter table secret_versions add column key_id text;
alter table secret_versions add column wrapped_dek bytea;

create index secret_versions_key_idx on secret_versions (key_id)
    where destroyed_at is null;

-- The issuer of an agent certificate by its stable identifier. NULL means
-- a row from before the identifier existed; the panel fills it in at
-- start for the CAs it holds, by subject and serial.
alter table agent_certificates add column issuer_id uuid;

create index agent_certificates_issuer_id_idx on agent_certificates (issuer_id)
    where revoked_at is null;
