-- The cryptographic state of an installation moves into the database, sealed
-- with a key that is not in it.
--
-- Until now the keys lay in the state directory of whichever machine happened
-- to run the panel: the keys of the secret store, the private key of the fleet
-- CA, the key that signs the root helper's capabilities. A second replica could
-- not read what the first had sealed, a restore needed the directory as well as
-- the dump, and nothing said which key belonged to which installation.
--
-- Here every one of them is a row, wrapped with the key encryption key the
-- deployment mounts as a secret. The rows are shared; the key is not. A copy of
-- the database alone opens nothing, and the key is backed up apart from it.
create table crypto_wrapped_keys (
    -- The name the key is known by elsewhere: the key id of the secret store,
    -- the identifier of a CA, the key id of the helper signer.
    key_id      text primary key,
    -- What the key is for, so that a reader knows what it may not be used for:
    -- 'secrets' seals the values of the secret store, 'agent-ca' signs the
    -- certificates of the fleet, 'helper-signing' signs the capabilities of the
    -- root helper.
    purpose     text        not null check (purpose in ('secrets', 'agent-ca', 'helper-signing')),
    -- The key encryption key this row is wrapped with, by the name it answers
    -- to. A row wrapped with a key the deployment no longer holds is a row
    -- nobody can open, and it says so rather than failing at the first use.
    kek_id      text        not null,
    -- The layout of the wrapping. It is counted apart from the envelope version
    -- of a secret: these are two floors of the same building.
    envelope_version int    not null default 1,
    nonce       bytea       not null,
    ciphertext  bytea       not null,
    created_at  timestamptz not null default now(),
    -- A key that no longer wraps anything new but is still needed to read what
    -- it wrapped: a retired CA, the previous helper signing key.
    retired_at  timestamptz
);

comment on table crypto_wrapped_keys is
    'The private keys of the installation, each wrapped with the key encryption key the deployment mounts. The rows travel with the database; the key that opens them does not.';
comment on column crypto_wrapped_keys.kek_id is
    'The key encryption key this row was wrapped with, by name. Wrong key, and the row is refused rather than half-read.';

create index crypto_wrapped_keys_purpose_idx on crypto_wrapped_keys (purpose)
    where retired_at is null;

-- The installation record says which key encryption key its rows are wrapped
-- with. Null is an installation that still keeps its keys in the state
-- directory: the migration to the database is a step somebody takes, not one
-- that happens under them.
alter table crypto_installation_state add column kek_id text;

comment on column crypto_installation_state.kek_id is
    'The key encryption key the wrapped keys of this installation are sealed with. Null before the keys were moved into the database.';
