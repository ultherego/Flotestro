-- The support bundle the panel produces, and the short-lived right to fetch
-- one (security remediation, chapter 14.6).
--
-- Until now the only bundle was the one an operator made on a host with
-- "agentctl support-bundle": a plain archive in a temporary directory, kept
-- for ever and handed on by whatever means were at hand. The chapter asks for
-- the other half - a bundle the panel produces, which needs step-up to ask
-- for, a link that expires to fetch, an audit entry for both, encryption at
-- rest and a retention after which it is gone.
--
-- The archive lives in the row rather than on a disk of one replica: a panel
-- that runs twice must be able to hand over a bundle either instance made,
-- and a retention that is a delete of a row is one the existing sweep already
-- knows how to run.

create table if not exists support_bundles (
    id           uuid primary key default gen_random_uuid(),
    -- pending while it is being assembled, ready once it is sealed, failed
    -- when the assembly or the scanner refused it. There is no "deleted":
    -- retention removes the row.
    state        text        not null default 'pending',
    -- Why the bundle was asked for, as the step-up demanded it. It is the
    -- reason of the request, never a description of the contents.
    reason       text        not null,
    requested_by text        not null,
    requested_at timestamptz not null default now(),
    ready_at     timestamptz,
    -- The typed code of a refusal; empty for a bundle that was assembled.
    error_code   text        not null default '',

    -- The envelope, exactly as the secret store writes one: the data key is
    -- fresh per bundle and wrapped by the installation's key encryption key,
    -- so nothing here opens without the panel's own key material.
    envelope_version integer not null default 0,
    key_id           text    not null default '',
    wrapped_dek      bytea,
    nonce            bytea,
    ciphertext       bytea,

    -- What the manifest says about the archive, kept outside it so that the
    -- screen and the trail can name a bundle without opening one.
    size_bytes       bigint  not null default 0,
    archive_sha256   text    not null default '',
    files            integer not null default 0,
    redaction_policy text    not null default '',
    scanned          boolean not null default false,

    -- A bundle nobody fetched is swept sooner than one somebody did: an
    -- archive of the panel's own state that nobody came for is not waiting
    -- for anybody.
    downloaded_at timestamptz,
    downloads     integer not null default 0
);

comment on table support_bundles is
    'The support bundles the panel produced, sealed at rest and removed by the retention sweep.';
comment on column support_bundles.ciphertext is
    'The gzipped archive under a data key of its own; there is no column with a readable bundle in it.';
comment on column support_bundles.archive_sha256 is
    'The digest of the archive as it was sealed, so what is downloaded can be held against what was made.';

alter table support_bundles drop constraint if exists support_bundles_state_check;
alter table support_bundles add constraint support_bundles_state_check
    check (state in ('pending', 'ready', 'failed'));

-- A ready bundle has an envelope; a pending or failed one has none. Without
-- this a half-written row would read as a bundle with an empty archive.
alter table support_bundles drop constraint if exists support_bundles_sealed_when_ready;
alter table support_bundles add constraint support_bundles_sealed_when_ready
    check (state <> 'ready' or (ciphertext is not null and wrapped_dek is not null
                                and nonce is not null and key_id <> ''));

create index if not exists support_bundles_requested_idx
    on support_bundles (requested_at desc);
-- The sweep scans by age and by "never fetched", both in one pass.
create index if not exists support_bundles_retention_idx
    on support_bundles (requested_at) where downloaded_at is null;

-- The right to fetch one bundle once, within a few minutes of being issued.
-- Only the digest of the value is kept, as for every other token of this
-- panel: a token readable in the database is a second copy of the link.
create table if not exists support_bundle_tokens (
    token_sha256 bytea       primary key,
    bundle_id    uuid        not null references support_bundles (id) on delete cascade,
    -- The identity the token was issued to. A link that works for whoever
    -- holds it is a link that works once it has been forwarded.
    issued_to    text        not null,
    issued_at    timestamptz not null default now(),
    expires_at   timestamptz not null,
    redeemed_at  timestamptz
);

comment on table support_bundle_tokens is
    'The short-lived, single-use rights to download a support bundle; the value itself is never stored.';

create index if not exists support_bundle_tokens_bundle_idx
    on support_bundle_tokens (bundle_id);
create index if not exists support_bundle_tokens_expiry_idx
    on support_bundle_tokens (expires_at);
