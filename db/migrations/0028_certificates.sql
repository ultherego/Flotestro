-- Certificates on hosts.
--
-- The panel keeps two things the host will not say itself. The first is the
-- scope: which files are service certificates and which service reads them -
-- that cannot be inferred from a directory name, and searching the whole disk
-- finds the trust store instead of the answer. The second is the deployment
-- history: what the panel sent, when and on whose order.
--
-- The private key is not here in any form. There is only the name of a secret
-- in the store - a reference that means nothing without the store and the key file.
create table if not exists certificate_targets (
    id           uuid        primary key default gen_random_uuid(),
    host_id      uuid        not null references hosts(id) on delete cascade,
    path         text        not null,
    key_path     text        not null default '',
    -- The name of the secret holding the private key. The value is neither here
    -- nor anywhere else but the store.
    key_secret   text        not null default '',
    -- The unit that reads this file and the address where the effect of the
    -- deployment is visible. Both are typed in by a human: the panel does not guess them.
    reload_unit  text        not null default '',
    probe_target text        not null default '',
    service      text        not null default '',
    note         text        not null default '',
    created_by   text        not null,
    created_at   timestamptz not null default now(),
    updated_by   text        not null,
    updated_at   timestamptz not null default now(),
    unique (host_id, path)
);

create index if not exists certificate_targets_host_idx on certificate_targets (host_id);

-- The deployment history. A certificate is public, so the panel may keep it
-- whole: that lets it show exactly what was sent and go back to what
-- worked. That does not and cannot apply to the key.
create table if not exists certificate_deployments (
    id                 uuid        primary key default gen_random_uuid(),
    host_id            uuid        not null references hosts(id) on delete cascade,
    path               text        not null,
    fingerprint_sha256 text        not null,
    subject            text        not null default '',
    issuer             text        not null default '',
    not_after          timestamptz,
    certificate        text        not null default '',
    key_secret         text        not null default '',
    key_secret_version int         not null default 0,
    job_id             uuid        references jobs(id) on delete set null,
    deployed_by        text        not null,
    deployed_at        timestamptz not null default now()
);

create index if not exists certificate_deployments_host_idx
    on certificate_deployments (host_id, path, deployed_at desc);
