-- The inner identity envelope of a session through a relay (security
-- document, chapter 4). The relay proves itself in its handshake; the host
-- proves itself with a signature over every message, which the gateway
-- checks against the public key of the certificate on record.

-- The public key of an issued certificate, as SubjectPublicKeyInfo DER. The
-- gateway never sees the certificate a host presented to a relay, only its
-- serial in the envelope, so the key has to be on record. It is written at
-- issue from here on; for a certificate issued before, the gateway learns
-- it from the certificate the relay presents in the attestation, once the
-- fingerprint on record confirms it is the issued one.
alter table agent_certificates add column public_key_der bytea;

-- The last accepted sequence of every session of every host. The sequence
-- is monotonic within the session the agent named, so a signed message
-- carried twice - by a relay retrying, or by anyone who kept a copy - is
-- refused the second time. A message the relay buffered keeps the session
-- it was signed in, which is why the rows outlive the gateway's own
-- session: the results of a session that ended arrive under its number.
create table relay_host_sequences (
    host_id       uuid        not null references hosts (id) on delete cascade,
    session_id    uuid        not null,
    last_sequence bigint      not null,
    updated_at    timestamptz not null default now(),
    primary key (host_id, session_id)
);

-- The housekeeping sweeps rows nobody has touched for longer than a relay
-- buffers; the index is what makes that sweep cheap.
create index relay_host_sequences_updated_idx on relay_host_sequences (updated_at);

-- The one-time challenges of a renewal through a relay. The panel keeps
-- the digest alone: the challenge itself is worth nothing to a reader of
-- the database. A challenge is bound to the host it was issued to and to
-- the relay it was issued through, lives two minutes and is consumed once.
create table identity_challenges (
    id             uuid        primary key,
    host_id        uuid        not null references hosts (id) on delete cascade,
    relay_id       uuid        references relays (id) on delete cascade,
    challenge_hash bytea       not null unique,
    expires_at     timestamptz not null,
    consumed_at    timestamptz,
    created_at     timestamptz not null default now()
);

create index identity_challenges_expiry_idx on identity_challenges (expires_at);

-- How strongly a session identified the host: end_to_end when the host's
-- own signature verified, relay_only when the session rests on the relay's
-- attestation or word. Null is a direct connection, where the handshake
-- itself is the proof. The operator reads the fleet's readiness for
-- FLOTESTRO_RELAY_IDENTITY=enforce from here: enforce is safe once no open
-- relayed session is relay_only.
alter table agent_sessions add column auth_strength text
    check (auth_strength in ('relay_only', 'end_to_end'));

-- The host carries the strength of its newest session; end_to_end joins
-- attested and weak. The constraint was created inline in 0093 and carries
-- the name PostgreSQL gives such a check.
alter table hosts drop constraint if exists hosts_relay_identity_check;
alter table hosts add constraint hosts_relay_identity_check
    check (relay_identity in ('attested', 'weak', 'end_to_end'));
