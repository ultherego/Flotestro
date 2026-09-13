-- Site relays. A relay handles the agent connections of its site, buffers
-- results during a link outage and bounds the number of connections to the centre.
--
-- A relay is a separate trust boundary: it terminates the agent connection and
-- attests to the panel itself whose traffic it is. That is why it has its own
-- identity, its own certificate and its own scope - it may relay only for the hosts of its site.
create table relays (
    id                 uuid        primary key,
    name               text        not null,
    site               text        not null,
    environment        text,
    -- The fingerprint of the current certificate; a rotation replaces it in place.
    fingerprint_sha256 bytea       unique,
    serial             text,
    not_after          timestamptz,
    enrolled_at        timestamptz not null default now(),
    last_seen_at       timestamptz,
    revoked_at         timestamptz,
    revocation_reason  text,
    created_at         timestamptz not null default now()
);

create unique index relays_name_idx on relays (name);
create index relays_site_idx on relays (site) where revoked_at is null;

-- An agent session may go through a relay. The record says who attested the
-- host identity: without it the audit trail does not tell a direct connection
-- from a relayed one, and those are two different bases of trust.
alter table agent_sessions add column relay_id uuid references relays (id);
create index agent_sessions_relay_idx on agent_sessions (relay_id) where relay_id is not null;

-- The enrollment token now serves two kinds of identity.
alter table enrollment_tokens add column kind text not null default 'agent';
