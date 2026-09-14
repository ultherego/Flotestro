-- Why a host cannot connect.
--
-- A certificate the gateway refuses fails the TLS handshake, and the panel
-- learns nothing of it: the host shows as offline, like a machine that is
-- switched off. An agent that let its certificate expire is nothing of the
-- sort - it is a host the operator can bring back with a recovery order -
-- and telling the two apart is what these three columns are for. They hold
-- the last refusal since the last successful session: a session that opens
-- clears them, so what stands here is always the reason the host is not
-- connected now, never a refusal from before a reconnect.
alter table hosts
    add column if not exists last_connection_refusal_code   text,
    add column if not exists last_connection_refusal_at     timestamptz,
    add column if not exists last_connection_refusal_detail text;

comment on column hosts.last_connection_refusal_code is
    'Why the gateway last turned the host away since its last session: certificate_expired, certificate_not_yet_valid, unknown_certificate, revoked_certificate, identity_mismatch or lifecycle_<state>. Null once a session opens.';
comment on column hosts.last_connection_refusal_at is
    'When that refusal was recorded.';
comment on column hosts.last_connection_refusal_detail is
    'What the gateway saw: the serial and the validity of the certificate, or the state of the host.';

-- The dashboard counts the refused hosts and the list filters by the
-- code; the hosts that were never refused are the bulk and stay out of
-- the index.
create index if not exists hosts_connection_refusal_idx
    on hosts (last_connection_refusal_code)
    where last_connection_refusal_code is not null;
