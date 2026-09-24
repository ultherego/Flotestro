-- A relay renewal is a request whose answer may be lost. The relay commits a
-- new identity only when the answer arrives; the panel wrote the new
-- fingerprint before sending it. When the answer does not arrive, the relay
-- stays on a certificate the panel no longer knows - and the renewal itself
-- refuses an unknown certificate, so the relay cannot climb out. The site is
-- down until somebody enrols it again by hand.
--
-- The hosts never had this: agent_certificates holds a row per certificate and
-- the old one stays valid until the agent turns up with the new one. Relays get
-- the same overlap, in the shape their single row allows.
alter table relays
    add column previous_fingerprint_sha256 bytea,
    add column previous_not_after          timestamptz;

comment on column relays.previous_fingerprint_sha256 is
    'The certificate the relay held before the last renewal. It is recognised until the relay first arrives with the new one, so a renewal whose answer was lost can be retried.';
comment on column relays.previous_not_after is
    'When the previous certificate expires. The overlap never outlives it.';

create index relays_previous_fingerprint_idx on relays (previous_fingerprint_sha256)
    where previous_fingerprint_sha256 is not null;

-- The issuer of the relay's certificate. Retiring a certificate authority
-- counted the hosts that use it and never the relays, because nothing recorded
-- which authority signed a relay - so a CA underwriting every relay of the
-- fleet retired cleanly and the relays stopped verifying.
alter table relays
    add column issuer_subject text,
    add column issuer_serial  text;

comment on column relays.issuer_subject is
    'The subject of the authority that signed the relay certificate; null for a relay enrolled before this was recorded.';
