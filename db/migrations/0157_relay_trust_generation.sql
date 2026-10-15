-- What a relay holds, not what it was sent.
--
-- Handing signing over to a new fleet CA cuts off everything whose trust set
-- does not carry it. The guard before an activation counted hosts and stopped
-- there, and a relay holds the bundle too: it terminates the agents of its
-- site, so a relay without the new authority darkens that whole site the
-- moment the handover happens.
--
-- The evidence is the one the hosts already use. The bundle travels with the
-- certificate in a single answer, so the authorities recorded here are the
-- ones that went out with the certificate the relay now carries, and
-- trust_presented_at says the relay has been seen using that certificate -
-- which is what turns "the panel sent it" into "the relay has it". A renewal
-- clears the presentation, because a new answer carries a new bundle the
-- relay has not been seen using yet.
alter table relays add column if not exists trust_issuer_ids uuid[] not null default '{}';
alter table relays add column if not exists trust_presented_at timestamptz;

comment on column relays.trust_issuer_ids is
    'The authorities carried by the bundle that went out with the current certificate.';
comment on column relays.trust_presented_at is
    'When the relay was last seen using that certificate; null means it has not been, and unknown is not evidence.';

create index if not exists relays_trust_generation_idx on relays using gin (trust_issuer_ids);
