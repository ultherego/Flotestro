-- Which authorities the host was given together with this certificate.
--
-- The guard of a CA handover asked whether a host had presented a certificate
-- since the preparation of the new authority. A presentation says the answer
-- that carried the certificate arrived; it says nothing about what was in that
-- answer. A certificate issued from the bundle {A}, before B was prepared, and
-- first presented after that preparation counted as evidence that the host
-- holds B - and the activation then cut that host off. An instance that has
-- not caught up with the preparation hands out the old bundle after the
-- preparation too, so the moment of issue is no better an answer.
--
-- The bundle itself is the evidence, so it is written down: the issuer
-- identifier of every authority in the bundle this certificate went out with.
-- Null is a row from before this column - unknown, which is not evidence
-- either, so the host counts as one that has still to renew.
alter table agent_certificates
    add column if not exists trust_issuer_ids uuid[];

comment on column agent_certificates.trust_issuer_ids is
    'The issuer identifiers of every authority in the trust bundle handed to the host with this certificate. Null means it was not recorded, which is not evidence that any generation was received.';

create index if not exists agent_certificates_trust_generation_idx
    on agent_certificates using gin (trust_issuer_ids);
