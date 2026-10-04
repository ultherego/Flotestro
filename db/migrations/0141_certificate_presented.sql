-- When a host first opened a session with this certificate.
--
-- The guard of a CA handover asked how many hosts had no certificate from the
-- new authority issued since the preparation - and treated the moment of issue
-- as proof that the host had received the new trust bundle. Those are two
-- different facts: the panel issues the certificate, the host receives the
-- bundle, and the answer that carries both can be lost on the way. Handing
-- signing over to an authority a host does not trust yet cuts that host off,
-- which is the one thing the guard exists to prevent.
--
-- A host that opens a session with a certificate holds that certificate, so
-- the answer that carried it - and the bundle with it - arrived and was
-- written. That is the evidence, and this is where it is kept.
alter table agent_certificates
    add column if not exists presented_at timestamptz;

comment on column agent_certificates.presented_at is
    'When a host first opened a session with this certificate. Evidence that the answer carrying it, and the trust bundle with it, reached the host.';

create index if not exists agent_certificates_presented_idx
    on agent_certificates (host_id, issuer_id, presented_at);
