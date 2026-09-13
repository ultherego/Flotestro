-- The issuer of the agent certificate. Without this there is no telling how
-- many hosts lose access when a given CA is withdrawn - and that is the only
-- safe basis for a withdrawal decision.
--
-- NULL means a certificate from before the CA rotation was introduced. The panel
-- fills these values in at startup, but only as long as exactly one CA exists:
-- with more there is no way to determine the issuer other than guessing.
alter table agent_certificates add column issuer_subject text;
alter table agent_certificates add column issuer_serial  text;

create index agent_certificates_issuer_idx
    on agent_certificates (issuer_subject, issuer_serial)
    where revoked_at is null;
