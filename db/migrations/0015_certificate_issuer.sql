-- Wystawca certyfikatu agenta. Bez tej informacji nie da sie powiedziec, ilu
-- hostom odbiera dostep wycofanie danego CA - a wlasnie to jest jedyna
-- bezpieczna podstawa decyzji o wycofaniu.
--
-- NULL oznacza certyfikat sprzed wprowadzenia wymiany CA. Panel uzupelnia te
-- wartosci przy starcie, ale tylko dopoki istnieje dokladnie jedno CA: przy
-- wiekszej liczbie nie da sie ustalic wystawcy inaczej niz zgadujac.
alter table agent_certificates add column issuer_subject text;
alter table agent_certificates add column issuer_serial  text;

create index agent_certificates_issuer_idx
    on agent_certificates (issuer_subject, issuer_serial)
    where revoked_at is null;
