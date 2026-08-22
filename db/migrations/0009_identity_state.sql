-- Stan integracji hosta z domena. Pola sluza do filtrowania i do wykrywania
-- hostow wymagajacych uwagi, wiec sa znormalizowane; pelny raport pozostaje
-- w JSONB rewizji inventory.
--
-- Wartosci NULL oznaczaja stan nieustalony, nie brak integracji: host, ktorego
-- nie udalo sie odpytac, to co innego niz host swiadomie poza domena.
alter table hosts add column identity_enrolled    boolean not null default false;
alter table hosts add column identity_domain      text;
alter table hosts add column identity_realm       text;
alter table hosts add column identity_sssd_online boolean;
alter table hosts add column identity_checked_at  timestamptz;

create index hosts_identity_idx on hosts (identity_enrolled, identity_domain);
-- Hosty w domenie, ktore stracily lacznosc z katalogiem, wymagaja uwagi.
create index hosts_identity_offline_idx on hosts (identity_sssd_online)
    where identity_enrolled and identity_sssd_online is not true;
