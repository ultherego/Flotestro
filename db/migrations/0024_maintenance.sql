-- Okno serwisowe hosta.
--
-- Maintenance nie jest stanem cyklu zycia: host w oknie serwisowym dziala,
-- jest zarzadzany i przyjmuje operacje zlecone recznie. Zmienia sie jedno -
-- kampanie go omijaja, a alerty z niego nie budza nikogo w nocy. Dlatego
-- osobne kolumny, a nie kolejna wartosc lifecycle_state.
--
-- Okno ma termin, a nie flage: "w serwisie do odwolania" konczy sie hostem,
-- o ktorym wszyscy zapomnieli i ktorego nikt nie aktualizuje od pol roku.
alter table hosts
    add column if not exists maintenance_until  timestamptz,
    add column if not exists maintenance_reason text,
    add column if not exists maintenance_by     text,
    add column if not exists maintenance_at     timestamptz;

-- Kampanie pytaja o hosty poza oknem serwisowym przy kazdej fali.
create index if not exists hosts_maintenance_idx
    on hosts (maintenance_until) where maintenance_until is not null;
