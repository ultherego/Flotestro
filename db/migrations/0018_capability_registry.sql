-- Rejestr adapterow hosta.
--
-- Wczesniej zdolnosci byly piecioma polami logicznymi. Pole logiczne nie mowi,
-- dlaczego adaptera nie ma, ani ze jest, lecz tylko do odczytu, ani ze potrafi
-- czesc rzeczy - a wszystkie trzy sa operatorowi potrzebne. Naprawa bazy
-- pakietow dziala wylacznie dla apta i host ma to powiedziec, zanim zadanie
-- zostanie zatwierdzone i wyslane.
create table host_capability_registry (
    host_id     uuid        not null references hosts(id) on delete cascade,
    -- Nazwa adaptera, nie nazwa wymagania operacji: 'packages.apt', nie 'packages'.
    name        text        not null,
    -- Wersja kontraktu adaptera. Wersja narzedzia jest faktem o hoscie
    -- i nalezy do inventory.
    version     int         not null default 1,
    available   boolean     not null,
    read_only   boolean     not null default false,
    reason      text,
    features    jsonb       not null default '{}'::jsonb,
    observed_at timestamptz not null default now(),
    primary key (host_id, name)
);

-- Filtrowanie floty po adapterze: "pokaz hosty, ktore maja apta".
create index host_capability_registry_name_idx
    on host_capability_registry (name) where available;

-- Hosty sprzed rejestru zachowuja to, co o nich wiadomo, do nastepnego
-- polaczenia agenta. Powod jest pusty, bo stare pole logiczne go nie niosło.
insert into host_capability_registry (host_id, name, available)
select host_id, nazwa, wartosc
from host_capabilities,
     lateral (values ('systemd', systemd),
                     ('packages.apt', apt),
                     ('packages.dnf', dnf),
                     ('docker', docker),
                     ('journald', journald)) as przeniesione(nazwa, wartosc)
on conflict do nothing;

drop table host_capabilities;
