-- Inventory rozbite na moduly.
--
-- Dotad caly stan hosta byl jedna rewizja: zmiana jednego licznika pakietow
-- przepisywala rowniez sprzet, konta i tozsamosc, a interfejs pokazywal jedna
-- date obserwacji dla wszystkich zakladek naraz. Operator patrzacy na zakladke
-- pakietow widzial swiezosc czegos innego.
--
-- Kazdy modul ma teraz wlasna rewizje, wlasne zrodlo i wlasny powod
-- niedostepnosci. Pusty modul i modul nieodczytany to dwie rozne informacje.
create table host_module_inventory (
    host_id            uuid        not null references hosts (id) on delete cascade,
    module             text        not null,
    revision           text        not null,
    -- Czym zmierzono, np. "agent/systemctl". Dane bez zrodla nie daja sie
    -- ocenic: operator nie wie, czy patrzy na odczyt jadra, czy na cache.
    source             text        not null,
    payload            jsonb       not null,
    unavailable_reason text,
    observed_at        timestamptz not null,
    updated_at         timestamptz not null default now(),
    primary key (host_id, module)
);

create index host_module_inventory_module_idx on host_module_inventory (module);
