-- Pelna lista zainstalowanych pakietow hosta.
--
-- Panel trzyma ja u siebie, bo bez niej nie da sie odpowiedziec na pytanie
-- o podatnosci: tracker bezpieczenstwa dystrybucji mowi o pakiecie zrodlowym
-- i wersji, a nie o hoscie. Lista jest pobierana na zadanie - inwentarz niesie
-- sam odcisk, wiec panel wie, kiedy jego kopia przestala opisywac host.
--
-- Wierszy nie ma dla hosta, ktorego jeszcze nie zapytano. To jest stan
-- "nie wiadomo", a nie "host czysty" - i tak musi byc pokazany.
create table if not exists host_packages (
    host_id       uuid        not null references hosts(id) on delete cascade,
    name          text        not null,
    architecture  text        not null default '',
    -- Epoka pusta oznacza pakiet bez epoki; zero i brak epoki znacza dla
    -- porownania to samo, ale w zapisie sa rozne.
    epoch         text        not null default '',
    version       text        not null,
    release       text        not null default '',
    -- Pakiet zrodlowy: Debian prowadzi bezpieczenstwo wlasnie po nim, a jeden
    -- zrodlowy daje kilkanascie binarnych.
    source_name    text       not null default '',
    source_version text       not null default '',
    source_rpm     text       not null default '',
    vendor         text       not null default '',
    repository_id  text       not null default '',
    module_stream  text       not null default '',
    primary key (host_id, name, architecture, version, release)
);

create index if not exists host_packages_source_idx on host_packages (source_name);
create index if not exists host_packages_name_idx on host_packages (name);

-- Stan listy: odcisk tego, co panel ma u siebie, oraz to, co ostatnio zglosil
-- host. Rozjazd miedzy nimi znaczy, ze kopia jest nieaktualna - i wtedy ocena
-- podatnosci dla tego hosta jest niepelna, a nie pusta.
create table if not exists host_package_state (
    host_id            uuid        primary key references hosts(id) on delete cascade,
    digest             text        not null default '',
    package_count      int         not null default 0,
    collected_at       timestamptz,
    job_id             uuid        references jobs(id) on delete set null,
    unavailable_reason text        not null default ''
);
