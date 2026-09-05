-- Certyfikaty na hostach.
--
-- Panel trzyma u siebie dwie rzeczy, ktorych host sam nie powie. Pierwsza to
-- zakres: ktore pliki sa certyfikatami uslug i ktora usluga je czyta - tego
-- nie da sie wywnioskowac z nazwy katalogu, a przeszukiwanie calego dysku
-- znajduje magazyn zaufania zamiast odpowiedzi. Druga to historia wdrozen:
-- co panel wyslal, kiedy i na czyje polecenie.
--
-- Klucza prywatnego nie ma tu w zadnej postaci. Jest wylacznie nazwa sekretu
-- w magazynie - odnosnik, ktory bez magazynu i bez pliku klucza nie znaczy nic.
create table if not exists certificate_targets (
    id           uuid        primary key default gen_random_uuid(),
    host_id      uuid        not null references hosts(id) on delete cascade,
    path         text        not null,
    key_path     text        not null default '',
    -- Nazwa sekretu z kluczem prywatnym. Wartosci nie ma tu ani nigdzie
    -- indziej poza magazynem.
    key_secret   text        not null default '',
    -- Jednostka, ktora ten plik czyta, oraz adres, pod ktorym widac skutek
    -- wdrozenia. Oba wpisuje czlowiek: panel ich nie zgaduje.
    reload_unit  text        not null default '',
    probe_target text        not null default '',
    service      text        not null default '',
    note         text        not null default '',
    created_by   text        not null,
    created_at   timestamptz not null default now(),
    updated_by   text        not null,
    updated_at   timestamptz not null default now(),
    unique (host_id, path)
);

create index if not exists certificate_targets_host_idx on certificate_targets (host_id);

-- Historia wdrozen. Certyfikat jest jawny, wiec panel moze go przechowac
-- w calosci: to pozwala pokazac, co dokladnie wyslano, i wrocic do tego,
-- co dzialalo. Klucza to nie dotyczy i dotyczyc nie moze.
create table if not exists certificate_deployments (
    id                 uuid        primary key default gen_random_uuid(),
    host_id            uuid        not null references hosts(id) on delete cascade,
    path               text        not null,
    fingerprint_sha256 text        not null,
    subject            text        not null default '',
    issuer             text        not null default '',
    not_after          timestamptz,
    certificate        text        not null default '',
    key_secret         text        not null default '',
    key_secret_version int         not null default 0,
    job_id             uuid        references jobs(id) on delete set null,
    deployed_by        text        not null,
    deployed_at        timestamptz not null default now()
);

create index if not exists certificate_deployments_host_idx
    on certificate_deployments (host_id, path, deployed_at desc);
