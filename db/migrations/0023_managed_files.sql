-- Pliki konfiguracyjne zarzadzane przez panel.
--
-- Stan docelowy trzymamy w panelu, a nie tylko na hoscie: bez tego nie da sie
-- powiedziec, czy plik na hoscie zostal zmieniony poza panelem, ani wrocic do
-- tresci sprzed zmiany. Tresci sa adresowane odciskiem, wiec ta sama
-- konfiguracja na stu hostach zajmuje miejsce raz.
create table if not exists file_versions (
    sha256     text        primary key,
    content    bytea       not null,
    size_bytes bigint      not null,
    created_at timestamptz not null default now()
);

create table if not exists managed_files (
    host_id        uuid        not null references hosts(id) on delete cascade,
    path           text        not null,
    desired_sha256 text        not null references file_versions(sha256),
    mode           text,
    owner_name     text,
    group_name     text,
    validator      text,
    updated_by     text        not null,
    updated_at     timestamptz not null default now(),
    primary key (host_id, path)
);

-- Historia zmian pliku. Rollback jest powrotem do konkretnej wersji, a nie
-- "cofnij ostatnia zmiane": operator wybiera tresc, ktora widzial.
create table if not exists managed_file_history (
    id         uuid        primary key default gen_random_uuid(),
    host_id    uuid        not null references hosts(id) on delete cascade,
    path       text        not null,
    sha256     text        not null references file_versions(sha256),
    job_id     uuid        references jobs(id) on delete set null,
    applied_by text        not null,
    applied_at timestamptz not null default now()
);

create index if not exists managed_file_history_plik_idx
    on managed_file_history(host_id, path, applied_at desc);
