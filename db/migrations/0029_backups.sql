-- Backup: definicje i historia przebiegow.
--
-- Dane backupowe nie plyna przez panel i nie ma ich w tej bazie. Sa tu
-- wylacznie metadane: co jest backupowane, dokad, jak dlugo zostaje i kiedy
-- ostatnia kopia sie udala. Panel, przez ktory plynelyby kopie stu hostow,
-- bylby waskim gardlem i najciekawszym celem w calej instalacji.
--
-- Poswiadczenia sa nazwami sekretow, nie wartosciami: haslo repozytorium
-- i zmienne srodowiskowe narzedzia zyja w magazynie i tylko tam.
create table if not exists backup_definitions (
    id             uuid        primary key default gen_random_uuid(),
    host_id        uuid        not null references hosts(id) on delete cascade,
    name           text        not null,
    tool           text        not null,
    repository     text        not null default '',
    paths          text[]      not null default '{}',
    excludes       text[]      not null default '{}',
    tags           text[]      not null default '{}',
    keep_last      int         not null default 0,
    keep_daily     int         not null default 0,
    keep_weekly    int         not null default 0,
    keep_monthly   int         not null default 0,
    prune          boolean     not null default false,
    runbook        text        not null default '',
    -- Zgoda na zalozenie repozytorium przy pierwszej kopii. Bez niej host
    -- niczego nie tworzy: repozytorium powstale przez literowke w adresie
    -- wyglada jak backup, ktory dziala.
    initialize     boolean     not null default false,
    -- Nazwa sekretu z haslem repozytorium oraz przypisanie zmiennych
    -- srodowiskowych do sekretow. Nazwy, nie wartosci.
    password_secret text       not null default '',
    env_secrets    jsonb       not null default '{}'::jsonb,
    note           text        not null default '',
    created_by     text        not null,
    created_at     timestamptz not null default now(),
    updated_by     text        not null,
    updated_at     timestamptz not null default now(),
    unique (host_id, name)
);

create index if not exists backup_definitions_host_idx on backup_definitions (host_id);

-- Historia przebiegow. Definicja moze zniknac, a historia zostaje: to, ze
-- kopia byla robiona i kiedy ostatnio sie udala, jest faktem, ktorego
-- skasowanie definicji nie odwraca.
create table if not exists backup_runs (
    id               uuid        primary key default gen_random_uuid(),
    host_id          uuid        not null references hosts(id) on delete cascade,
    definition       text        not null,
    -- Rodzaj: plan, run, verify albo restore.
    kind             text        not null,
    job_id           uuid        references jobs(id) on delete set null,
    outcome          text        not null,
    snapshot_id      text        not null default '',
    bytes_added      bigint,
    total_bytes      bigint,
    files_new        bigint,
    duration_seconds double precision,
    -- Pola z planu: ile kopii jest w repozytorium, ile zajmuja i kiedy
    -- powstala najnowsza.
    snapshots        int,
    repository_size  bigint,
    last_success_at  timestamptz,
    message          text        not null default '',
    started_by       text        not null default '',
    recorded_at      timestamptz not null default now()
);

create index if not exists backup_runs_host_idx
    on backup_runs (host_id, definition, recorded_at desc);
