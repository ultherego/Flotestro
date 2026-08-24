-- Magazyn sekretow.
--
-- Wartosc sekretu nie moze pojawic sie ani w zadaniu, ani w audycie, ani
-- w inwentarzu. Zadanie niesie sam odnosnik; host siega po tresc dopiero
-- wtedy, gdy zaczyna operacje, i tylko na podstawie krotkiej dzierzawy
-- wystawionej dla tego jednego zadania.
--
-- Tresc lezy zaszyfrowana kluczem, ktorego nie ma w bazie: bez pliku klucza
-- kopia bazy nie wystarcza, zeby cokolwiek odczytac.
create table if not exists secrets (
    id              uuid        primary key default gen_random_uuid(),
    name            text        not null unique,
    description     text,
    -- Wersja biezaca; odnosnik bez wersji wskazuje wlasnie ja.
    current_version int         not null default 0,
    created_by      text        not null,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    -- Sekret wycofany zostaje w tabeli razem z historia, ale nie da sie go
    -- juz wydac: slad po tym, ze istnial, jest czescia audytu.
    retired_at      timestamptz
);

create table if not exists secret_versions (
    secret_id  uuid        not null references secrets(id) on delete cascade,
    version    int         not null,
    -- Nonce i szyfrogram sa jedynym miejscem, w ktorym wartosc istnieje.
    nonce      bytea       not null,
    ciphertext bytea       not null,
    -- Rozmiar jawny sluzy do pokazania operatorowi, ze wersja nie jest pusta,
    -- bez odszyfrowywania czegokolwiek.
    size_bytes int         not null,
    created_by text        not null,
    created_at timestamptz not null default now(),
    -- Zniszczona wersja traci szyfrogram, a nie wiersz: historia ma pokazac,
    -- ze wersja istniala i kiedy przestala.
    destroyed_at timestamptz,
    primary key (secret_id, version)
);

-- Dzierzawa jest krotka, jednorazowa i zwiazana z zadaniem oraz hostem.
create table if not exists secret_leases (
    id          uuid        primary key default gen_random_uuid(),
    secret_id   uuid        not null references secrets(id) on delete cascade,
    version     int         not null,
    job_id      uuid        not null references jobs(id) on delete cascade,
    host_id     uuid        not null references hosts(id) on delete cascade,
    issued_at   timestamptz not null default now(),
    expires_at  timestamptz not null,
    redeemed_at timestamptz,
    revoked_at  timestamptz
);

create index if not exists secret_leases_job_idx on secret_leases (job_id);
create index if not exists secret_leases_expiry_idx on secret_leases (expires_at)
    where redeemed_at is null and revoked_at is null;
