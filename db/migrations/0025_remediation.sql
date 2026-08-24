-- Plan naprawy jako byt trwaly.
--
-- Naprawa wieloetapowa nie miesci sie w jednym zadaniu: kroki musza isc po
-- kolei, kazdy z wlasnym zatwierdzeniem, a to, co zostalo wykonane przed
-- bledem, musi byc widoczne. Bez tabeli panel po restarcie nie wiedzialby,
-- ktore kroki juz poszly, a operator zobaczylby garsc niepowiazanych zadan.
create table if not exists remediation_plans (
    id                uuid        primary key default gen_random_uuid(),
    host_id           uuid        not null references hosts(id) on delete cascade,
    -- Odcisk wiaze plan ze stanem hosta, ktory operator ogladal, a wersja
    -- kanonizacji mowi, wedlug jakich zasad go policzono.
    plan_hash         text        not null,
    plan_hash_version int         not null,
    reason            text        not null,
    created_by        text        not null,
    -- Zatrzymanie po bledzie jest domyslne: kolejne kroki zakladaja, ze
    -- poprzednie sie udaly.
    stop_on_failure   boolean     not null default true,
    state             text        not null
                                  check (state in ('running', 'succeeded', 'failed', 'stopped')),
    created_at        timestamptz not null default now(),
    finished_at       timestamptz
);

create table if not exists remediation_steps (
    id              uuid        primary key default gen_random_uuid(),
    plan_id         uuid        not null references remediation_plans(id) on delete cascade,
    -- Pozycja jest zaleznoscia: krok rusza dopiero, gdy poprzedni sie udal.
    position        int         not null,
    check_id        text        not null,
    check_version   int         not null,
    action_type     text        not null,
    payload         jsonb       not null,
    -- Klasa blokady zasobu hosta. Dwa kroki tej samej klasy nie moga isc
    -- rownolegle - i nie ida, bo plan wykonuje jeden krok naraz.
    lock_class      text        not null default '',
    -- Krok konczacy plan: po restarcie stan hosta trzeba ocenic na nowo.
    requires_reboot boolean     not null default false,
    job_id          uuid        references jobs(id) on delete set null,
    state           text        not null
                                check (state in ('pending', 'running', 'succeeded', 'failed', 'skipped')),
    reason          text,
    started_at      timestamptz,
    finished_at     timestamptz,
    unique (plan_id, position)
);

create index if not exists remediation_plans_host_idx
    on remediation_plans (host_id, created_at desc);
-- Runner pyta o plany w toku przy kazdym cyklu.
create index if not exists remediation_plans_running_idx
    on remediation_plans (state) where state = 'running';
