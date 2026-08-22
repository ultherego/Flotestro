-- Zmiana w katalogu jest jedna transakcja biznesowa Flotestro, ale moze
-- skladac sie z kilku operacji FreeIPA. Kazda faza ma wlasny wynik, bo
-- czesciowy sukces nie moze byc przedstawiany jako zakonczone powodzeniem.

create table directory_changes (
    id                uuid        primary key,
    action_type       text        not null,
    payload           jsonb       not null,
    -- Hash planu zatwierdzonego przez czlowieka. Podmiana tresci po
    -- zatwierdzeniu jest wykrywalna.
    payload_hash      bytea       not null,
    -- Podglad wplywu: co zmiana zrobi, zanim cokolwiek sie wydarzy.
    plan              jsonb       not null default '{}'::jsonb,

    state             text        not null
                          check (state in ('planned', 'awaiting_approval', 'running',
                                           'succeeded', 'partially_applied', 'failed',
                                           'canceled')),
    requires_approval boolean     not null default true,
    approved_by       text,
    approved_at       timestamptz,
    canceled_by       text,
    canceled_at       timestamptz,

    -- Wynik kazdej fazy z osobna. Bez tego nie da sie powiedziec, co zdazylo
    -- sie zmienic przed bledem.
    phases            jsonb       not null default '[]'::jsonb,
    result_message    text,

    created_by        text        not null,
    request_id        text,
    started_at        timestamptz,
    finished_at       timestamptz,
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now()
);

create index directory_changes_state_idx on directory_changes (state, created_at desc);
create index directory_changes_actor_idx on directory_changes (created_by, created_at desc);

-- Lokalny znacznik odmowy. Ustawiany przed blokada w katalogu, zeby odebranie
-- dostepu dzialalo natychmiast, zanim zmiana zdazy sie rozpropagowac.
alter table principals add column denied_at timestamptz;
alter table principals add column denied_reason text;

create index principals_denied_idx on principals (denied_at) where denied_at is not null;
