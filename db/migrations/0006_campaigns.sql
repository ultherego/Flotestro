-- Kampania jest glownym mechanizmem zmian flotowych. Selektor jest zamieniany
-- na niemutowalna migawke hostow w chwili planowania: host dodany do floty po
-- zatwierdzeniu nie moze wejsc do trwajacej kampanii bez wiedzy operatora.

create table campaigns (
    id             uuid        primary key,
    name           text        not null,
    action_type    text        not null,
    payload        jsonb       not null default '{}'::jsonb,
    -- Selektor jest zapisany dla audytu; wiazace sa cele w campaign_targets.
    selector       jsonb       not null default '{}'::jsonb,

    state          text        not null
                       check (state in ('planned', 'awaiting_approval', 'canary', 'running',
                                        'paused', 'completed', 'failed', 'canceled')),

    -- Canary to mala reprezentatywna grupa; fala 0 zawsze jest canary.
    canary_size    integer     not null default 1 check (canary_size >= 0),
    wave_size      integer     not null default 10 check (wave_size > 0),
    -- Limit rownoczesnych hostow chroni lacze i repozytorium lokalizacji.
    max_concurrent integer     not null default 5 check (max_concurrent > 0),

    -- Progi zatrzymania. Przekroczenie ktoregokolwiek wstrzymuje kampanie.
    failure_threshold_percent  integer not null default 20
                                   check (failure_threshold_percent between 0 and 100),
    failure_threshold_absolute integer not null default 0 check (failure_threshold_absolute >= 0),

    maintenance_start timestamptz,
    maintenance_end   timestamptz,
    -- Polityka restartu: never, if_required albo always.
    reboot_policy     text not null default 'never'
                          check (reboot_policy in ('never', 'if_required', 'always')),
    -- Jednostki sprawdzane po zmianie i po restarcie.
    health_check_units text[] not null default '{}',

    job_timeout_seconds integer not null default 1800 check (job_timeout_seconds > 0),

    requires_approval boolean     not null default true,
    approved_by       text,
    approved_at       timestamptz,
    paused_by         text,
    paused_at         timestamptz,
    pause_reason      text,
    canceled_by       text,
    canceled_at       timestamptz,

    created_by        text        not null,
    request_id        text,
    started_at        timestamptz,
    finished_at       timestamptz,
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now()
);

create index campaigns_state_idx on campaigns (state, created_at desc);
create index campaigns_active_idx on campaigns (id) where state in ('canary', 'running');

create table campaign_targets (
    id            uuid        primary key,
    campaign_id   uuid        not null references campaigns (id) on delete cascade,
    host_id       uuid        not null references hosts (id) on delete cascade,
    -- Fala 0 to canary; kolejne fale rusza dopiero po zamknieciu poprzedniej.
    wave          integer     not null check (wave >= 0),
    position      integer     not null,

    state         text        not null default 'pending'
                      check (state in ('pending', 'running', 'rebooting', 'verifying',
                                       'succeeded', 'failed', 'skipped', 'canceled')),
    job_id        uuid        references jobs (id) on delete set null,
    reboot_job_id uuid        references jobs (id) on delete set null,
    health_job_id uuid        references jobs (id) on delete set null,
    -- Boot ID sprzed restartu; zmiana oznacza, ze host faktycznie wstal.
    boot_id_before text,

    error_code    text,
    message       text,
    started_at    timestamptz,
    finished_at   timestamptz,
    created_at    timestamptz not null default now(),

    unique (campaign_id, host_id)
);

create index campaign_targets_wave_idx  on campaign_targets (campaign_id, wave, position);
create index campaign_targets_state_idx on campaign_targets (campaign_id, state);
create index campaign_targets_job_idx   on campaign_targets (job_id) where job_id is not null;
