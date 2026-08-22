-- Operacje typowane: jedna operacja logiczna na jednym hoscie to job,
-- kazde jej uruchomienie to attempt. Rozdzielenie jest konieczne, bo sieć moze
-- dostarczyc zadanie ponownie, a lease moze wygasnac w trakcie wykonania.

create table jobs (
    id                uuid        primary key,
    host_id           uuid        not null references hosts (id) on delete cascade,
    campaign_id       uuid,

    action_type       text        not null,
    action_version    integer     not null default 1,
    payload           jsonb       not null,
    -- Hash planu zatwierdzonego przez czlowieka. Agent porownuje go z trescia
    -- koperty, wiec podmiana payloadu po approvalu jest wykrywalna.
    payload_hash      bytea       not null,
    -- Klucz idempotencji jest unikalny w obrebie hosta: ponowne zlecenie tej
    -- samej operacji nie tworzy drugiego joba.
    idempotency_key   text        not null,

    state             text        not null
                          check (state in ('planned', 'awaiting_approval', 'queued', 'leased',
                                           'dispatched', 'running', 'succeeded', 'failed',
                                           'timed_out', 'canceled', 'expired')),
    requires_approval boolean     not null default false,

    preconditions     jsonb       not null default '{}'::jsonb,
    timeout_seconds   integer     not null default 60 check (timeout_seconds > 0),
    max_output_bytes  integer     not null default 65536 check (max_output_bytes > 0),
    -- Bezwzgledny TTL: zadanie po terminie nie jest wykonywane po powrocie sieci.
    expires_at        timestamptz not null,

    created_by        text        not null,
    request_id        text,
    approved_by       text,
    approved_at       timestamptz,
    canceled_by       text,
    canceled_at       timestamptz,
    cancel_reason     text,

    result_status     text,
    result_error_code text,
    result_message    text,
    finished_at       timestamptz,

    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now(),

    unique (host_id, idempotency_key)
);

create index jobs_host_idx    on jobs (host_id, created_at desc);
create index jobs_state_idx   on jobs (state, expires_at);
-- Indeks kolejki: scheduler pobiera wylacznie zadania gotowe do wykonania.
create index jobs_runnable_idx on jobs (created_at) where state = 'queued';

create table job_attempts (
    id                uuid        primary key,
    job_id            uuid        not null references jobs (id) on delete cascade,
    attempt_number    integer     not null check (attempt_number > 0),

    -- Lease chroni przed dwoma gatewayami wykonujacymi to samo zadanie.
    lease_owner       text,
    lease_expires_at  timestamptz,
    gateway_id        text,
    session_id        uuid,

    status            text,
    exit_code         integer,
    error_code        text,
    message           text,
    -- Output jest ograniczony przez max_output_bytes joba. Duze wyniki naleza
    -- do object storage; tu trzymamy wylacznie bounded output.
    stdout            text,
    stderr            text,
    output_truncated  boolean     not null default false,
    replayed          boolean     not null default false,
    unit_state_before jsonb,
    unit_state_after  jsonb,

    dispatched_at     timestamptz,
    started_at        timestamptz,
    finished_at       timestamptz,
    created_at        timestamptz not null default now(),

    unique (job_id, attempt_number)
);

create index job_attempts_job_idx   on job_attempts (job_id, attempt_number desc);
-- Wygasle lease trzeba znalezc szybko, zeby zadanie wrocilo do kolejki.
create index job_attempts_lease_idx on job_attempts (lease_expires_at)
    where lease_expires_at is not null and finished_at is null;
