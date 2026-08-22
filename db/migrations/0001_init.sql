-- Fundament: tozsamosc hosta, PKI agenta, inventory i audyt.
-- Zgodnie z modelem danych: pola uzywane do filtrowania i autoryzacji sa
-- znormalizowane, surowy inventory trafia do JSONB.

create table hosts (
    id                       uuid primary key,
    machine_id               text        not null unique,
    hostname                 text        not null,
    site                     text        not null default 'default',
    environment              text        not null default 'unassigned',
    owner                    text,
    lifecycle_state          text        not null default 'active'
                                 check (lifecycle_state in ('active', 'quarantined', 'retired')),

    os_family                text,
    os_distribution          text,
    os_version               text,
    architecture             text,
    agent_version            text,

    connection_state         text        not null default 'unknown'
                                 check (connection_state in ('online', 'offline', 'stale', 'unknown')),
    last_seen_at             timestamptz,
    boot_id                  text,

    reboot_required          boolean     not null default false,
    failed_units             integer     not null default 0,
    pending_updates          integer     not null default 0,
    pending_security_updates integer     not null default 0,

    current_inventory_revision text,
    enrolled_at              timestamptz not null default now(),
    created_at               timestamptz not null default now(),
    updated_at               timestamptz not null default now()
);

create index hosts_connection_state_idx on hosts (connection_state, last_seen_at desc);
create index hosts_site_env_idx         on hosts (site, environment);
create index hosts_os_idx               on hosts (os_family, os_version);
create index hosts_attention_idx        on hosts (reboot_required, failed_units)
    where reboot_required or failed_units > 0;

-- Token enrollmentu jest jednorazowy lub ograniczony liczba uzyc i zawsze
-- zwiazany z site/environment. W bazie trzymamy wylacznie skrot.
create table enrollment_tokens (
    id          uuid        primary key,
    token_hash  bytea       not null unique,
    description text,
    site        text        not null default 'default',
    environment text        not null default 'unassigned',
    max_uses    integer     not null default 1 check (max_uses > 0),
    uses        integer     not null default 0 check (uses >= 0),
    expires_at  timestamptz not null,
    revoked_at  timestamptz,
    created_by  text        not null default 'system',
    created_at  timestamptz not null default now()
);

create index enrollment_tokens_active_idx on enrollment_tokens (expires_at)
    where revoked_at is null;

create table agent_certificates (
    id                 uuid        primary key,
    host_id            uuid        not null references hosts (id) on delete cascade,
    serial             text        not null unique,
    fingerprint_sha256 bytea       not null unique,
    subject_common_name text       not null,
    not_before         timestamptz not null,
    not_after          timestamptz not null,
    revoked_at         timestamptz,
    revocation_reason  text,
    created_at         timestamptz not null default now()
);

create index agent_certificates_host_idx on agent_certificates (host_id, not_after desc);

create table host_capabilities (
    host_id     uuid        primary key references hosts (id) on delete cascade,
    systemd     boolean     not null default false,
    apt         boolean     not null default false,
    dnf         boolean     not null default false,
    docker      boolean     not null default false,
    journald    boolean     not null default false,
    detail      jsonb       not null default '{}'::jsonb,
    observed_at timestamptz not null default now()
);

-- Rewizje sa niemutowalne. Ta sama tresc daje ta sama rewizje, wiec powtorzony
-- raport nie tworzy nowego wiersza.
create table inventory_revisions (
    id             uuid        primary key,
    host_id        uuid        not null references hosts (id) on delete cascade,
    revision       text        not null,
    is_full        boolean     not null,
    schema_version text        not null,
    payload        jsonb       not null,
    observed_at    timestamptz not null default now(),
    created_at     timestamptz not null default now(),
    unique (host_id, revision)
);

create index inventory_revisions_host_time_idx on inventory_revisions (host_id, observed_at desc);

create table agent_sessions (
    id                 uuid        primary key,
    host_id            uuid        not null references hosts (id) on delete cascade,
    gateway_id         text        not null,
    cert_fingerprint   bytea       not null,
    remote_addr        text,
    agent_version      text,
    boot_id            text,
    started_at         timestamptz not null default now(),
    last_heartbeat_at  timestamptz,
    ended_at           timestamptz,
    end_reason         text
);

create index agent_sessions_host_idx   on agent_sessions (host_id, started_at desc);
create index agent_sessions_active_idx on agent_sessions (gateway_id) where ended_at is null;

-- Audyt jest append-only. Kazda sciezka sukcesu i bledu tworzy zdarzenie.
create table audit_events (
    id           bigserial   primary key,
    occurred_at  timestamptz not null default now(),
    actor_type   text        not null check (actor_type in ('user', 'agent', 'system')),
    actor_id     text        not null,
    action       text        not null,
    target_type  text,
    target_id    text,
    request_id   text,
    outcome      text        not null check (outcome in ('success', 'failure', 'denied')),
    detail       jsonb       not null default '{}'::jsonb
);

create index audit_events_time_idx   on audit_events (occurred_at desc);
create index audit_events_target_idx on audit_events (target_type, target_id, occurred_at desc);
create index audit_events_actor_idx  on audit_events (actor_type, actor_id, occurred_at desc);

create or replace function audit_events_immutable() returns trigger as $$
begin
    raise exception 'audit_events jest append-only: % nie jest dozwolone', tg_op;
end;
$$ language plpgsql;

create trigger audit_events_no_update before update on audit_events
    for each row execute function audit_events_immutable();

create trigger audit_events_no_delete before delete on audit_events
    for each row execute function audit_events_immutable();
