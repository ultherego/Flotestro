-- A campaign is the main mechanism of fleet changes. The selector is turned
-- into an immutable host snapshot at planning time: a host added to the fleet
-- after approval cannot enter a running campaign without the operator knowing.

create table campaigns (
    id             uuid        primary key,
    name           text        not null,
    action_type    text        not null,
    payload        jsonb       not null default '{}'::jsonb,
    -- The selector is recorded for the audit; the targets in campaign_targets are binding.
    selector       jsonb       not null default '{}'::jsonb,

    state          text        not null
                       check (state in ('planned', 'awaiting_approval', 'canary', 'running',
                                        'paused', 'completed', 'failed', 'canceled')),

    -- The canary is a small representative group; wave 0 is always the canary.
    canary_size    integer     not null default 1 check (canary_size >= 0),
    wave_size      integer     not null default 10 check (wave_size > 0),
    -- The concurrent host limit protects the link and the site repository.
    max_concurrent integer     not null default 5 check (max_concurrent > 0),

    -- Stop thresholds. Exceeding either one pauses the campaign.
    failure_threshold_percent  integer not null default 20
                                   check (failure_threshold_percent between 0 and 100),
    failure_threshold_absolute integer not null default 0 check (failure_threshold_absolute >= 0),

    maintenance_start timestamptz,
    maintenance_end   timestamptz,
    -- The reboot policy: never, if_required or always.
    reboot_policy     text not null default 'never'
                          check (reboot_policy in ('never', 'if_required', 'always')),
    -- Units checked after the change and after the reboot.
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
    -- Wave 0 is the canary; the next waves start only once the previous one closes.
    wave          integer     not null check (wave >= 0),
    position      integer     not null,

    state         text        not null default 'pending'
                      check (state in ('pending', 'running', 'rebooting', 'verifying',
                                       'succeeded', 'failed', 'skipped', 'canceled')),
    job_id        uuid        references jobs (id) on delete set null,
    reboot_job_id uuid        references jobs (id) on delete set null,
    health_job_id uuid        references jobs (id) on delete set null,
    -- The boot ID from before the reboot; a change means the host really came up.
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
