-- The host lifecycle has a fourth state and its own memory of the reason.
--
-- Between "running" and "retired" there is a moment when the panel no longer
-- orders anything new, but the host still finishes what it started. Without
-- that state retirement either cuts the work off halfway or lets another be ordered.
do $$
begin
    if exists (select 1 from pg_constraint where conname = 'hosts_lifecycle_state_check') then
        alter table hosts drop constraint hosts_lifecycle_state_check;
    end if;
    alter table hosts add constraint hosts_lifecycle_state_check
        check (lifecycle_state in ('active', 'quarantined', 'retiring', 'retired'));
end $$;

alter table hosts
    -- The reason for the state change is part of the decision, not a comment:
    -- a quarantined host without a reason is a host nobody remembers any
    -- more why it was cut off.
    add column if not exists lifecycle_reason     text        not null default '',
    add column if not exists lifecycle_changed_at timestamptz,
    add column if not exists lifecycle_changed_by text        not null default '',
    add column if not exists retired_at           timestamptz;

create index if not exists hosts_lifecycle_idx on hosts (lifecycle_state)
    where lifecycle_state <> 'active';
