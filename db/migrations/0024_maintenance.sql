-- The maintenance window of a host.
--
-- Maintenance is not a lifecycle state: a host in a maintenance window runs,
-- is managed and accepts manually ordered operations. One thing changes -
-- campaigns skip it, and its alerts wake nobody at night. Hence separate
-- columns, not another lifecycle_state value.
--
-- A window has a deadline, not a flag: "in maintenance until further notice"
-- ends with a host everybody forgot and nobody has updated for half a year.
alter table hosts
    add column if not exists maintenance_until  timestamptz,
    add column if not exists maintenance_reason text,
    add column if not exists maintenance_by     text,
    add column if not exists maintenance_at     timestamptz;

-- Campaigns ask for hosts outside a maintenance window at every wave.
create index if not exists hosts_maintenance_idx
    on hosts (maintenance_until) where maintenance_until is not null;
