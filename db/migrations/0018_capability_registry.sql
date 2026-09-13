-- The host adapter registry.
--
-- Earlier the capabilities were five boolean fields. A boolean does not say
-- why an adapter is missing, nor that it is there but read-only, nor that it
-- can do part of the things - and the operator needs all three. Package
-- database repair works only for apt and the host is to say so before the job
-- is approved and sent.
create table host_capability_registry (
    host_id     uuid        not null references hosts(id) on delete cascade,
    -- The adapter name, not the operation requirement name: 'packages.apt', not 'packages'.
    name        text        not null,
    -- The adapter contract version. The tool version is a fact about the host
    -- and belongs to the inventory.
    version     int         not null default 1,
    available   boolean     not null,
    read_only   boolean     not null default false,
    reason      text,
    features    jsonb       not null default '{}'::jsonb,
    observed_at timestamptz not null default now(),
    primary key (host_id, name)
);

-- Filtering the fleet by adapter: "show the hosts that have apt".
create index host_capability_registry_name_idx
    on host_capability_registry (name) where available;

-- Hosts from before the registry keep what is known about them until the
-- agent's next connection. The reason is empty, because the old boolean did not carry one.
insert into host_capability_registry (host_id, name, available)
select host_id, nazwa, wartosc
from host_capabilities,
     lateral (values ('systemd', systemd),
                     ('packages.apt', apt),
                     ('packages.dnf', dnf),
                     ('docker', docker),
                     ('journald', journald)) as przeniesione(nazwa, wartosc)
on conflict do nothing;

drop table host_capabilities;
