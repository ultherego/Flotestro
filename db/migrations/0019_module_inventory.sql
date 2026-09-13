-- The inventory split into modules.
--
-- Until now the whole host state was one revision: a change of one package
-- counter rewrote the hardware, accounts and identity too, and the interface
-- showed one observation date for all the tabs at once. An operator looking at
-- the packages tab saw the freshness of something else.
--
-- Every module now has its own revision, its own source and its own
-- unavailability reason. An empty module and an unread module are two different pieces of information.
create table host_module_inventory (
    host_id            uuid        not null references hosts (id) on delete cascade,
    module             text        not null,
    revision           text        not null,
    -- What it was measured with, e.g. "agent/systemctl". Data without a source
    -- cannot be assessed: the operator does not know whether they look at a kernel read or a cache.
    source             text        not null,
    payload            jsonb       not null,
    unavailable_reason text,
    observed_at        timestamptz not null,
    updated_at         timestamptz not null default now(),
    primary key (host_id, module)
);

create index host_module_inventory_module_idx on host_module_inventory (module);
