-- The replicas of the control plane, by the identifier they answer under.
--
-- FLOTESTRO_GATEWAY_ID is not a label. It is written into the sessions of
-- the agents, into the lease of every job a replica takes, and into the
-- audit trail as the actor of everything the machinery does by itself. Two
-- replicas started with the same identifier are therefore not two replicas
-- to the rest of the product: the scheduler reads a lease taken by the
-- other one as its own and dispatches the job twice, and the session
-- fencing cannot tell the two apart because there is nothing in the row
-- that differs. It is the one misconfiguration of chapter 21 that nothing
-- downstream can detect, because every mechanism that would detect it reads
-- exactly that identifier.
--
-- So the identifier is claimed rather than declared. One row per gateway
-- identifier, holding the process that has it and a heartbeat that process
-- renews. A start that finds its identifier held by a record whose
-- heartbeat is still moving refuses: another replica is alive under it. A
-- start that finds a record nobody renews any more takes it over, which is
-- what an ordinary restart looks like from here.
--
-- The row also carries the pool the replica was allowed to open, because
-- the connection budget of the installation is the sum over the replicas
-- and no single replica knows the others. It is what lets the panel answer
-- "would another replica fit" before somebody scales rather than after.
create table if not exists control_plane_instances (
    gateway_id        text        primary key,
    -- The process, not the deployment: it is drawn anew at every start, so
    -- a row that names another process is either a live replica or the
    -- remains of one that died.
    instance_id       uuid        not null,
    hostname          text        not null default '',
    version           text        not null default '',
    -- What this replica may open against the database. Zero means a
    -- replica that did not say, and the budget then counts it as unknown
    -- rather than as nothing.
    pool_max_conns    int         not null default 0,
    started_at        timestamptz not null default now(),
    last_heartbeat_at timestamptz not null default now(),
    -- Grows every time the identifier changes hands, so a takeover is
    -- visible in the row itself and not only in the log of the process
    -- that did it.
    revision          bigint      not null default 0
);

comment on table control_plane_instances is
    'One row per FLOTESTRO_GATEWAY_ID: the control-plane process that holds it, its heartbeat and the connection pool it may open. A start refuses an identifier whose heartbeat is still being renewed by another process.';
comment on column control_plane_instances.instance_id is
    'The process that holds the identifier, drawn anew at every start; a heartbeat that stops moving is what lets the next start take the row over.';
comment on column control_plane_instances.pool_max_conns is
    'The maximum connections this replica may open; the budget of the installation is the sum over the live rows, against max_connections of the server.';

-- The status screen and every claim read the live rows by their heartbeat.
create index if not exists control_plane_instances_heartbeat_idx
    on control_plane_instances (last_heartbeat_at desc);
