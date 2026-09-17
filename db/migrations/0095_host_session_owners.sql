-- The durable record of which control-plane instance owns the open session
-- of a host, and the fencing token every write on that session carries.
--
-- The epoch of agent_sessions settles which session is the newest, and a
-- gateway learns of a takeover through LISTEN/NOTIFY. That is enough to
-- close the older stream quickly; it is not enough to keep the older
-- instance from writing. A notification can be late or lost, and an
-- instance that has not heard it still holds a stream that looks alive,
-- a result the agent already sent over it, and every intention of
-- recording it. The epoch is checked at the delivery, once; the result of
-- the task arrives minutes later, and by then nothing in the process
-- remembers to ask again. So every write of a delivery or a result carries
-- the token of the session it was made on, and the database refuses the
-- write when the host's row names a newer token. Ownership is decided by
-- this table alone: a restarted instance adopts nothing from its memory,
-- the sessions reconnect and claim anew.
--
-- One row per host; the token only ever grows, whatever happens to the
-- session, so a token once refused stays refused. A row whose lease ran
-- out is a host nobody owns: the scheduler delivers nothing to it until a
-- session claims it again.
create table if not exists host_session_owners (
    host_id           uuid        primary key references hosts (id) on delete cascade,
    fencing_token     bigint      not null default 0,
    session_id        uuid,
    owner_instance_id uuid,
    lease_until       timestamptz,
    connected_at      timestamptz,
    revision          bigint      not null default 0,
    updated_at        timestamptz not null default now()
);

comment on table host_session_owners is
    'Which session and control-plane instance own a host right now; the fencing token fences every write of a delivery or a result on that session.';
comment on column host_session_owners.fencing_token is
    'Grows by one with every claim and never goes back; a write carrying a lower token is refused by the database.';
comment on column host_session_owners.lease_until is
    'The owner renews it while its stream lives; past it the host has no owner and the scheduler holds its tasks.';

-- The sweep and the scheduler look for leases that ran out; the rows of
-- hosts nobody owns are not in the index.
create index if not exists host_session_owners_expiry
    on host_session_owners (lease_until)
    where session_id is not null;
