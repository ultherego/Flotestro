-- The host lifecycle gets a fifth state and a memory of retired machines.
--
-- "recovery" is the host between an identity recovery order and the first
-- session of its new certificate. It takes no operation and gets no secret,
-- like a quarantined host, but the old certificate may still open a session
-- for a day: the operator recovering a key wants to keep reading the host
-- until the new key proves it works. "retiring" stays: it is the host in the
-- decommission handshake, between the final task and the final commit.
do $$
begin
    if exists (select 1 from pg_constraint where conname = 'hosts_lifecycle_state_check') then
        alter table hosts drop constraint hosts_lifecycle_state_check;
    end if;
    alter table hosts add constraint hosts_lifecycle_state_check
        check (lifecycle_state in ('active', 'quarantined', 'recovery', 'retiring', 'retired'));
end $$;

-- A retired machine does not come back as a new host for a while. The
-- machine identifier is refused for a "new host" token until this moment:
-- a machine handed over with its disk intact must not slip back into the
-- fleet under a fresh name on the strength of a token alone.
alter table hosts
    add column if not exists retired_machine_id_until timestamptz;
