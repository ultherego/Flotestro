-- The epoch of a host's session is the fencing token of the takeover rule:
-- the higher number is the session that counts, and the lower one is
-- closed. Two gateways opening a session for the same host at the same
-- moment each computed max(epoch) + 1 in their own transaction and could
-- both get the same number, and then neither closed the other. The
-- database now refuses the second one; the gateway retries with a higher
-- number.
--
-- A duplicate that already exists is renumbered by the start order before
-- the index goes on, the way the epochs were backfilled when they were
-- introduced: within a host only the order matters.
with numbered as (
    select id, row_number() over (partition by host_id order by epoch, started_at, id) as position
    from agent_sessions
    where host_id in (
        select host_id from agent_sessions group by host_id, epoch having count(*) > 1
    )
)
update agent_sessions set epoch = numbered.position
from numbered where agent_sessions.id = numbered.id;

create unique index agent_sessions_host_epoch_key on agent_sessions (host_id, epoch);
