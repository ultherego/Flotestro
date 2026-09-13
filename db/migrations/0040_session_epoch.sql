-- The session epoch decides which host session is the authoritative one.
--
-- A host connects to one gateway at a time, but when switching between
-- gateways the old session may still live: the second gateway does not know
-- about the first, and an HTTP/2 stream broken on the host side is sometimes
-- seen by the server with a delay. Without a decision both gateways would
-- consider themselves authoritative and the same job would go out twice.
--
-- The number grows within a host, so the comparison is local and needs no
-- clock, which on two machines is not the same anyway.
alter table agent_sessions add column epoch bigint not null default 0;

-- Backfilling the history: the start order is the only truth there is here,
-- and it is enough - all that counts is that a newer session has a higher number.
with numeracja as (
    select id, row_number() over (partition by host_id order by started_at, id) as numer
    from agent_sessions
)
update agent_sessions set epoch = numeracja.numer
from numeracja where agent_sessions.id = numeracja.id;

create index agent_sessions_epoch_idx on agent_sessions (host_id, epoch desc);
