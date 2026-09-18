-- The orders one control-plane instance leaves for another to carry out on
-- the host whose session it holds.
--
-- Everything that only needs the database already crosses the instances:
-- the scheduler reads its own hosts, a cancel travels on the job's row, a
-- write is fenced by host_session_owners. What does not cross is the work
-- that needs the host's open stream. The decommission handshake is the
-- clearest case: the instance that took the request looks in its own
-- registry of sessions, finds nothing, and retires the host as if it were
-- offline - while the host is connected to the instance next to it,
-- answering heartbeats, and never hears the final task at all. The same
-- goes for ending a session at a quarantine or an identity recovery: the
-- session stays open on the other instance until its lease runs out.
--
-- A command is one such order, addressed not to an instance but to a
-- session: the session host_session_owners named when the decision was
-- taken, with the fencing token of that claim. Only the instance that
-- still holds exactly that session may claim it, and it checks the session
-- again in its own registry before it acts. An instance that has since
-- lost the host claims nothing, and a command whose session is gone is
-- never carried out - it expires and says so, and the caller falls back to
-- what the panel does for a host nobody holds.
--
-- The row is written in the transaction of the decision that caused it: a
-- decommission that did not commit leaves no order behind. The outcome is
-- written back on the same row, so the instance that took the request can
-- answer the operator with what really happened on the host.
create table if not exists gateway_commands (
    id             uuid        primary key default gen_random_uuid(),
    host_id        uuid        not null references hosts (id) on delete cascade,
    -- session_id and fencing_token address the command. They are not a
    -- description of the host's state at the time: they are the condition
    -- under which the order may still be carried out.
    session_id     uuid        not null,
    fencing_token  bigint      not null,
    kind           text        not null,
    payload        jsonb       not null default '{}'::jsonb,
    created_by     text        not null default '',
    created_at     timestamptz not null default now(),
    claimed_at     timestamptz,
    claimed_by     uuid,
    done_at        timestamptz,
    -- outcome is done, failed, no_session or expired; outcome_detail is
    -- what the instance that carried it out has to say - for a
    -- decommission, the whole outcome of the handshake, which the answer
    -- to the operator is built from.
    outcome        text,
    outcome_detail jsonb,
    -- expires_at bounds the wait. An order nobody claimed by then is not
    -- carried out late: the host has moved on, and the panel would be
    -- acting on a decision whose moment has passed.
    expires_at     timestamptz not null
);

comment on table gateway_commands is
    'Lifecycle orders addressed to the control-plane instance that holds a host session: the final task of a decommission, the end of a session. Claimed only by the owner of the named session under the named fencing token.';
comment on column gateway_commands.session_id is
    'The session the order is for, as host_session_owners named it when the decision was taken; an instance holding another session of the host claims nothing.';
comment on column gateway_commands.fencing_token is
    'The token of that claim; a command carrying a token the host has grown past is never carried out.';
comment on column gateway_commands.outcome is
    'done: carried out; failed: the owner took it and could not finish; no_session: the owner no longer held the session; expired: nobody claimed it in time.';

-- The claim of every instance reads the open commands in the order they
-- were written; the rows already settled are not in the index, so the
-- queue stays the size of what is outstanding rather than of the history.
create index if not exists gateway_commands_open_idx
    on gateway_commands (created_at)
    where done_at is null;

-- The answer to the operator waits on one row by its identifier, and the
-- host page reads the orders of one host; both go by these.
create index if not exists gateway_commands_host_idx
    on gateway_commands (host_id, created_at desc);
