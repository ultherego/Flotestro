-- The address the agents reach the panel at, as a setting of the installation
-- rather than of the process.
--
-- FLOTESTRO_ADVERTISE was read once at start, and its default is 127.0.0.1.
-- That default is right on a laptop and wrong everywhere else, so an
-- installation started from a compose file with no questions in the terminal
-- had no way to become reachable without the operator editing the deployment
-- and restarting the control plane. The address the whole fleet dials is the
-- installation's, so the installation holds it.
--
-- The database and not the state directory: the choice has to be the same
-- answer on every replica. A state volume belongs to one replica, so two of
-- them would advertise two addresses, issue two certificates and hand two
-- agent configurations out of the same panel with nothing to say which is in
-- force.
--
-- One row. There is one panel and one address it is seen under; a key-value
-- table would let two rows disagree with nothing to decide between them.
--
-- No row at all is an installation that has confirmed nothing. It is not an
-- empty address: the environment of the process still decides, which is what
-- keeps FLOTESTRO_ADVERTISE meaningful and what keeps an existing deployment
-- behaving exactly as it did before this table existed.
--
-- N-1: a replica on the previous release never reads this table and goes on
-- advertising what its own environment names. Nothing here changes an existing
-- table, so a downgrade needs no undo.
create table if not exists advertised_address (
    singleton        boolean     primary key default true check (singleton),
    -- The names and addresses in force, in the order the agents try them. A
    -- name is an IP address or a DNS name; the panel validates that before it
    -- writes, because these go into a certificate and into a shell command.
    names            text[]      not null check (cardinality(names) > 0),
    -- The names this panel was seen under before. They stay reserved against a
    -- relay: an agent that has not been reconfigured yet still dials the old
    -- name, and a relay holding a certificate for it would answer in the
    -- panel's place. A name confirmed again leaves this list.
    superseded_names text[]      not null default '{}',
    confirmed_at     timestamptz not null default now(),
    -- Who confirmed it. A detected address is a proposal; this column records
    -- that a person decided, as the audit trail does.
    confirmed_by     text        not null default '',
    revision         bigint      not null default 1
);

comment on table advertised_address is
    'The address the agents reach this panel at, one row, confirmed by an administrator; no row means the installation confirmed nothing and the environment of the control plane still decides.';
comment on column advertised_address.names is
    'The names and addresses in force. They are the panel certificate''s subject alternative names, what a generated agent configuration dials, and what a relay may not take.';
comment on column advertised_address.superseded_names is
    'Names this panel was seen under earlier. Still refused to a relay, because an agent not yet reconfigured still dials them.';
comment on column advertised_address.confirmed_by is
    'The identity that confirmed these names, as the audit trail names it.';
