-- The history of the platform of a host: every (kernel, distribution)
-- pair the panel has seen on it, with when it was first and last seen.
--
-- The inventory keeps only the latest picture of a host. A host that came
-- up on another kernel, or was upgraded to the next release, is a fact the
-- operator wants to look up later - "when did this box move to bookworm"
-- - and the inventory revisions do not keep that long enough. The gateway
-- writes a row when the system module of a report names a pair it has not
-- seen, moves last_seen when it names one it has, and keeps the newest
-- twenty pairs per host.
create table host_system_history (
    host_id                 uuid        not null references hosts(id) on delete cascade,
    kernel                  text        not null,
    distribution            text        not null,
    distribution_version    text        not null,
    first_seen_at           timestamptz not null,
    last_seen_at            timestamptz not null,
    primary key (host_id, kernel, distribution, distribution_version)
);

create index host_system_history_recent on host_system_history (host_id, last_seen_at desc);
