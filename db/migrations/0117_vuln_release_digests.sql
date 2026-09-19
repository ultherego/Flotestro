-- A feed fetch that changed one release must not recompute the whole
-- distribution.
--
-- The snapshot is per provider and covers every release it carries, so any
-- new fetch changes the snapshot digest for every host of that distribution
-- and the scheduler judges all of them again. At ten thousand hosts and a
-- fetch every half hour that is the cost chapter 11.1 was written to avoid.
-- The digest below is over the advisories of one release alone, so a host is
-- judged again only when the data that concerns it moved.

create table if not exists vuln_release_digests (
    snapshot_id  uuid not null references vuln_snapshots (id) on delete cascade,
    distribution text not null,
    release      text not null,
    digest       text not null,
    advisories   int  not null default 0,
    primary key (snapshot_id, distribution, release)
);

comment on table vuln_release_digests is
    'One digest per release of a feed snapshot, so a host is recomputed only when its own release changed.';

-- The verdict says which release digest produced it. Empty means a verdict
-- written before this migration: unknown is not "the current digest", and the
-- scheduler falls back to comparing the whole snapshot for such a host.
alter table vuln_host_state
    add column if not exists release_digest text not null default '';

comment on column vuln_host_state.release_digest is
    'The digest of the release advisories that produced this verdict; empty for a verdict written before release digests existed.';
