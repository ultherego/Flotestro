-- Feed generations and a sanity gate stronger than "empty".
--
-- Two gaps are closed here.
--
-- The first: a host's verdict named the digest of the snapshot that
-- settled it, and a digest is a fingerprint rather than a date. An
-- operator reading "no findings" could not tell a host judged against
-- yesterday's feed from one judged a minute ago against today's, and a
-- re-assessment after a new fetch changed the numbers without anything
-- saying why. A generation is the name of one feed snapshot and the moment
-- it was taken; every verdict carries it, so two hosts judged in one pass
-- name the same generation and a host left behind names an older one.
--
-- The second: the panel refused a feed that came back empty, and nothing
-- else. A fetch that went from twelve thousand findings to four hundred,
-- or one that quietly lost a whole release, is the same broken download
-- with a different number in it - and it would have assessed most of the
-- fleet as clean. Such a fetch is now kept as a candidate with a typed
-- reason instead of being activated; the previous snapshot stays in force
-- and ages into stale, which is visible, and an operator who has looked at
-- the candidate can accept it deliberately.

-- The generation of a snapshot. It is assigned when the row is created,
-- not when it is activated: the same data re-confirmed are the same
-- generation, and only a fetch that really carried something else is a new
-- one. A verdict that names a generation can therefore be compared with
-- the generation in force without reading the findings again.
alter table vuln_snapshots
    add column if not exists generation_id uuid        not null default gen_random_uuid(),
    add column if not exists generation_at timestamptz not null default now();

-- The rows that existed before this migration get their fetch time rather
-- than the time of the upgrade: a generation dated to the migration would
-- make every old assessment look fresh.
update vuln_snapshots set generation_at = fetched_at where fetched_at is not null;

comment on column vuln_snapshots.generation_id is
    'The name of this fetch of the feed; a verdict carries it so an operator can tell which snapshot judged the host.';
comment on column vuln_snapshots.generation_at is
    'When the generation was taken.';

-- A candidate is a fetch the gate refused to activate. It keeps its
-- findings, because accepting it must not need another download, and it
-- keeps the reason in a typed code rather than in a sentence.
alter table vuln_snapshots
    add column if not exists candidate_reason text not null default '',
    add column if not exists candidate_at     timestamptz;

comment on column vuln_snapshots.candidate_reason is
    'Why this fetch was not activated: feed_shrank or feed_release_missing; empty for a snapshot the gate let through.';
comment on column vuln_snapshots.candidate_at is
    'When the gate held this fetch back; empty for a snapshot the gate let through.';

alter table vuln_snapshots drop constraint if exists vuln_snapshots_candidate_check;
-- A candidate is never the active snapshot: the whole point of holding it
-- back is that the previous data stay in force.
alter table vuln_snapshots add constraint vuln_snapshots_candidate_check
    check (candidate_reason = '' or not active);

create index if not exists vuln_snapshots_candidate_idx
    on vuln_snapshots (provider, candidate_at desc) where candidate_reason <> '';

-- The verdict of a host names the generation that produced it. Null means
-- a verdict written before this migration: unknown is not "the current
-- generation", and the panel says "not recorded" rather than implying the
-- host was judged against today's feed.
alter table vuln_host_state
    add column if not exists generation_id uuid,
    add column if not exists generation_at timestamptz;

comment on column vuln_host_state.generation_id is
    'The feed generation that produced this verdict; null for a verdict written before generations were recorded.';
comment on column vuln_host_state.generation_at is
    'When the generation that produced this verdict was taken.';

-- The fleet screen asks "which hosts are still judged against an older
-- generation": that is a scan by generation over every assessed host.
create index if not exists vuln_host_state_generation_idx
    on vuln_host_state (generation_id);
