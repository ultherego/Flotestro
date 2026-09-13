-- Host tags, host groups and the excluded campaign target.
--
-- Until now a campaign could name its hosts only by site, environment and
-- OS family, or by an explicit list of identifiers. A fleet is described by
-- more than that: the role of a machine, its tier, the team that owns it.
-- Tags are facts an operator records about a host; a group is a saved
-- answer to "which hosts" - either a fixed list or a selector the panel
-- resolves when asked.

-- A tag is 'key' or 'key=value'. An empty array is the default: a host
-- without tags is a host nobody described, and a NULL there would only make
-- every query say so twice.
alter table hosts add column if not exists tags text[] not null default '{}';
-- The list filters by "has every one of these tags" and the selector by
-- "has this tag"; both are containment, which a GIN index answers.
create index if not exists hosts_tags_idx on hosts using gin (tags);

comment on column hosts.tags is
    'Tags recorded by operators, key or key=value; every campaign selector may use them.';

create table if not exists host_groups (
    id          uuid        primary key,
    name        text        not null unique,
    description text        not null default '',
    kind        text        not null check (kind in ('static', 'dynamic')),
    -- The selector of a dynamic group; a static group has none and lists
    -- its members instead.
    selector    jsonb,
    created_by  text        not null,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now(),
    check ((kind = 'dynamic') = (selector is not null))
);

comment on table host_groups is
    'Saved host selections: a static list of members or a dynamic selector resolved at read time.';

-- The members of a static group. A host that leaves the fleet leaves its
-- groups with it; a group removed takes its member list along.
create table if not exists host_group_members (
    group_id uuid not null references host_groups (id) on delete cascade,
    host_id  uuid not null references hosts (id) on delete cascade,
    primary key (group_id, host_id)
);

-- The selector asks "is this host in the group" per host, and the group
-- page asks the other way round; the primary key serves the first, this
-- index the second.
create index if not exists host_group_members_host_idx on host_group_members (host_id);

-- A host excluded by the operator stays in the snapshot, closed at once
-- with the reason and the author: a host left out in silence is a decision
-- nobody can review.
alter table campaign_targets drop constraint if exists campaign_targets_state_check;
alter table campaign_targets add constraint campaign_targets_state_check
    check (state in ('pending', 'planning', 'awaiting_budget', 'queued_offline', 'ineligible',
                     'excluded', 'running', 'rebooting', 'verifying',
                     'succeeded', 'failed', 'skipped', 'canceled'));
