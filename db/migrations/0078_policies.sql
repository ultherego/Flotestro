-- Desired-state policies: the third model of change the document names.
--
-- A policy declares what is to be true on a dynamic group of hosts - a
-- package installed, a unit enabled and running, a file at a known content,
-- a sysctl at a value, a key on an account - and the panel judges every
-- host against it from the facts the host reports anyway. The policy never
-- touches a host by itself: it writes verdicts, and where a remediation is
-- wanted it orders a campaign of typed steps that waits for its approval
-- like any campaign.
--
-- The document is versioned. A draft is edited in place; a publication
-- bumps the version and freezes the document in policy_versions together
-- with who published it, on the strength of what authentication and why -
-- the same evidence a campaign approval carries, because a publication is
-- the approval the document names "at publication".
create table if not exists policies (
    id                     uuid primary key default gen_random_uuid(),
    name                   text not null unique,
    description            text not null default '',
    -- The published version; zero for a draft nobody has published yet.
    version                int not null default 0,
    -- The selector in the shape the campaigns take (site, environment,
    -- os_family, host_ids, expression, exclude).
    selector               jsonb not null default '{}'::jsonb,
    -- The typed rules, in order; the index of a rule is its identity in
    -- the results of a version.
    rules                  jsonb not null default '[]'::jsonb,
    remediation_mode       text not null default 'report'
                           check (remediation_mode in ('report', 'campaign', 'automatic')),
    enabled                boolean not null default true,
    check_interval_seconds int not null default 900
                           check (check_interval_seconds between 60 and 86400),
    created_by             text not null,
    created_at             timestamptz not null default now(),
    updated_at             timestamptz not null default now(),
    published_at           timestamptz,
    published_by           text not null default '',
    -- When the loop last judged the fleet against this policy; null for a
    -- policy never evaluated.
    last_evaluated_at      timestamptz
);

-- The frozen documents. One row per publication; never updated.
create table if not exists policy_versions (
    policy_id        uuid not null references policies (id) on delete cascade,
    version          int not null,
    -- The whole document as published: name, description, selector, rules,
    -- remediation mode, check interval.
    document         jsonb not null,
    published_by     text not null,
    published_at     timestamptz not null default now(),
    reason           text not null default '',
    -- The authentication behind the publication, the way a campaign
    -- approval records it: a session with its ACR and AMR, or a token.
    authentication   text not null default '',
    acr              text not null default '',
    amr              text[] not null default '{}',
    authenticated_at timestamptz,
    primary key (policy_id, version)
);

-- The latest verdict of every rule on every host. One row per
-- (policy, host, rule); the version says which document judged it and the
-- revision which read of the host it rests on. A verdict is replaced by the
-- next evaluation, so the table is the current picture, not a history -
-- the audit trail and the campaigns keep what happened.
create table if not exists policy_results (
    policy_id         uuid not null references policies (id) on delete cascade,
    host_id           uuid not null references hosts (id) on delete cascade,
    rule_index        int not null,
    version           int not null,
    verdict           text not null
                      check (verdict in ('compliant', 'drift', 'error', 'not_applicable')),
    reason            text not null default '',
    observed_revision text not null default '',
    evaluated_at      timestamptz not null default now(),
    primary key (policy_id, host_id, rule_index)
);

create index if not exists policy_results_host_idx on policy_results (host_id, policy_id);
create index if not exists policy_results_verdict_idx on policy_results (policy_id, verdict);

-- The remediation campaigns a policy ordered, keyed by the fingerprint of
-- the drift set (version, hosts, rules): the same drift on the same hosts
-- does not get a second campaign while the first one is still on the
-- table, and a resolved drift that returns is a new set and a new campaign.
create table if not exists policy_remediations (
    policy_id   uuid not null references policies (id) on delete cascade,
    version     int not null,
    fingerprint text not null,
    campaign_id uuid not null references campaigns (id) on delete cascade,
    created_at  timestamptz not null default now(),
    primary key (policy_id, fingerprint)
);

-- Every remediation campaign links back to the policy and the version that
-- ordered it, so the campaign page can say where the order came from and
-- the policy page can list what it ordered.
alter table campaigns add column if not exists policy_id uuid references policies (id) on delete set null;
alter table campaigns add column if not exists policy_version int;
create index if not exists campaigns_policy_idx on campaigns (policy_id) where policy_id is not null;
