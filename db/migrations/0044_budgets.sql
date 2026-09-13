-- Hierarchical budgets: fleet capacity, not a collision on a host.
--
-- A resource lock answers whether two operations exclude each other. A budget
-- answers whether the system has the capacity to start another. Those are two
-- different questions: a limit of five hosts in a campaign does not protect the
-- repository from a hundred parallel downloads, and a package mutex on a host says nothing about the site load.
create table if not exists budget_limits (
    -- The key is exact ('global:mutations') or a pattern with an asterisk
    -- ('site:*:packages'). A pattern describes the default policy for a site
    -- nobody has described separately yet.
    key        text        primary key,
    capacity   int         not null check (capacity > 0),
    note       text        not null default '',
    updated_at timestamptz not null default now()
);

comment on table budget_limits is
    'The capacity of one budget. A missing row means an unconfigured budget, not a zero one.';

-- The token lease. It has an owner and a deadline, because an orchestrator
-- failure must not permanently shrink the fleet capacity: an expired lease stops counting.
create table if not exists budget_leases (
    key         text        not null,
    owner       text        not null,
    -- The claimant is the unit of fairness: the campaign, not a single host.
    -- Without this one big campaign would take all the free tokens.
    claimant    text        not null,
    weight      int         not null check (weight > 0),
    acquired_at timestamptz not null default now(),
    lease_until timestamptz not null,
    primary key (key, owner)
);

create index if not exists budget_leases_key_expiry on budget_leases (key, lease_until);
create index if not exists budget_leases_owner on budget_leases (owner);

comment on table budget_leases is
    'Granted tokens. An expired lease does not count towards the usage.';

-- Waiting for tokens. Recorded, because without it the share cannot be
-- computed: a fair split must also know those who got nothing yet. The
-- waiting time is at the same time the basis of promotion: whoever waits
-- long stops being bounded by the share.
create table if not exists budget_waiters (
    key      text        not null,
    claimant text        not null,
    class    text        not null,
    since    timestamptz not null default now(),
    seen_at  timestamptz not null default now(),
    primary key (key, claimant)
);

comment on table budget_waiters is
    'Who waits for capacity. Serves the fair share and the promotion by waiting time.';

-- A host waiting for tokens does not take an execution slot. The state is
-- separate, so that the operator sees the difference between "not started yet" and "no room".
alter table campaign_targets drop constraint if exists campaign_targets_state_check;
alter table campaign_targets add constraint campaign_targets_state_check
    check (state in ('pending', 'planning', 'awaiting_budget', 'running', 'rebooting',
                     'verifying', 'succeeded', 'failed', 'skipped', 'canceled'));

-- The starting values from the document. The patterns apply to every site
-- nobody described separately; an installation may override them with an exact row.
insert into budget_limits (key, capacity, note) values
    ('global:mutations',   50,  'jednoczesne mutacje w calej flocie'),
    ('global:reads',       200, 'jednoczesne odczyty w calej flocie'),
    ('site:*:packages',    5,   'transakcje pakietowe w jednej lokalizacji'),
    ('site:*:reboot',      2,   'restarty w jednej lokalizacji'),
    ('site:*:network',     1,   'zmiany sieci w jednej lokalizacji'),
    ('site:*:storage',     2,   'zmiany przestrzeni dyskowej w jednej lokalizacji'),
    ('site:*:backup',      2,   'operacje na repozytorium kopii'),
    ('site:*:units',       10,  'zmiany jednostek w jednej lokalizacji')
on conflict (key) do nothing;
