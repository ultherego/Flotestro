-- The plan bodies an approval was given for.
--
-- Until now the approval recorded who consented, on what authentication
-- and under which fingerprint; the plans themselves lived in
-- campaign_plans, which the next planning of the same campaign overwrites.
-- The consent has to keep what it covered: for every host the digest of the
-- plan envelope, the version of the planner that computed it, the principal
-- who consented, the revision of the campaign record (its rollout policy
-- included) the consent was given against, and the plan body itself. The
-- table is append-only like the approvals: evidence is not edited.
create table if not exists campaign_approval_plans (
    id               uuid primary key default gen_random_uuid(),
    approval_id      uuid not null references campaign_approvals (id) on delete cascade,
    campaign_id      uuid not null references campaigns (id) on delete cascade,
    host_id          uuid not null,
    plan_hash        text not null,
    -- The planner that computed the plan; empty for a plan of the older
    -- shape, which binds by its digest alone.
    planner_version  text not null default '',
    principal        text not null,
    policy_revision  bigint not null default 0,
    plan             jsonb not null default '{}'::jsonb,
    created_at       timestamptz not null default now()
);

create index if not exists campaign_approval_plans_approval_idx
    on campaign_approval_plans (approval_id);
create index if not exists campaign_approval_plans_campaign_host_idx
    on campaign_approval_plans (campaign_id, host_id);

comment on table campaign_approval_plans is
    'The plan of every host as it was when the approval was given: the digest, the planner version and the body the consent covered.';

drop trigger if exists campaign_approval_plans_no_update on campaign_approval_plans;
create trigger campaign_approval_plans_no_update before update on campaign_approval_plans
    for each row execute function campaign_approvals_immutable();

drop trigger if exists campaign_approval_plans_no_delete on campaign_approval_plans;
create trigger campaign_approval_plans_no_delete before delete on campaign_approval_plans
    for each row execute function campaign_approvals_immutable();
