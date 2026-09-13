-- The final report of a campaign, written once.
--
-- Until now the report was computed from the targets every time somebody
-- asked. For a campaign under way that is right: the answer changes. For a
-- finished one it is a liability: a host removed from the fleet takes its
-- target rows with it, and the report of last month's rollout then loses
-- the host that failed. The report is written when the campaign reaches a
-- terminal state, in the same transaction as the transition, and never
-- changed. The consent fingerprint and the plan set digest travel with it,
-- so the report says what was approved as well as what happened.
create table if not exists campaign_reports (
    campaign_id          uuid        primary key references campaigns (id) on delete cascade,
    state                text        not null check (state in ('completed', 'failed', 'canceled')),
    totals               jsonb       not null default '{}'::jsonb,
    waves                jsonb       not null default '[]'::jsonb,
    failures             jsonb       not null default '[]'::jsonb,
    -- The hosts that came back from being offline with a state that gives
    -- a different plan than the approved one. They ran nothing and are
    -- neither failures nor ordinary skips, so they keep their own list.
    plan_changed         jsonb       not null default '[]'::jsonb,
    generated_at         timestamptz not null default now(),
    approval_fingerprint text        not null default '',
    plan_set_hash        text        not null default '',
    approved_by          text        not null default '',
    created_by           text        not null
);

comment on table campaign_reports is
    'The final report of a finished campaign, written with the terminal transition and never changed.';

create or replace function campaign_reports_immutable() returns trigger as $$
begin
    raise exception 'campaign_reports is append-only: % is not allowed', tg_op;
end;
$$ language plpgsql;

drop trigger if exists campaign_reports_no_update on campaign_reports;
create trigger campaign_reports_no_update before update on campaign_reports
    for each row execute function campaign_reports_immutable();

drop trigger if exists campaign_reports_no_delete on campaign_reports;
create trigger campaign_reports_no_delete before delete on campaign_reports
    for each row execute function campaign_reports_immutable();
