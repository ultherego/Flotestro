-- The approval record of a campaign.
--
-- A consent is evidence, not a flag: who approved what, on the strength of
-- which authentication and for what reason. The record is written once and
-- never changed; the columns on the campaign row remain a convenience for
-- the list and the state machine.
create table if not exists campaign_approvals (
    id                   uuid primary key default gen_random_uuid(),
    campaign_id          uuid not null references campaigns (id) on delete cascade,
    approval_fingerprint text not null,
    requested_by         text not null,
    approved_by          text not null,
    -- How the approver was authenticated: a session (with the ACR, the AMR
    -- and the time the provider reported) or an API token, which cannot
    -- re-authenticate and says so.
    authentication       text not null,
    acr                  text not null default '',
    amr                  text[] not null default '{}',
    authenticated_at     timestamptz,
    reason               text not null default '',
    change_ticket        text not null default '',
    created_at           timestamptz not null default now(),
    constraint campaign_approvals_fingerprint check (length(approval_fingerprint) = 64)
);

create index if not exists campaign_approvals_campaign_idx
    on campaign_approvals (campaign_id, created_at);

create or replace function campaign_approvals_immutable() returns trigger as $$
begin
    raise exception 'campaign_approvals is append-only: % is not allowed', tg_op;
end;
$$ language plpgsql;

drop trigger if exists campaign_approvals_no_update on campaign_approvals;
create trigger campaign_approvals_no_update before update on campaign_approvals
    for each row execute function campaign_approvals_immutable();

drop trigger if exists campaign_approvals_no_delete on campaign_approvals;
create trigger campaign_approvals_no_delete before delete on campaign_approvals
    for each row execute function campaign_approvals_immutable();
