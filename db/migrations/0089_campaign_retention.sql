-- The approvals and the reports of a campaign stay append-only for every
-- ordinary path: nothing in the panel updates or deletes one. The one
-- exception is the retention sweep of finished campaigns, whose cascade
-- takes the approvals and the report with the campaign. The triggers let
-- that delete through only inside a transaction the sweep has marked, the
-- way the audit trail lets its own retention through, so a stray delete
-- elsewhere is still refused. The trail keeps who approved what after the
-- campaign row is gone.

create or replace function campaign_approvals_immutable() returns trigger as $$
begin
    if tg_op = 'DELETE' and current_setting('flotestro.campaign_sweep', true) = 'on' then
        return old;
    end if;
    raise exception 'campaign_approvals is append-only: % is not allowed', tg_op;
end;
$$ language plpgsql;

create or replace function campaign_reports_immutable() returns trigger as $$
begin
    if tg_op = 'DELETE' and current_setting('flotestro.campaign_sweep', true) = 'on' then
        return old;
    end if;
    raise exception 'campaign_reports is append-only: % is not allowed', tg_op;
end;
$$ language plpgsql;

-- campaigns_expire deletes the finished campaigns older than the retention,
-- oldest first and at most a batch of them, and returns how many went. A
-- campaign another campaign retries or compensates stays until that one
-- goes: the reference has no cascade. The marker is local to the
-- transaction, so it ends with the function whatever happens inside it.
create or replace function campaigns_expire(retention interval, batch integer) returns bigint as $$
declare
    deleted bigint;
begin
    perform set_config('flotestro.campaign_sweep', 'on', true);
    delete from campaigns where id in (
        select c.id from campaigns c
        where c.state in ('completed', 'completed_with_issues', 'failed', 'plan_failed',
                          'expired', 'canceled')
          and coalesce(c.finished_at, c.updated_at) < now() - retention
          and not exists (select 1 from campaigns r
                           where r.retries_campaign_id = c.id
                              or r.compensates_campaign_id = c.id)
        order by coalesce(c.finished_at, c.updated_at)
        limit batch);
    get diagnostics deleted = row_count;
    perform set_config('flotestro.campaign_sweep', 'off', true);
    return deleted;
end;
$$ language plpgsql;
